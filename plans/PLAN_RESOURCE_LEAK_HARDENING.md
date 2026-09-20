# PLAN_RESOURCE_LEAK_HARDENING.md

**Status:** Survey complete — hardening not started
**Created:** 2026-09-12
**Last Updated:** 2026-09-12

## Overview

Read-only survey of the Go SDK (all non-test `.go` files under
`connection/`, `pool/`, `stream/`, `content/`, `dht/`, `directdial/`,
`transport/`, `manifest/`, `cbor/`, `frame/`, `identity/`, `ucan/`,
`bolt4/`; quic-go v0.62.0) for memory and resource leaks, cross-checked
against the C# sibling's survey (`macula-dotnet/plans/PLAN_RESOURCE_LEAK_HARDENING.md`).
The dominant theme is the same as the C# port: **dedicated QUIC streams
have no teardown path at all** — `content.Put`/`content.Get` and
`stream.Open`/`stream.Accept`/`stream.Abort` can neither close nor cancel
the streams they open, and unlike the C# port there is no `RefuseAsync`-
style partial cleanup anywhere. Go-specific additions: untrusted-manifest
input can drive an unrecoverable OOM **and** an explicit `panic` **and**
an infinite loop; a panicking `onDone` in `RunPublisher` kills the whole
process (Go has no per-goroutine isolation); `time.After` timers up to
30 min are un-stoppable; and idle-timeout dead connections are
misclassified as "nothing arrived" by three `net.Error.Timeout()` filter
sites, so `RunSubscriber`/`ServeForever` can poll a corpse forever.

General hygiene found GOOD and not repeated here: `connectOne` closes the
connection on every handshake failure path (connection.go:116-120),
`directdial` dials are `defer`-closed on all paths (directdial.go:187,
293, 324, 440, 528, 569), the CBOR decoder is panic-free and bounds
wire-supplied preallocation hints (`maxPreallocHint`, cbor/decode.go:152),
`frame.Decode` caps claimed frame length at `MaxFrameBytes` (~16 MB,
frame/codec.go:44-46), pool actor `outbox` is capped at 128 with overflow
treated as fatal (actor.go:27, 256-258), and pool `Close` is
ctx-cancellation-driven with a WaitGroup (pool.go:377-381).

---

## Findings (ranked)

### CRITICAL

#### F1. `content.Put`/`content.Get` never release their dedicated stream — success OR failure
`content/content.go:109` (Put) and `:142` (Get).

Every put/get opens a dedicated bidirectional QUIC stream via
`session.OpenDedicatedStream` and **never** calls `CloseSend` (the only
teardown `FrameStream` exposes) nor any cancel on it — not on success
(`:119`, `:137`, `:155`, `:180`), not on any failure path
(`:116-118`, `:130-136`, `:149-154`, `:159-161`, `:169-174`, `:177-179`:
`ErrHashMismatch`, `RemoteError`, `ErrNotFound`, timeouts, decode
errors). Nothing else in the SDK closes dedicated streams either (grep
for `Close`/`CancelRead`/`CancelWrite`: only `connection.go:327`
touches a stream, and that is the *control* stream during session
teardown). Consequences:

- Each transfer permanently consumes an outbound stream slot on the
  connection; after enough transfers `OpenStreamSync` exhausts the
  peer's stream budget and starts failing/blocking.
- Each abandoned stream retains quic-go receive buffers (the station's
  RESULTs are read, but never read to FIN, so the stream never completes
  and its buffers are never freed) until whole-connection teardown.

This is the single most important fix, and in Go it is *structural*: the
`quicStream` interface (connection/frame_stream.go:26-32) only exposes
`io.Reader/Writer/Closer` + deadlines — there is no `CancelRead`/
`CancelWrite` anywhere in the API, so `content` **cannot** be fixed
without extending that interface (see F6).

#### F2. `stream.Accept` abandons the accepted stream on every failure path
`stream/stream.go:87-104`, specifically `:94-97` and `:98-101`.

`AcceptDedicatedStream` hands back a stream and `Accept` then reads the
first frame off it. If `RecvFrame` errors (the peer opened then stalled
or reset, the accept-timeout deadline fires mid-read, the connection
drops) or `ParseStreamOpen` rejects the first frame, the just-accepted
QUIC stream is abandoned with no abort/cancel. The peer gets no
RESET/STOP_SENDING (its side can hang), and the local stream slot and
receive buffers are consumed until connection teardown. Unlike the C#
port (`RefuseAsync` released the four handled shapes), **Go has no
refusal path at all** — every error path leaks.

Fix: make the invariant explicit — `Accept` either returns a `*Handle`
or has freed the stream; add a `CancelRead` on `FrameStream` and call it
in the error paths before rethrowing.

#### F3. `stream.Open` leaks the stream if the STREAM_OPEN write fails
`stream/stream.go:64-78`, specifically `:65-68` and `:75-77`.

The dedicated stream is opened at `:65` and the signed STREAM_OPEN
written at `:75`. If `SendFrame` throws (send blocked, session ended),
the freshly opened stream is abandoned with no cancel. Same
slot-consumption consequence as F2, on the caller side. (The
`rand.Read` failure at `:70-72` leaks it too, though that path is
documented-unreachable.)

### HIGH

#### F4. Untrusted wire manifest drives unbounded allocation, an explicit panic, and an infinite loop
Three separate untrusted-input paths, all reachable from
`content.Get` with a malicious/broken station:

1. **OOM preallocation** — `content/content.go:162`:
   `data := make([]byte, 0, m.Size)` where `m.Size` comes straight off
   the wire (`manifest.FromWire`, manifest.go:307, no cap). A hostile
   `size` field (up to 2^63-1) makes `make` try to allocate gigabytes;
   unlike the C# version there is no recover anywhere on this path, so
   the allocation failure is an unrecoverable runtime panic ("out of
   memory"), not an exception a caller can catch.
2. **Explicit panic on chunk_count mismatch** — `content/content.go:163-166`:
   the fetch loop iterates `m.ChunkCount` (wire-supplied) but each
   `ChunkMcid(m, index)` returns `!ok` when `index >= len(m.Chunks)`,
   and the `!ok` branch is `panic("content: index < m.ChunkCount...")`.
   `FromWire` never cross-validates `chunk_count` against the actual
   length of the wire `chunks` list (manifest.go:291-356), so a
   manifest claiming `chunk_count=1000000` with a 1-element list
   crashes the caller's process — from an untrusted station, on any
   `Get` of a chunked MCID.
3. **Infinite loop on chunk_size=0** — `manifest/manifest.go:182-195`
   (`doChunk`, called from `Verify` at `:173`): `for i := 0; i < len(data);
   i += chunkSize` with a wire-supplied `chunk_size` of 0 never
   advances and appends `data[0:0]` forever — unbounded slice growth,
   OOM, and a permanently hung goroutine. `FromWire` accepts
   `chunk_size=0` (manifest.go:315-318, no positivity check), and
   `Get` reaches `Verify` whenever the fetched chunks happen to sum to
   `Size` (the attacker controls the manifest, so it can arrange that).

Fix: validate `Size == Σ chunk sizes`, `ChunkCount == len(Chunks)`, and
`ChunkSize >= 1` in `FromWire` (or before use in `Get`), and cap `Size`
before the `make` — fail fast with an error, never panic.

#### F5. Unbounded goroutine fan-out per inbound EVENT — the pool's dispatch path
`pool/subscribe.go:152-154` (`deliver`), with `fanoutEvents` at `:124-133`.

Every inbound EVENT spawns one `go deliverOne(...)` **per matching
handler**, with no concurrency cap, no backpressure, and no tracking.
A slow `EventHandler` (or a flood of events from a relay) grows
goroutines without bound; each holds the payload and closure until the
handler returns. `deliverOne` recovers panics (:166-169) so the process
survives, which only hides the growth. This is the Go analog of the C#
F7 (unbounded task fan-out per inbound CALL) — except the pool's *call*
path does not fan out at all (see "Not present" below), so the exposure
moved to the event path. Fix: bounded worker pool or semaphore per
delivery, or a per-handler bounded queue.

#### F6. No stream teardown primitive exists — and `Handle.Abort` is app-level only
`connection/frame_stream.go:26-32` (the `quicStream` interface) and
`stream/stream.go:241-245` (`Abort`).

The SDK cannot abort a dedicated stream's receive side at all:
`quicStream` exposes only `io.Closer` (quic-go `Stream.Close`, i.e.
half-close send), and no method anywhere maps to `CancelRead`/
`CancelWrite`. `Handle.Abort` sends a signed STREAM_ERROR frame and
then does *nothing* to the underlying QUIC stream — the stream stays
fully open (both directions) until connection teardown, so even a
cooperative caller that correctly calls `Abort` leaks the slot. This is
the C# F6 "no IDisposable safety net" in sharper form: it is not
convention-driven misuse, the API literally cannot release a stream.
Any fix for F1-F3 must first extend `FrameStream` with cancel
primitives.

#### F7. A dropped `Session` leaks its connection and goroutines forever — no finalizer, no registry
`connection/connection.go:36-40` (Session struct), `transport/transport.go:101-104`
(quic config with `KeepAlivePeriod: 15s`), and the absence of any
`runtime.SetFinalizer` in this repo *or* in quic-go v0.62.0 (verified in
the module cache).

A `Session` the application drops without `Close` keeps: the live
`quic.Conn` (2-3 internal goroutines, send/receive buffers), its
control `FrameStream`, and — because the transport config enables a
15 s keepalive — a network peer that is genuinely *livelier* than the
application: PINGs every 15 s keep the QUIC state alive indefinitely,
so nothing on either side ever times it out, and the station keeps its
side of the session too. GC cannot reclaim any of it because quic-go
never registers a finalizer. The C# port mitigated this with a static
`OpenSessions.Live` registry (making the leak visible and providing a
watchdog point); Go has neither — the leak is fully invisible. Fix:
`runtime.SetFinalizer` on `Session` as a last-chance `CloseWithError`,
or a debug-mode registry/watchdog.

### MEDIUM

#### F8. `RunPublisher`'s background goroutine: a panicking `onDone` kills the process, outcome unobserved
`connection/publisher.go:57-67`.

The fire-and-forget goroutine calls the caller-supplied `onDone`
(`:60`, `:66`) with **no recover** — unlike the same package family's
`deliverOne` (subscribe.go:166-169) and `callOnLinkEvent`
(subscribe.go:173-176), which both recover explicitly *because* an
unrecovered panic in any goroutine terminates the whole Go process
(no per-goroutine isolation). A panicking `onDone` therefore takes down
the entire daemon; a blocking `onDone` leaks the goroutine forever (it
is untracked — no WaitGroup). Fix: wrap the callback in a recover
matching the two existing call sites.

#### F9. Dedup map growth between sweeps
`pool/dedup.go:54-62` (`CheckAndMark`) and `:65-73` (`Sweep`); sweep
loop at `pool/subscribe.go:178-189` (default window 60 s / sweep 30 s).

`seen` is bounded only by event rate × `DedupWindow`; under a sustained
event flood the map grows arbitrarily between sweeps and each `Sweep`
is O(all entries). Each entry holds three string-copied keys (realm,
publisher, topic), so at high relay rates this is a real memory-pressure
knob. Not unbounded (entries are removed), same shape as the C# F8.
Fix: a size cap with early sweep, or bucket-based expiry.

#### F10. `time.After` timers that cannot be stopped
Four sites: `pool/discovery.go:61` (`RefreshInterval` — default **30
minutes**), `pool/discovery.go:74` (50 ms poll), `pool/rpc.go:167`
(50 ms poll, one timer per iteration of `CallStation`'s wait loop),
`pool/link.go:152` (`sleepOrDone`, respawn backoff).

Each `time.After` allocates a runtime timer that stays live until it
fires even when the select exits early via `ctx.Done()`; the discovery
loop's 30-minute timer is retained for up to 30 minutes after pool
close/cancel. None of these is a per-iteration unbounded growth (they
fire eventually), but `time.NewTimer` + `Stop` (or a shared ticker) is
the correct shape, and `CallStation`'s loop allocates ~20 timers/sec
per waiting caller.

#### F11. Idle-timeout connection death is misclassified as "nothing arrived"
`connection/subscriber.go:90-93` (`isRecvTimeout`), used at
`subscriber.go:64-66` and `connection/serve.go:91-93`; the pool's copy
`pool/actor.go:455-458` used at `actor.go:417-420`.

quic-go's `IdleTimeoutError` (internal/qerr/errors.go:90 in v0.62.0)
implements `net.Error` with `Timeout() == true`. When a peer dies
unreachably, the connection closes with exactly this error after
`MaxIdleTimeout` (300 s) — and every `isRecvTimeout` filter classifies
it as "read-deadline timeout: nothing arrived, keep polling":

- `RunSubscriber` (subscriber.go:64-66) loops forever on a corpse —
  it never watches `session.Done()`.
- `ServeForever` (serve_loop.go:35-46) treats the resulting
  `ErrServeOneCallTimeout` as "keep looping" — same, forever.
- The pool's `actor.readLoop` (actor.go:417-420) is rescued *only*
  because `actor.run`'s select also watches `session.Done()`
  (actor.go:238-239), so the link does respawn — but only after run
  wins the select race.

Unlike the C# F4 (OCE-vs-CTS misclassification, five sites), Go has no
`errors.Is(err, context.DeadlineExceeded)` filters anywhere (verified by
grep) — this `Timeout()==true` blind spot on connection-close errors is
the Go-specific misclassification. Consequence: permanently stuck
goroutines holding a dead `Session` (and its 16 MB-capable frame
buffer), a provider that keeps "serving" a connection nobody can reach,
and a caller that never learns its subscription is dead. Fix: treat
`errors.Is(err, net.ErrClosed)` as fatal in all three filters (quic-go
wraps close errors under `net.ErrClosed`), and/or watch
`session.Done()` in the two standalone loops.

### LOW

#### F12. Fire-and-forget cancel goroutine discards its error
`pool/rpc.go:202`: `go func() { _ = a.send(context.Background(),
cancelCallCmd{...}) }()`. Deliberate best-effort (the comment says so),
but the error is unobserved and the goroutine is untracked; a pool that
is mid-shutdown lets it outlive `Close`. Attach a `wg` or route the
error to a debug log. (`actor.go:214`'s deferred `session.Close` is the
same deliberate-discard shape — harmless, bounded by `closeSendTimeout`.)

#### F13. `FrameStream.buf` never shrinks; per-call chunk allocation
`connection/frame_stream.go:81` (fresh 4 KB `chunk` per `RecvFrame`
call — allocated every 2 s poll even when idle) and `:88`/`:94`
(`fs.buf = fs.buf[decoded.Consumed:]` re-slices but keeps the backing
array). Growth is bounded by `MaxFrameBytes` (~16 MB, frame/codec.go:44-46),
but a control stream that once carried a large frame retains the peak
allocation for the session's lifetime. Consider releasing to nil when
the buffer is fully consumed.

#### F14. Actor outbox re-slice retains the backing array
`pool/actor.go:253` (`a.outbox = a.outbox[1:]`). Bounded by
`outboxCap` (128) + growth slack, so the retention is at most a few
encoded frames' worth of payload references; prune on actor exit for
tidiness.

---

### Dotnet cross-check — findings NOT present in the Go port

- **C# F4 (OCE misclassified as timeout at five sites):** not present in
  that shape — no `errors.Is(err, context.DeadlineExceeded)` filters
  exist anywhere in the repo. The residual misclassification is the
  `net.Error.Timeout()` blind spot in F11.
- **C# F7 (unbounded task fan-out per inbound CALL):** not present — the
  pool deliberately does not serve inbound calls in v1
  (`pool/actor.go:349-365` ignores non-event/result frames); the
  exposure moved to event fan-out (F5).
- **C# F11 (dead Subscription objects retained by the ended channel):**
  not present — no channel-end retention model; `p.subs` is
  pool-scoped, entries removed by `Unsubscribe` (subscribe.go:45-61),
  pool teardown is ctx-driven.
- **C# F12 (static `OpenSessions.Live` registry):** not present — there
  is no registry at all. The Go gap is the inverse (F7): no registry
  *and* no finalizer, so the leak is invisible.
- **C# LOW (KeyPair tmp file leftover):** not present —
  `identity.KeyPair.Save` is a direct `os.WriteFile`
  (identity/identity.go:122-125), no temp-file rename step.
- **C# LOW (undisposed CTS):** not present in Go terms — `cancel()`
  funcs are deferred at every `context.WithTimeout` site (e.g.
  connection.go:102, rpc.go:187).

---

## Phases

- [ ] Phase 1 — Stream lifetime: extend `FrameStream`/`quicStream` with
      `CancelRead`/`CancelWrite` (F6), then make `content.Put`/`Get`
      (F1), `stream.Accept` (F2) and `stream.Open` (F3) release their
      streams on every exit path (finish on success, cancel on error).
      `Handle.Abort` must cancel the transport stream, not just send
      the frame.
- [ ] Phase 2 — Untrusted manifest bounds (F4): validate `chunk_count`
      vs `len(chunks)`, `chunk_size >= 1`, and cap `size` before
      allocation in `Get`; replace both panics and the infinite loop
      with typed errors; hash-verify incrementally.
- [ ] Phase 3 — Backpressure on event delivery (F5): bounded worker
      pool or per-handler queue instead of one goroutine per delivery.
- [ ] Phase 4 — Liveness misclassification (F11): treat
      `net.ErrClosed`-wrapped errors as fatal in `isRecvTimeout` (both
      copies), watch `session.Done()` in `RunSubscriber`/`ServeForever`.
- [ ] Phase 5 — Retention and hygiene: Session finalizer/watchdog (F7),
      `recover` around `RunPublisher`'s `onDone` (F8), dedup size cap
      (F9), `time.NewTimer`+`Stop` at the four `time.After` sites (F10),
      observe the cancel-goroutine error (F12), release `FrameStream.buf`
      when consumed (F13).

## Files to Create/Modify

| File | Purpose | Status |
|------|---------|--------|
| `connection/frame_stream.go` | F6: `CancelRead`/`CancelWrite` on `FrameStream` + `quicStream`; F13 buffer release | Not started |
| `connection/connection.go` | F7: `Session` finalizer/watchdog; F11: `Done()` watch in standalone loops | Not started |
| `connection/subscriber.go` | F11: fatal-close classification in `isRecvTimeout`/`RunSubscriber` | Not started |
| `connection/serve.go`, `connection/serve_loop.go` | F11: fatal-close classification + `Done()` watch in `ServeForever` | Not started |
| `connection/publisher.go` | F8: recover around `onDone` | Not started |
| `content/content.go` | F1: stream teardown on all paths; F4: manifest size/count validation before allocation | Not started |
| `manifest/manifest.go` | F4: `FromWire` cross-validation (`chunk_count`, `chunk_size >= 1`, size cap) | Not started |
| `stream/stream.go` | F2/F3: abort-on-throw on Accept/Open; F6: `Abort` cancels the transport stream | Not started |
| `pool/actor.go` | F11: fatal-close classification in readLoop; F14: outbox prune | Not started |
| `pool/subscribe.go` | F5: bounded delivery; F9: dedup size cap/early sweep | Not started |
| `pool/rpc.go`, `pool/link.go`, `pool/discovery.go` | F10: `time.NewTimer`+`Stop`; F12: observe cancel error | Not started |

## Success Criteria

- [ ] A live-session stress test (N sequential `content.Put`/`Get`
      calls) shows no growth in open-stream count on the connection and
      succeeds beyond N where it previously exhausted the stream budget
      (`go test` against a real station, or `stream/` live tests).
- [ ] `stream.Accept` against a peer that opens-then-stalls leaves no
      live QUIC stream behind (repeatable 1000x, zero growth); same for
      `stream.Open` against a send failure.
- [ ] A malicious manifest (`size` huge, `chunk_count` mismatch,
      `chunk_size` 0) fails fast with a typed error — no panic, no
      infinite loop, no large allocation (`manifest`/`content` unit
      tests).
- [ ] Killing the peer mid-`RunSubscriber`/`ServeForever` returns a
      connection-closed error within one poll interval, never loops
      forever on `Timeout()==true` idle-timeout errors.
- [ ] Event flood with slow handlers: goroutine count stays bounded
      (observable via `runtime.NumGoroutine` in a pool test).
- [ ] A dropped `Session` triggers a finalizer close (no leaked conn /
      keepalive traffic on the wire).
- [ ] All tests green: `go test ./...` and `go vet ./...`.
