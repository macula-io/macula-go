# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-09-11

### Breaking

- `connection.Session.Subscribe` returns a `*Subscription` with `Recv` and
  `Close`. `Session.RecvEvent`, `Session.Unsubscribe`, `Session.RecvAny` and
  `Session.SendAny` are removed.
- `Session.Done` closes when the session ends for any reason, not only when
  its connection closes. `Session.Err` says why.
- A `Session.Call` or `CallWithUCAN` whose timeout passes returns an error
  wrapping `ErrCallTimeout`, which also wraps `ErrNotSent` when the CALL was
  never written. On a session that has ended, a call's error wraps
  `ErrSessionEnded` and `ErrNotSent`.
- `directdial.OpenStreamDirect` and `OpenStreamDirectWithCertChain` return a
  `*directdial.Stream`, which holds the session carrying the stream until
  `Close`, instead of the session and the stream handle.
- `pool.Pool.Call` tries another link only when the CALL was not sent. A
  timeout after the CALL was written is returned, rather than sent again on
  another link where the provider could run it a second time.

### Added

- A `Session` has one reader, so calls, subscriptions and serve loops can
  share it from any number of goroutines. Each RESULT and ERROR goes to its
  call, each EVENT to every matching `Subscription`, and each inbound CALL to
  `ServeOneCall` or `ServeOneCallGated`.
- A subscription's topic matches as the station matches it: a `*` segment
  matches exactly one segment.
- `Session.LinkCall` makes a call that publishes no RPC facts, as
  `macula_station_link:call` does. The pool's calls and liveness probe use it.
- `Session.Unrouted` counts inbound frames nothing routed, per frame type.
  `Session.SetLogger` logs those at most once a minute per type, and logs the
  session's end once with its reason: a warning when the station or the
  connection ended it, information when `Close` did.
- `connection.DialLeased`, `connection.Acquire` and `connection.Lease`: open
  sessions are registered by the identity they connected as and the station
  they reached, and work that reuses a session holds a lease, so it never
  closes a session it doesn't own.
- `directdial.Call`, `CallWithUCAN`, `CallWithCertChain`, `OpenStreamDirect`,
  `GetDirect` and `PutDirect` use a session this process already holds to the
  target station under the same identity, such as the resolving session
  itself, instead of dialling a second connection the station would answer by
  closing the first.
- Errors: `ErrSessionEnded`, `ErrProtocolViolation`, `ErrSendTimeout`,
  `ErrNotSent`, `ErrCallTimeout`, `ErrConsumerOverflow`, `ErrRecvTimeout`,
  `ErrSubscriptionClosed`, `*GoodbyeError` and
  `directdial.ErrMalformedStationEndpoint`.

### Changed

- A subscription whose 256-event queue is full when an event arrives ends
  with `ErrConsumerOverflow`, after returning what it had queued. It keeps the
  station subscription until it is closed, since only `Close` sends
  UNSUBSCRIBE, and the session stays up.
- Inbound CALLs wait in a queue of 64 for a serve loop. A CALL that doesn't
  fit is answered with `temporary_relay_failure`.
- A send waits for the write lock until its own deadline (a call's timeout,
  otherwise 30 s) and then returns `ErrNotSent`. A write in progress is
  bounded by a 30 s send timeout, after which the session ends with
  `ErrSendTimeout`.
- The station's GOODBYE ends a session with `*GoodbyeError`, and a HELLO or
  CONNECT after the handshake ends it with `ErrProtocolViolation`. A frame
  that cannot be decoded ends the session and closes its connection.
- RPC telemetry facts go through the session's writer and are dropped when it
  is 64 frames behind. `rpc.sent_v1` is published once the CALL is written.
- `pool`: each link holds one `Session` and subscribes once per tracked realm
  and topic. A subscription that overflows is replaced before it is closed.
  `Publish` writes to the selected links concurrently and returns at the first
  success.
- `directdial`: a CALL that failed with `connection.ErrNotSent` lets the next
  candidate be tried, and that candidate is tried again on the next pass. At
  the deadline the error names, in this order, the most recent candidate's
  failure, why the latest lookup that answered found nothing usable, or the
  latest failed lookup's error, joined with the deadline. A lookup cut off by
  the deadline records nothing. A station endpoint lookup is asked again past
  a failed lookup or a malformed record.

### Fixed

- A `pool` subscription to a topic with a `*` segment receives the events it
  matches. The pool looked handlers up by the event's own topic, so such a
  subscription received nothing. An event matching two subscriptions, such as
  `a/*` and `a/b`, reaches each one's handlers once.

## [0.8.2] - 2026-09-11

### Fixed

- `FrameStream.SendFrame` writes each frame whole when several goroutines
  send on the same stream at once, as `RunPublisher` and `KeepAdvertised` do
  beside a session's other sends. Frames were kept whole only because quic-go
  serializes concurrent writes on a stream, which it documents as not
  permitted.

## [0.8.1] - 2026-09-11

### Fixed

- When every candidate failed before its request was sent, `Call`,
  `CallWithUCAN`, `CallWithCertChain`, `OpenStreamDirect`,
  `OpenStreamDirectWithCertChain`, `Resolve`, `ResolveWithCertChain` and
  `GetDirect` report the most recent candidate's failure at their deadline.
  A later pass that found no candidate, or a DHT lookup that failed, took
  its place, so a refused dial could come back as
  `ErrProcedureNotAdvertised`, `ErrContentNotAnnounced` or the lookup's own
  error.

## [0.8.0] - 2026-09-11

### Breaking

- `Resolve`, `ResolveWithCertChain` and `ResolveStationEndpoint` take a
  `context.Context` as their first argument. Without a deadline,
  `DefaultResolveTimeout` (10 s) applies. An error at the deadline joins the
  last failure with the context's error.
- A gated call (`ucan.Required`) is accepted only when the token's audience
  is the calling identity's node ID as lowercase hex, so tokens must be
  minted with that audience. `Policy.Check` takes the caller alongside the
  token, and returns `ErrNoCaller` or `ErrWrongAudience` when either is
  missing or they don't match.
- A provider answers only CALLs signed by the caller they name.
  `ServeOneCall` and `ServeOneCallGated` verify an inbound CALL's signature
  against its `caller` field before any policy or handler sees it, and give
  any other CALL no reply.

### Changed

- Direct dial treats every advertisement that verifies as a candidate, in the
  order the DHT returns them. A candidate whose station endpoint can't be
  resolved, whose dial fails, or whose dialed identity doesn't match is
  passed over for the next before the request is sent; once a CALL or a
  stream's opening frame may have gone out, its outcome stands. Resolution
  asks the DHT again after a pause that doubles from 100 ms to 1 s, and tries
  a candidate that failed again only when its advertisement or endpoint
  record has changed.
- `Call`, `CallWithUCAN` and `CallWithCertChain`: `timeout` bounds
  resolution, dials and the CALL. `OpenStreamDirect` and
  `OpenStreamDirectWithCertChain`: `timeout` bounds resolution and dials.
  `GetDirect`: `timeout` bounds lookups, dials and transfers, and a fetch
  that fails or doesn't verify moves on to the next provider. `PutDirect`:
  `timeout` bounds the endpoint lookup and the dial.

### Added

- `dht.FindRecordTimeout` and `dht.FindRecordsTimeout` bound one lookup by a
  given timeout.
