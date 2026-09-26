# The macula C ABI: contract

`cabi` is macula-go's macula 12 API behind a C ABI, so that one Go
implementation serves every binding not written in Go: .NET (P/Invoke),
Python (ctypes), PHP (FFI) and TypeScript (N-API). `macula.h` declares it;
this file says what every part of it means. A binding follows both and
nothing else.

## Version

`macula_abi_version()` returns the library's `MACULA_ABI_VERSION`. A binding
compares it with the version it was written against and refuses a library
built for another. A change to an existing declaration in `macula.h` changes
the version; a new function does not, and `macula.h` says since which
macula-go version it exists, so a binding that uses one pins at least that
version. The set of declarations is fixed per macula-go tag.

An error `kind` a binding does not know is `failed` to it: kinds may be added
without a new version.

## Handles

Every Go value that crosses the boundary is a `macula_handle`: an opaque
`uintptr_t`, never 0. A handle this process never issued, one already freed,
or one of another kind is refused with the error kind `invalid_handle`,
never a crash.

| Handle | Made by | Ended by |
|---|---|---|
| key | `macula_key_generate`, `_load`, `_load_or_create` | `macula_key_free` |
| pool | `macula_pool_connect` | `macula_pool_close` |
| subscription | `macula_pool_subscribe` | `macula_subscription_stop` |
| served | `macula_pool_serve`, `_serve_stream`, `_serve_gated`, `_serve_stream_gated` | `macula_served_stop` |
| pending call | `macula_served_next` | its first answer, or its procedure stopping (never freed by the caller) |
| stream | `macula_pool_open_stream`, `_open_stream_with`, `macula_served_next` | `macula_stream_free` |
| cancel token | `macula_cancel_new` | `macula_cancel_free` |

Closing a pool ends its subscriptions and served procedures (their inboxes
report closed) and its streams; their handles still need their own
stop/free, which then does nothing more than free them.

## Memory

- A `char *` or `uint8_t *` the library returns is the caller's, freed with
  `macula_free_string` or `macula_free_bytes`. A byte result's length is in
  `*out_len`; an empty result is NULL with `*out_len` 0.
- Fixed-size outputs (`out_node_id[32]`, `out_mcid[50]`) are buffers the
  caller owns.
- Inputs are only read during the call; the library keeps no pointer to
  them.
- `realm`, `key` and node ids are 32 bytes; an MCID is 50 bytes. A pointer
  argument documented as optional (`provider_node_id`, `options_json`, a
  profile) may be NULL.

## Errors

Every call that can fail takes `char **err_out` last. On failure it stores a
string the caller frees, and returns a zero value (NULL, 0, or nothing). On
success it leaves `*err_out` untouched, so the caller sets it to NULL before
the call. The string is a JSON object:

```json
{"kind": "provider_error", "message": "...", "code": "...", "detail": "..."}
```

`kind` is one of a fixed set, and a binding maps each to its own error type.
`message` is for people, never for matching.

| kind | When | Extra fields |
|---|---|---|
| `cancelled` | the call's own cancel token was cancelled, and nothing else | |
| `timeout` | the call's `timeout_ms` ran out | |
| `invalid_handle` | a handle this process does not hold, or of another kind | |
| `invalid_argument` | a malformed id, JSON, profile, mode, size or payload (a JSON boolean, say) | |
| `provider_error` | the provider answered a call with an error | `code`, `detail` (may be null) |
| `relay_error` | a station could not deliver a call | `code` |
| `not_found` | no DHT record under that key | |
| `no_provider` | no provider the realm trusts advertises the procedure (since v0.15.0; `failed` before) | |
| `not_shared` | no node shares that content in that realm | |
| `unavailable` | every sharer failed to give the content | `failures`: a list of strings |
| `answered` | a pending call was answered already | |
| `closed` | the pool, subscription, served procedure or stream has ended, including a call in flight when its own pool closes | |
| `refused` | the network refused it (an advertisement, an admission, a key) | |
| `confidentiality` | a call or stream that could not be kept confidential (since v0.18.0; see "Confidentiality") | `reason`, `named`, `found` (key ids as hex, or null) |
| `failed` | anything else | |

## Threads and blocking

- Every function may be called from any thread. Calls on different handles
  run concurrently; calls on one handle are safe from several threads, with
  the ordering noted per call (two `macula_stream_recv` on one stream each
  get a different frame).
- A call that does network I/O blocks the calling thread until it finishes,
  its `timeout_ms` runs out (0: no timeout of its own), or its cancel token
  is cancelled. Run it off any event loop.
- The library never calls into the binding: no callbacks, no Go thread ever
  enters the host's runtime. Everything that arrives on its own waits in an
  inbox.

## Inboxes

A subscription's events, a served procedure's calls and sessions, and a
pool's link events wait in an inbox of 256 until taken with the matching
`*_next`:

- It returns the next item's JSON, or NULL. After NULL, `*closed` tells why:
  1 when the source ended and the inbox is drained, 0 when `timeout_ms` ran
  out with nothing (`timeout_ms` 0 waits for ever). A cancelled wait is the
  error kind `cancelled`.
- A full subscription inbox drops the newest event and counts it
  (`macula_subscription_dropped`). A full served inbox makes the call wait
  for room until its deadline, then answers it with an error for you. A
  pool's link events drop the oldest.
- `macula_served_next` also stores the item's handle in `*out_item`: a
  pending call for `macula_pool_serve`, a stream for `_serve_stream`.

## Cancellation

A cancel token is created, passed to any number of calls, cancelled, and
freed. `macula_cancel` is safe from any thread while calls using the token
block on others: that is its purpose. A cancelled token stays cancelled and
fails every later call given it at once, so a binding makes one per
operation (asyncio) or one per `CancellationToken` (.NET, cancelled from the
token's registration). Freeing a token while a call still uses it is safe.

## Payloads

A payload (a call's arguments and result, a publication, a stream value, a
request) crosses as JSON text, mapped to and from macula's deterministic
CBOR:

| JSON | CBOR |
|---|---|
| `null` | null |
| a number with no fraction or exponent | an integer, exact over the int64 range |
| any other number | a float |
| a string | text |
| an array | an array |
| an object | a map with text keys |
| `{"$bytes": "<standard padded base64>"}` (that sole key) | a byte string |

- `true` and `false` are refused (`invalid_argument`): macula's CBOR has no
  boolean. Send 0 and 1.
- An integer outside the int64 range is refused (`invalid_argument`):
  macula's decoding rule refuses one on the wire. Integers beyond 2^53 stay
  exact, so a binding parses returned JSON integers as 64-bit integers, never
  through a double.
- Bytes always come out in the same `{"$bytes": ...}` form they go in with,
  so a value received can be sent back unchanged. There is no hex form.
- A map key that is not text comes out as its diagnostic string; macula's
  own payloads use text keys.
- An empty or NULL payload is null.

Everything else the library returns is JSON with ids and keys as lowercase
hex strings, and flags as 0 or 1.

## Serving and streams

- A pending call is answered once, with `macula_pending_reply` (a result) or
  `macula_pending_error` (a message the caller receives as a provider error
  of code `handler_error`, the message as its detail, cut to 256 bytes). A
  call not answered by its deadline is answered with an error for you, and
  an answer after that is `answered`. The handle ends with its first answer,
  whether that answer went or was `answered`; an answer after it is
  `invalid_handle`. Stopping the procedure answers each call still pending
  with an error and ends its handle.
- A request's `payload`, of a call or a session, never holds a "caller"
  its sender wrote into it (since v0.17.0), as macula's handlers never see
  one: who called is the request's own `caller`, which the signature proves.
- A served stream session is a stream handle like one the node opened. The
  provider sends, replies or aborts, and ends it; `macula_stream_free`
  aborts one not ended.
- `macula_pool_open_stream`'s `deadline_ms` is how far ahead of now the
  absolute deadline (Unix ms) signed into the STREAM_OPEN lies (30 s when
  0). A provider refuses to admit an open past it (`expired`) or more than
  10 minutes before it (`not_yet_valid`). It does not bound the stream's
  life: a session ends when either side ends or closes it, or when a relay
  gives it up. Bound your own waits with `macula_stream_recv`'s timeout.
- `macula_stream_recv` returns one frame as JSON: `data` (with `encoding`,
  `raw` for bytes sent with `macula_stream_send_bytes` or `msgpack` for a
  value sent with `macula_stream_send_json`, and `body`), `end` (the peer
  closed its send side, with its `role`, `send` or `both`), `reply` (the provider's terminal value), `eof` (the stream
  ended normally), or `error` (a stream error, `relay` 1 when a station
  raised it).

## UCANs

Since macula-go v0.17.0. A gated procedure serves only callers presenting a
UCAN (macula 12's D7; macula's `test/vectors/UCAN_V1.md` is the contract,
and macula-go's `ucan` package passes its vectors):

- `macula_ucan_create` mints one from an identity key for another node,
  `caps_json` a list of `{"with", "can"}`, each `with` an MRI
  (`mri:realm:<realm>`, `mri:org:<realm>/<org>`, `mri:proc:<realm>/<org>/<name>`,
  a realm by its name, whose SHA-256 is its id). A delegated token names its
  parent in `options_json`'s `prf` by `macula_ucan_proof_id`, and is minted
  for the node that presents it: the token's audience is always the caller
  that presents it.
- `macula_pool_call_with` and `macula_pool_open_stream_with` present a token
  and its chain's proofs (the parents, as a JSON list of their text). Every
  proof sent must be one the chain names.
- `macula_pool_serve_gated` and `_serve_stream_gated` serve under
  `policy_json`: `{"kind":"ucan_required","issuer"}` (a chain rooted at that
  node's identity key) or `{"kind":"realm_member_required","key_id","can"}`
  (rooted at that realm key, with that can). The provider checks each call
  and open before it reaches the inbox, as macula's link does: a refused call
  is a `provider_error` of code `unauthorized`, or `malformed_frame` for a
  proof no token names; a refused open is a stream `error` of the same code.
  An open procedure ignores any token.

## Confidentiality

Since v0.18.0 (macula 13's end-to-end payload confidentiality, E2E seal
scheme 1). A provider opts in by naming its KEM key in its advertisements, and
callers seal to that key; stations route what they cannot read.

- `macula_pool_connect`'s `kem_advertise: 1` gives the node a KEM keyring (in
  memory only, rotated every 24 hours, a replaced key kept 30 minutes) and names
  its current key in the advertisements of its confidential procedures. Enable
  it only once every station runs macula 12.11 or later (the station floor);
  it is off by default.
- `macula_pool_serve_opts` and `_serve_stream_opts` take `confidential`:
  `preferred` (the default: the key is named, and a clear call is still taken
  while the procedure's last keyless advertisement could be served),
  `required` (every clear call is refused `sealed_required`; needs
  `kem_advertise`, or the serve fails with the kind `confidentiality`, reason
  `kem_advertise_disabled`) or `off` (served in the clear).
- `macula_pool_call_opts` and `macula_pool_open_stream_opts` take
  `confidential`, decided from the provider's verified advertisement only:
  `preferred` seals whenever it names a key, `required` never calls one that
  names none. Only an advertisement naming no key is called in the clear
  (design §8.1): `off` is an explicit target's, and is refused here
  (`invalid_argument`) rather than ignored. A sealed call never falls back to
  the clear. A request's `sealed` (0 or 1) in `macula_served_next` says whether it
  came sealed; its payload is the opened plaintext either way.
- A call that could not be kept confidential fails with the kind
  `confidentiality`: `reason` `no_kem_key` (the provider names no key where
  one is required, or one this node cannot seal to), `key_mismatch` (after a
  `sealed_refused`, the provider's advertisement names another key than its
  refusal did: `named` and `found`), `reply_not_opened` (a sealed answer that
  does not open), `clear_answer_to_sealed` (a clear answer that nothing clear
  may give), or `kem_advertise_disabled`.
- A provider that cannot open a request answers `sealed_refused`, naming the key
  it holds now; the pool looks the provider's advertisement up once more and
  seals again only to exactly that key. A second refusal is a `provider_error`
  of code `sealed_refused`, its `detail` the key id named.
- What stays visible: a request's `token` and `proofs`, sizes, timing and
  routing fields. Content (`macula_pool_share_content`) is served and fetched in
  the clear, as it is public by design.

## Content

`macula_pool_share_content` keeps the bytes in this node, serves them on its
own `~<node_id>/content_v1` and announces them in the realm, for as long as
the pool is open or until `macula_pool_unshare_content`; it gives the MCID.
`macula_pool_get_content` finds the nodes that announced an MCID and fetches
from them, checking every block against it; `not_shared` means none shares
it, `unavailable` that all failed.

## Test harness

`teststation/cmd/teststation` runs two in-process macula 12 stations sharing
one DHT, and a test realm with one org, for a binding's own tests:

```sh
go run github.com/macula-io/macula-go/teststation/cmd/teststation@<tag> [pq_pure|pq_hybrid]
```

It prints one JSON line `{"stations": [{"host","port","node_id"}],
"realm_name", "realm_id", "realm_key", "org"}` (the realm's id is its name's
SHA-256, so a UCAN grants in it by that name), then answers each stdin line with one
line: `admit <node_id hex>` (the org delegates to that node) and `relayed`
(how many streams the stations relay). It exits when stdin closes.

## Release artifacts

Each macula-go `v*` tag's GitHub release carries, built on GitHub-hosted
runners:

| File | Platform |
|---|---|
| `libmacula-linux-x64.so` | Linux x86-64 (glibc 2.28 or later) |
| `libmacula-linux-arm64.so` | Linux arm64 (glibc 2.28 or later) |
| `libmacula-macos-x64.dylib` | macOS x86-64 (13.0 or later) |
| `libmacula-macos-arm64.dylib` | macOS arm64 (13.0 or later) |
| `macula-windows-x64.dll` | Windows x86-64 |
| `macula.h` | the header |
| `SHA256SUMS` | every file above |

The Linux libraries are built in the manylinux_2_28 images and need glibc
2.28 or later; the macOS libraries are built for macOS 13.0 or later, the
floor of the Go toolchain that builds them. Each release job checks its file
against that floor (no `GLIBC_` symbol version above 2.28; `vtool
-show-build` reporting `minos 13.0`) before hashing it. Each library records
its own file name as its SONAME (Linux) or `@rpath/` install name (macOS).

Each file has a GitHub build provenance attestation. A binding downloads
the files for its tag, checks each against `SHA256SUMS`, and verifies its
attestation (`gh attestation verify <file> --repo macula-io/macula-go`)
before using it. It never uses a file that fails either check.
