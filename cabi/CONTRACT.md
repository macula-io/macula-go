# The macula C ABI: contract

`cabi` is macula-go's macula 12 API behind a C ABI, so that one Go
implementation serves every binding not written in Go: .NET (P/Invoke),
Python (ctypes), PHP (FFI) and TypeScript (N-API). `macula.h` declares it;
this file says what every part of it means. A binding follows both and
nothing else.

## Version

`macula_abi_version()` returns the library's `MACULA_ABI_VERSION`. A binding
compares it with the version it was written against and refuses a library
built for another. Any change to a declaration in `macula.h` changes the
version; the set of declarations is fixed per macula-go tag.

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
| served | `macula_pool_serve`, `_serve_stream` | `macula_served_stop` |
| pending call | `macula_served_next` | its answer, or its deadline (never freed by the caller) |
| stream | `macula_pool_open_stream`, `macula_served_next` | `macula_stream_free` |
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
| `cancelled` | the call's cancel token was cancelled | |
| `timeout` | the call's `timeout_ms` ran out | |
| `invalid_handle` | a handle this process does not hold, or of another kind | |
| `invalid_argument` | a malformed id, JSON, profile, mode, size or payload (a JSON boolean, say) | |
| `provider_error` | the provider answered a call with an error | `code`, `detail` (may be null) |
| `relay_error` | a station could not deliver a call | `code` |
| `not_found` | no DHT record under that key | |
| `not_shared` | no node shares that content in that realm | |
| `unavailable` | every sharer failed to give the content | `failures`: a list of strings |
| `answered` | a pending call was answered already | |
| `closed` | the pool, subscription, served procedure or stream has ended | |
| `refused` | the network refused it (an advertisement, an admission, a key) | |
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
| a number with no fraction or exponent | an integer, exact to the full uint64 and int64 range |
| any other number | a float |
| a string | text |
| an array | an array |
| an object | a map with text keys |
| `{"$bytes": "<standard padded base64>"}` (that sole key) | a byte string |

- `true` and `false` are refused (`invalid_argument`): macula's CBOR has no
  boolean. Send 0 and 1.
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
  of code `handler_error`, the message as its detail, cut to 256 bytes). A call not answered by its deadline is answered with an
  error for you; a later answer is `answered`.
- A served stream session is a stream handle like one the node opened. The
  provider sends, replies or aborts, and ends it; `macula_stream_free`
  aborts one not ended.
- `macula_stream_recv` returns one frame as JSON: `data` (with `encoding`,
  `raw` or `value`, and `body`), `end` (the peer closed its send side, with
  its `role`), `reply` (the provider's terminal value), `eof` (the stream
  ended normally), or `error` (a stream error, `relay` 1 when a station
  raised it).

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
"realm_id", "realm_key", "org"}`, then answers each stdin line with one
line: `admit <node_id hex>` (the org delegates to that node) and `relayed`
(how many streams the stations relay). It exits when stdin closes.

## Release artifacts

Each macula-go `v*` tag's GitHub release carries, built on GitHub-hosted
runners:

| File | Platform |
|---|---|
| `libmacula-linux-x64.so` | Linux x86-64 (glibc) |
| `libmacula-linux-arm64.so` | Linux arm64 (glibc) |
| `libmacula-macos-x64.dylib` | macOS x86-64 |
| `libmacula-macos-arm64.dylib` | macOS arm64 |
| `macula-windows-x64.dll` | Windows x86-64 |
| `macula.h` | the header |
| `SHA256SUMS` | every file above |

Each file has a GitHub build provenance attestation. A binding downloads
the files for its tag, checks each against `SHA256SUMS`, and verifies its
attestation (`gh attestation verify <file> --repo macula-io/macula-go`)
before using it. It never uses a file that fails either check.
