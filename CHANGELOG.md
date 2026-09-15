# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- `cbor.Decode` decodes under macula 11.0.0's decoding rule and returns
  `(Value, error)`. It refuses bytes after the top-level value, map keys other
  than text or integers, duplicate map keys, text that is not valid UTF-8,
  lists and maps nested more than 64 levels, integers below -2^63 or above
  2^63-1, floats that are NaN or infinite, and input of more than
  `cbor.MaxElements` (131,072) items, each with an error of its own:
  `ErrTrailingBytes`, `ErrBadKey`, `ErrDuplicateKey`, `ErrInvalidText`,
  `ErrNestingTooDeep`, `ErrIntegerOutOfRange`, `ErrTooManyElements` and
  `ErrMalformed`. Every item counts once against the budget, map keys and
  array elements included. It accepts lengths in any width, map keys in any
  order, and half, single and double floats. `cbor.MaxNestingDepth` is 64. A
  list or map is given room by the bytes that follow it, not by the count it
  declares.
- `frame.CheckPayload` refuses what that rule refuses: byte-string map keys,
  integers outside -2^63 to 2^63-1, text that is not valid UTF-8, payloads
  nested more than `frame.MaxPayloadNesting` (63) levels, and payloads of more
  than `frame.MaxPayloadElements` items, which leaves
  `frame.FrameReservedElements` (64) of the budget for the frame's own fields.
- `identity.Verify` checks a signature by a node key (see Added). The Ed25519
  check it replaces is `identity.VerifyEd25519` for now.
- macula-go requires Go 1.27.

### Added

- `profile`: the crypto profiles `pq_pure` and `pq_hybrid`, parsed from
  configuration with no default, and each profile's key exchange group, TLS
  signature scheme, cipher suite and signature algorithm.
- `identity.NodeKey`: a node's identity or CONNECT key in its profile, with
  `GenerateKey`, `GenerateIdentityKey` for a node_id puzzle difficulty, `Sign`,
  `PublicKey` in the carried form, `NodeID` and `KeyID`, and the functions
  `Verify`, `NodeIDOf`, `KeyIDOf`, `CarriedKeyWellFormed`, `SignatureSize` and
  `PuzzleSolved`. In `pq_hybrid` a key signs Macula's composite
  ML-DSA-87-PS384, valid only if both halves verify. A node key never shows a
  private half when printed or logged. A `NodeKey` that holds no key, such as
  the zero value, has no public key and refuses to sign with `ErrEmptyNodeKey`.
- `NodeKey.Save` and `identity.LoadKey`: key files in the seed form, readable
  by their owner only. `Save` creates the file exclusively in a new owner-only
  directory beside the path, syncs it, renames it over the path, syncs the
  path's directory and removes the new one, leaving anything else beside the
  path as it was. `LoadKey` follows a symlink, as macula does, and checks the
  file it reaches. It refuses a path that names anything but a regular file
  (`ErrKeyFileNotRegular`) before opening it and again on the opened file,
  which it opens without waiting on a FIFO; a file another user owns
  (`ErrKeyFileOwner`), where the platform has user ids; a file its group or
  others can read (`ErrKeyFilePermissions`); a file longer than 64 KiB
  (`ErrKeyFileTooLarge`); a key for another purpose or profile; a stored public
  key its private key does not derive; and a key that fails a sign-and-verify
  round trip.
- `identity.TLSBinding`, `ConnectBinding` and `StatusStatement` issue the
  signed structures that bind a TLS or CONNECT key to an identity key, and
  that keep a binding in force, as a `SignedTBS` of `tbs` and `signature`.
  `VerifyTLSBinding`, `VerifyConnectBinding` and `VerifyStatus` check the
  signature over the `tbs` bytes as received before decoding them under the
  decoding rule. They refuse an unknown or duplicate key, a field of the wrong
  type or length, another node_id, use or subject, and a binding or statement
  outside its validity with 5 minutes of tolerance, each with its own error.
  `VerifyStatus` checks that a statement names its binding, not the binding
  itself, so a caller verifies both. `ParseSignedTBS` reads the
  `{tbs, signature}` map.
- `identity.StatementIssuer`: a client's status statement issuer. It holds the
  CONNECT key with its binding and a fresh status statement. At every `Tick`
  (`Run` ticks every 15 minutes) it issues a statement valid for an hour for
  each binding still in force. Every 5 days it rotates the CONNECT key, with
  the new binding and statement in place before `ConnectMaterial` hands the key
  out; a rotated-out binding keeps its statements until its not_after, and the
  issuer lets go of the rotated-out key. `ConnectMaterial` does work that is
  due itself, after missed ticks, a sleep or a clock step, and returns
  `ErrNoConnectMaterial` rather than a binding or statement out of force. The
  current binding is let go of only once a new one replaces it, and a tick
  carries on past a failure and returns every error. `Subscribe` delivers a
  binding's newest statement, and its channel closes when the binding ends or
  the subscriber unsubscribes; the subscriber owns the subscription. Bindings
  and statements are handed out as copies. Nothing is written to disk.
- `handshake`: the version 3 connection handshake as CBOR bytes, on both
  sides. `Opener`, `Challenge`, `AnswerChallenge` (the client checks the
  challenge's frame, profile, carried key, key purposes, the station's node_id
  against the one dialed, the TLS binding against the leaf it received, and the
  status statement, before it signs its proof), `AcceptConnect` (the station
  checks CONNECT, the node_id puzzle before any signature, the CONNECT binding
  and statement, and the proof, and answers with a HELLO that refuses with one
  coarse code), `ReadHello`, `StatusFrame` and `ReadStatus`. Every frame
  decodes exactly its keys, each of its type and length.
- `frame.CheckFrame` checks a whole frame under the decoding rule, as macula
  checks every frame before it sends it: at most `cbor.MaxElements` items and
  `cbor.MaxNestingDepth` levels, besides what `frame.CheckPayload` checks. Its
  refusals wrap `frame.ErrFrameBreaksDecodingRule`, and `frame.Encode` refuses
  a frame over the cap with `frame.ErrFrameTooLarge`. Every frame a
  `connection.FrameStream` sends passes both before anything is written, so a
  call, publish or stream frame that fails either returns that error. A
  handler reply that fails either is logged, and the call is answered with an
  ERROR instead: `PayloadTooLarge` for a reply over the cap, `UnknownError`
  otherwise.

### Fixed

- A frame over the frame cap sent on a control stream ended the session. It
  returns `frame.ErrFrameTooLarge` and leaves the session up.
- Drop warnings escaped control characters but printed Unicode format
  characters as they were. They escape those too, the bidirectional overrides
  and isolates among them.

- `cbor.Value.AsInt64` reports -2^63-1 as not fitting an int64, where it
  returned 2^63-1.
- `cbor.Value.String` prints integers below -2^63 as they are, where it
  printed a wrapped value.

## [0.10.0] - 2026-09-14

### Breaking

- An inbound CALL whose payload is a map, and a STREAM_OPEN whose args are a
  map, carry the caller the session verified under `"caller"`, as the 32-byte
  node id, replacing a `"caller"` the sender put there under a text or a
  byte-string key. A payload or args that aren't a map are handed over
  unchanged.
- `manifest.CreateOptions.HashAlgorithm`, `manifest.Sha256` and
  `manifest.AlgorithmFromName` are removed. Blake3 is the one hash algorithm a
  manifest can name, and every macula stack refuses a sha256 manifest.

### Security

This release fixes these defects in v0.9.0 and earlier releases.

- A fetched manifest was used before it was checked against the MCID asked
  for, and its size, chunk count and chunk size were taken as given, which
  could stop or stall the process.
- A RESULT, ERROR or STREAM_REPLY counted without a check that it was signed
  by the key its `responded_by` or `reported_by` names.
- A dedicated stream reached a provider without a check that its STREAM_OPEN
  was signed by its caller.
- CBOR decoding had no limit on how deeply lists and maps nest.
- On a 32-bit platform, a frame's claimed length could pass the frame size
  cap.

### Added

- `connection.Session.AcceptStreamOpen` accepts the next dedicated stream
  whose first frame is a STREAM_OPEN signed by the caller it names.
  `stream.Accept` uses it.
- `stream.Handle.Refuse` turns down a stream `Accept` handed a provider: it
  writes a STREAM_ERROR with the given code and message, finishes its side of
  the stream, and stops receiving with `connection.StreamRefusedCode`. Use
  `not_found` for a procedure the provider doesn't serve and `unauthorized` for
  a caller it won't serve.
- Drop warnings. A session with a logger (`Session.SetLogger`) logs the
  inbound frames it drops, and the dedicated streams it refuses or aborts, as
  `macula: drop warning` lines with a kind, a count and a reason, using the
  names every macula stack logs. The kinds are `refused_stream_open`,
  `dropped_call`, `dropped_reply`, `aborted_stream` and `dropped_frame`. A
  frame is `unsigned` when its signature is missing or isn't 64 bytes, or its
  signer is missing or isn't a 32-byte key, and `invalid_signature` when both
  are well formed and it doesn't verify. The first drop of a kind is logged at
  once and opens an interval; the rest during it are logged in one closing
  line when it ends. `Session.SetDropWarningInterval` sets the interval, a
  minute by default. The procedure and frame_type a warning carries are cut to
  256 bytes and have their control characters escaped by the SDK, so the
  line never breaks whatever handler prints it.
- `connection.StreamRefusedCode` (2) and `connection.StreamProtocolErrorCode`
  (3), the QUIC application error codes every macula stack uses for a refused
  dedicated stream and for one carrying a frame that doesn't decode, with
  `FrameStream.Abort` and `FrameStream.StopReceiving`.
- `manifest.McidFor`, `manifest.VerifyMcid` and `manifest.CheckWhole`, with
  `manifest.ErrManifestMcidMismatch` and `manifest.ErrManifestNotWhole`.
- `connection.FrameStream.StreamReplyCounts`, `connection.ErrMalformedFrame`,
  `cbor.MaxNestingDepth`, `cbor.ErrNestingTooDeep`, `cbor.MaxElements` and
  `cbor.ErrTooManyElements`.
- `manifest.CheckChunkHashes` and `manifest.ErrManifestChunkHashes`.
- `pool.Opts.Logger` and `pool.Opts.DropWarningInterval`, given to every
  session a pool link dials, a redial's included, so a pool link logs its drop
  warnings and its end as a session connected on its own does.

### Changed

- A dedicated stream reaches a provider only when its first frame is a
  STREAM_OPEN whose signature verifies against its caller. Any other stream is
  reset and stopped with `StreamRefusedCode`, nothing is written on it, and a
  `refused_stream_open` drop warning gives the reason: `invalid_signature`,
  `unsigned`, `not_a_stream_open` or `malformed`.
- A RESULT counts only when it is signed by the key its `responded_by` names,
  and an ERROR only when it is signed by the key its `reported_by` names. This
  holds on the control stream, on dedicated streams (`FrameStream.Call`, which
  content transfer uses) and for a STREAM_REPLY (`Handle.AwaitReply`). A reply
  that doesn't verify, doesn't parse, or answers no call or stream waiting for
  it is dropped with a `dropped_reply` drop warning, and the call keeps waiting
  until its timeout.
- On an established dedicated stream, a frame that doesn't decode ends the
  stream: it is reset and stopped with `StreamProtocolErrorCode`, and an
  `aborted_stream` drop warning names the reason `malformed`. A session whose
  control stream carries a frame that doesn't decode ends with an error
  wrapping `ErrMalformedFrame`.
- A frame of a type the control stream doesn't carry, and an EVENT that
  doesn't parse or that no subscription matches, is a `dropped_frame` drop
  warning. These replace the per-type unrouted log line. `Session.Unrouted`
  counts a frame under its frame type when that is one macula defines, and
  under `"unknown"` otherwise.
- CBOR decoding refuses a list or map nested more than `MaxNestingDepth` (128)
  levels below the top-level value with `ErrNestingTooDeep`, the same cap as
  macula's decoder. Duplicate map keys are matched by a digest of each key's
  canonical encoding, built as the key decodes, and still merge exactly when
  their canonical encodings are equal. Decoding refuses a value that would
  decode to more than `MaxElements` (1<<20) values in all, counting every value
  it decodes: the top-level value, each list and map, and each list item, map
  key and map value. The error is `ErrTooManyElements`.
- `content.Get` uses a fetched manifest only once it describes the requested
  MCID (`manifest.VerifyMcid`), its chunks are cut the way `manifest.Create`
  cuts content (`manifest.CheckWhole`), and its chunk hashes make its root hash
  (`manifest.CheckChunkHashes`), so no chunk is fetched before all three hold.
  Each fetched chunk must be the size its entry says, and the receive buffer is
  no longer sized from the manifest. `manifest.Verify` refuses a chunk size that
  isn't positive.
- `manifest.FromWire` reads a missing `hash_algorithm` as blake3 and refuses
  any other name, sha256 included. It also refuses a manifest whose chunks
  don't describe its content whole, so empty content has one form: size 0,
  chunk_count 0, no chunks and a positive chunk_size. `manifest.VerifyMcid`
  refuses any hash algorithm but blake3.
- The session-end log line carries a station's GOODBYE reason and detail each
  cut to 256 bytes, with control characters escaped as in drop warnings, and
  the SDK's own words around them whole. Any other reason is cut and escaped
  as a whole.

### Fixed

- Setting a frame's signature or `publisher_sig` works on a copy of its
  entries. Signing a frame a second time, by another identity or after it was
  already signed, no longer rewrites the signature of the frame signed first.
- `frame.Decode` compares a frame's claimed length with `MaxFrameBytes` before
  converting it to an `int`.
- `manifest.FromWire` checks a manifest's version against the range of a
  `uint32`, and its chunk size, chunk count and each chunk's index, offset and
  size against the range of an `int`, before converting them.

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
