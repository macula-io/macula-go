# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `cabi`: macula-go's macula 12 API behind one C ABI (`cabi/macula.h`,
  ABI 1), shared by every binding not written in Go; `cabi/CONTRACT.md` says
  what every call means. Poll-only (inboxes drained by `*_next`, no callback
  into a binding), a cancel token and a timeout on every blocking call,
  errors as JSON with a fixed kind, and payloads mapped exactly between JSON
  and macula's CBOR (int64 integers, floats, `{"$bytes": ...}`, no
  booleans). Tested from Go against in-process stations and from C against
  the built library, the header held to the exports.
- Each `v*` release carries libmacula for Linux x64/arm64 (glibc 2.28+),
  macOS x64/arm64 (12.0+) and Windows x64, with `macula.h` and `SHA256SUMS`,
  every file with a build provenance attestation. CI builds all five on
  every push.
- `teststation/cmd/teststation`: in-process stations for a binding's tests,
  over stdin and stdout.
- `identity.GenerateIdentityKeyContext`: key generation that gives up when
  its context ends.

- `seal`: end-to-end payload sealing, scheme 1 (macula's
  `test/vectors/E2E_SEAL_V1.md`), the primitives only; no frame carries a
  sealed payload yet. ML-KEM-1024, with an ephemeral P-384 ECDH in
  `pq_hybrid`, combined by HKDF-SHA-384 into a shared secret
  (`SenderSecret`, `RecipientSecret`); call, stream and per-publisher event
  keys (`CallKeys`, `StreamKeys`, `EventKey`); the AAD of every sealed frame;
  stream and random nonces; AES-256-GCM `Seal` and `Open`. Held to macula's
  vectors byte for byte on both sides of the key agreement (the sender's
  through `crypto/mlkem/mlkemtest`), copied by
  `scripts/interop/copy_e2e_seal_vectors.sh`. A recipient refuses an
  ephemeral P-384 point whose ECDH output is zero, which `crypto/ecdh`
  itself returns; the vectors' `refusals` entry pins it.

### Documentation

- The README describes the wire as TLS 1.3 with a hybrid post-quantum key
  exchange and names the `pq_hybrid` composite ML-DSA-87 + RSA-PSS-4096,
  instead of calling everything on the wire post-quantum.

## [0.12.0] - 2026-09-26

### Breaking

- A content announcement (0x11) names where the content is served, as macula
  12.6.0's does: `realm_id`, `serving_station` and a non-empty `procedure`,
  which the verifier requires; `endpoint` is gone.
  `record.NewContentAnnouncement` takes them in `ContentAnnouncementOptions`,
  and `ContentAnnouncement` reads them.

### Added

- Node-served content (macula 12.6.0, D27). `pool.ShareContent` keeps content,
  serves it on the node's own `~<node_id>/content_v1` server stream and
  announces it, renewed at half an hour; `UnshareContent` withdraws it with a
  tombstone. `pool.GetContent` finds the announcements whose procedure is
  bound to their announcer (`ContentProcedureBound`), dials each sharer's
  station from its own endpoint record, and checks a block against its
  content id, a manifest against its content id before its sizes are read and
  against `ContentOptions` before a chunk is asked for, each chunk against its
  own content id (four at a time), and the whole. It needs no realm key.
  Cross-checked both ways against macula 12.6.0 (v12.6.0 8ff6bc04) through a
  station: a raw block, 600 KB chunked, a fetch after unsharing, and a padded
  chunk macula's fetcher refuses (`scripts/interop/gocontent`,
  `erlang_content.escript`).

## [0.11.0] - 2026-09-25

### Breaking

- **macula-go speaks the macula 12 wire and nothing older.** Removed with
  the 10.x path, which cannot reach a macula 12 station: `connection`,
  `dht`, `directdial`, `stream`, `content`, the Ed25519 `ucan`, `bolt4`, the
  unsigned 10.x frame builders (`frame.Call`, `Result`, `Connect`, `Hello`,
  `Goodbye`, `Publish`, `Subscribe`, `Advertise`, the 10.x stream frames),
  frame-level Ed25519 signing (`frame.Sign`, `frame.Verify`, `SigDomain`,
  `publisher_sig`), Ed25519 identity (`identity.KeyPair`, `Generate`,
  `VerifyEd25519`) and the trust-mode `transport.Dial` (`WebPKI`, `Pinned`,
  `Insecure`). Content transfer waits for macula's node-served content (D27:
  stations keep none); streaming RPC is back (below); the examples are new (`call`, `serve`, `pubsub`).
- `pool` is rewritten on `stationlink`, as macula 12's `macula_client`:
  `Connect` takes seeds pinned by node_id and `Opts.RealmTrust`, and refuses
  an unpinned seed, a malformed realm key or too many seeds before it dials;
  every link shares the node's identity key, statement issuer (run by the
  pool), request admission, event dedup and publication seq; a link that
  ends is redialed and given back its subscriptions and served procedures.
  `Call` reaches a provider by direct dial (its trusted advertisements from
  the DHT, freshest first, the serving station dialed from its own
  station_endpoint, the next candidate on a reachability failure);
  `Providers`, `Serve`, `Publish` (signed once for every link), `Subscribe`,
  `FindRecord`, `FindRecords`, `FindRecordsByType`, `PutRecord`. Station
  discovery is removed (macula#31).
- `teststation`: an in-process macula 12 station (many connections, the
  DHT, CALLs and streams routed to the advertising connection, PUBLISH
  delivered as EVENTs), public so SDKs built on macula-go test against it;
  it reports to any `teststation.T`, which a `*testing.T` is.
- `manifest` is macula 12's: SHA-384 hashes and a 50-byte `Mcid`
  (`<<2, Codec, SHA-384>>`), `HashSize` and `Hash`; `SHA384` replaces
  `Blake3`, and a wire manifest that names no hash algorithm, or any but
  `sha384`, is refused. Checked byte for byte against manifests macula
  built. The BLAKE3 dependency is gone.
- A node's own namespace, `~<node_id>/<name>` (macula 12.5.0, D25 item 6):
  `record.OwnNamespace` and `VerifyAuthorization` decide it as
  `macula_record` does (the 64 lowercase hex characters after `~` must be
  the advertiser, which the signature binds; no authorization may be
  attached; another node's namespace is `ErrNotOwnNamespace`, a mis-spelled
  one `ErrMalformed`), held to macula's shared fixtures under both profiles
  (`record/testdata/own_namespace`, copied by
  `scripts/interop/copy_own_namespace_fixtures.sh`). `Serve` serves one with
  no realm key and no chain from the DHT; `Call`, `Providers` and
  `OpenStream` reach one with no realm key pinned. `record.InOwnNamespace`,
  `NamespaceNode` and `OwnProcedure` name the form. The teststation admits
  an own-namespace advertisement only from the node it names, as
  macula-station 0.6.4 does.
- Streaming RPC on the macula 12 wire: `stationlink.Link.OpenStream` and
  `pool.OpenStream` (by direct dial) open a session on a QUIC stream of its
  own; `Offer.Stream` serves one with a `StreamHandler`. `Stream` sends
  (`Send`, `SendValue`, `CloseSend`, `Close`, `Reply`, `Abort`) and receives
  (`Recv`: data, end and reply events, or a `*StreamError`) signed frames, a
  seq per side. Opens are admitted as CALLs are and bounded by sessions per
  caller and per node; inboxes are bounded per stream, per caller and per
  node. Every stream is released on every path.
- `stationlink.Link.Serve` serves an org procedure: its org directory and
  delegation from the DHT, checked against the realm key, an advertisement
  naming the connected station, sent in an ADVERTISE and put in the DHT,
  renewed at half its lifetime; inbound CALLs admitted as
  `macula_request_admission` admits them and answered with a signed RESULT,
  `handler_error`, `temporary_relay_failure` or `unknown_next_peer`; `Stop`
  withdraws it with a tombstone. Gated procedures are refused
  (`ErrGatedUnsupported`, #2). Links of one node share an `Admission` and an
  `EventDedup` (`Config.Admission`, `Share`, `Dedup`); `SignPublication` and
  `PublishSigned` send one publication on several links.
- A `pq_hybrid` key signs the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512,
  as macula 12 does: the label is `COMPSIG-MLDSA87-RSA4096-PSS-SHA512`, and
  the ML-DSA-87 half signs with that label as its context. Composites made
  under the earlier `MACULA-ML-DSA-87-PS384` label no longer verify, in either
  direction. Checked against the LAMPS draft's own vector, a composite macula
  12.1.0 signed, and macula 12.1.0 verifying macula-go's keys (26 checks) and
  bindings (40 checks); the bindings fixture is rewritten by macula 12.1.0.
- `stationlink`, a client's link to one macula 12 station, as macula's
  `macula_station_link`: `Dial` dials the target through
  `transport.DialTarget`, runs the v4 handshake on one control stream with
  the CONNECT material of an `identity.StatementIssuer`, and keeps the link:
  it sends its status statement at every reissue, ends when the station's
  statement lapses five minutes past expiry or its TLS binding reaches
  not_after, neighbour-signs control frames with a seq per direction (and
  ends on one out of sequence), ends on the station's GOODBYE, and sends its
  own on `Close`. `Link.Call` sends a signed CALL (to the station itself for
  `_dht.*` and `_macula.ping`, to the provider for an org procedure) and
  returns the RESULT payload, a `*ProviderError` or a `*RelayError`, each
  verified for its request; a reply that does not verify is counted and
  ignored. The link probes `_macula.ping` every 30 s and ends after two
  misses. `PutRecord`, `FindRecord`, `FindRecords` and `FindRecordsByType`
  reach the station's DHT as macula's facade does (station calls on the zero
  realm carrying record wire bytes); every record found is verified before it
  is handed on, and one that does not verify is dropped and counted.
  `Publish` sends a publication signed with the link's identity key, its seq
  from a `PublicationSeq` (wall-clock microseconds, then counting up, shared
  by the links of one key); `Subscribe` sends SUBSCRIBE and delivers each
  EVENT whose publication verifies, once, until it expires; `Unsubscribe`
  sends UNSUBSCRIBE when the last subscription to a realm and topic ends.
  The runtime moves onto it chunk by chunk
  (`plans/PLAN_MACULA_12_RUNTIME.md`).
- Neighbour signatures (D17), as macula 12 signs and reads them:
  `frame.SignNeighbour` and `frame.VerifyNeighbour` wrap a control frame as
  `{version, frame_type, neighbour}` in `pq_hybrid`, a held object under
  `MACULA-PQ-NEIGHBOUR-V1` over the frame's fields, the connection hash and a
  per-direction seq, and leave it as it is in `pq_pure`. The control frames a
  client link sends in macula 12 have builders of their own:
  `AdvertiseFrame` and `UnadvertiseFrame` (a signed record), `SubscribeFrame`,
  `UnsubscribeFrame` and `GoodbyeFrame`. macula 12.1.0 verifies all five as
  macula-go signs them (12 checks), and macula-go reads macula's
  (`frame/testdata/erlang_neighbour.json`), refusing both at the wrong seq or
  on another connection. `stationlink` sends them.
- A request carries its delegation chain's proofs (`RequestSpec.Proofs`,
  `VerifiedRequest.Proofs`) in its signed part, as macula 12 does: at most
  `MaxProofs` (8) distinct byte strings of at most `MaxProofsBytes` (256 KiB)
  in all. `SignCall` refuses a set outside that with `ErrProofsOutOfBound`,
  and a verifier refuses it as a malformed frame. The shared decoding-rule
  vectors are macula v12.1.0's (59 entries); the five read "via"
  request_fields run in `frame`'s `TestRequestFieldVectors`.
- The post-quantum handshake is version 4, as macula 12's: CONNECT always
  carries `member_endorsement`, empty when the node holds none
  (`ClientSession.MemberEndorsement`), outside the proof, and the station is
  handed it (`Client.MemberEndorsement`); nothing here checks it. A version 3
  frame is refused `unsupported_version`. macula 12.1.0 accepts macula-go's
  CONNECT and answers its CHALLENGE, and macula-go accepts macula's CONNECT and
  answers its CHALLENGE, in both profiles (`handshake/testdata/erlang_handshake.json`).
- A profile dial offers and accepts macula-pqc's key exchange groups,
  `transport.KeyExchangeGroups` (SecP384r1MLKEM1024, then SecP256r1MLKEM768),
  whatever the node's profile, as every macula 12 station does, and checks no
  cipher suite. `ErrWrongCipherSuite` is gone, as are `profile.Definition`'s
  `KeyExchangeGroup` and `TLSCipherSuite`. `pq_pure` no longer offers
  ML-KEM-1024 alone, which no macula 12 station accepts.

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
- `identity.Verify` checks a signature by a node key (see Added).
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
  the zero value, and a nil `*NodeKey` have no public key and refuse to sign
  with `ErrEmptyNodeKey`.
- `NodeKey.Save` and `identity.LoadKey`: key files in the seed form, readable
  by their owner only. `Save` creates the file exclusively in a new owner-only
  directory beside the path, syncs it, renames it over the path, syncs the
  path's directory and removes the new one, leaving anything else beside the
  path as it was. `LoadKey` follows a symlink, as macula does, and checks the
  file it reaches. It refuses a path that names anything but a regular file
  (`ErrKeyFileNotRegular`) before opening it and again on the opened file,
  which it opens without waiting on a FIFO; a file another user owns, or whose
  owner cannot be read (`ErrKeyFileOwner`), where the platform has user ids; a
  file its group or others can read (`ErrKeyFilePermissions`); a file longer
  than 64 KiB (`ErrKeyFileTooLarge`); a key for another purpose or profile; a
  stored public key its private key does not derive; and a key that fails a
  sign-and-verify round trip.
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
  carries on past a failure and returns every error. A rotation that fails is
  counted (`RotationFailures`) and retried at the next tick, and once the
  current binding expires within `RotationMargin` (24 hours) a tick reports it
  as `ErrRotationOverdue`. `Run` and `RunEvery` with no error handler log a
  failed tick as a warning on slog's default logger. A clock stepped back
  within a verifier's 5 minutes of tolerance keeps the current CONNECT key;
  a step further back rotates it. `Subscribe` delivers a
  binding's newest statement, and its channel closes when the binding ends or
  the subscriber unsubscribes; the subscriber owns the subscription. Bindings
  and statements are handed out as copies. Nothing is written to disk.
- `handshake`: the connection handshake (version 4, see Breaking) as CBOR bytes, on both
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
  a frame over the cap with `frame.ErrFrameTooLarge`.
- `transport.DialTarget` dials a `transport.Target`, a station's host and port
  with its crypto profile and expected node_id, with the TLS 1.3 settings of
  that profile. It offers only the profile's key exchange group and macula's
  ALPN protocol, and keeps no session cache, so every connection is a full
  handshake with no early data. It checks no chain, name or expiry of the
  self-signed station certificate: the completed handshake, whose signature
  crypto/tls verifies against the leaf, shows that the station holds the
  leaf's key. It refuses a target without an expected node_id or a known
  profile before dialing, and a handshake on a group outside
  `transport.KeyExchangeGroups` (`ErrWrongKeyExchangeGroup`), with anything but one
  certificate with a key of the profile's signature scheme, ML-DSA-87 in both
  profiles (`ErrStationCertificate`), or with no ALPN protocol or another one.
  It returns the caller's own copy of the leaf DER as it arrived, for the
  connection handshake. `Dial` and its trust modes stay until the connection
  moves to the post-quantum handshake.
- `identity.ErrPostQuantumUnavailable` and `identity.CheckPostQuantum`. A
  binary built with `GOFIPS140=v1.0.0` (or `GOFIPS140=certified`, which names
  that module at Go 1.27) uses the FIPS 140-3 Go Cryptographic Module v1.0.0,
  which has no ML-DSA, and every profile signs with ML-DSA-87. Such a binary
  returns `ErrPostQuantumUnavailable` from `GenerateKey`,
  `GenerateIdentityKey`, `LoadKey` (before reading the file),
  `VerifyTLSBinding`, `VerifyConnectBinding`, `VerifyStatus`, `VerifyObject`
  and `VerifyHeldObject` (and so from the handshake's checks and from
  `frame.VerifyRequest`, `VerifyReply`, `VerifyRelayError`,
  `VerifyProviderStream`, `VerifyCallerStream` and `VerifyPublication`, and
  from `record.Verify`), and
  `transport.DialTarget` (before dialing), instead of an error that blames a
  signature or a TLS handshake. Build without `GOFIPS140`, or with
  `GOFIPS140=v1.26.0` or later. CI runs the tests for it under
  `GOFIPS140=v1.0.0` and requires each to pass.
- `identity.SignObject`, `SignHeldObject`, `VerifyObject` and
  `VerifyHeldObject`: the signed objects of macula 11.0.0's records and
  frames, `{key, tbs, signature}` when the signer's key travels with the
  object and `{tbs, signature}` when the verifier holds it. A signature covers
  the label, a zero byte, the SHA-384 of the key as carried, and `tbs`, which
  holds the signed fields with `alg`. A verifier checks the object's shape,
  the carried key's form, the signature over `tbs` as received, and only then
  decodes `tbs` under the decoding rule and checks its `alg`, refusing with
  `ErrObjectMalformed`, `ErrObjectSignatureInvalid` or `ErrObjectAlgMismatch`.
  `ParseObject`, `ParseHeldObject`, `DecodeObject` and `DecodeHeldObject` read
  the wire form.
- `frame.SignCall`, `SignStreamOpen`, `SignResult`, `SignProviderError` and
  `SignRelayError`, with `VerifyRequest`, `VerifyReply`, `VerifyRelayError`
  and `ClaimedReplyIDs`: macula 11.0.0's requests, replies and relay errors
  (D25). A request is a signed object under `MACULA-PQ-REQUEST-V1` from the
  caller's identity key, a reply one under `MACULA-PQ-REPLY-V1` from the
  request's target, and a relay error one under `MACULA-PQ-RELAY-ERROR-V1`
  from a station, with a code from the closed set and no detail. A STREAM_OPEN
  carries a stream mode and a CALL none. A builder refuses what its receiver
  would: a key that is not an identity key or not the expected sender
  (`ErrUnsignable`), a procedure over 512 bytes, a code over 64 or a detail
  over 256 (`ErrTextTooLong`), text that is not UTF-8 (`ErrInvalidText`), a
  payload the wire cannot carry, a relay code outside its set
  (`ErrRelayCodeOutsideItsSet`), and a field out of its range or set
  (`ErrOutOfRange`). A verifier reads a frame in macula's order, its version
  and routing fields as a received frame is decoded, and refuses with
  `ErrMalformedFrame`, `identity.ErrObjectSignatureInvalid`,
  `ErrKeyIDMismatch`, `ErrRequestMismatch`, `ErrNotTheTarget` or
  `ErrNotTheConnection`, and in a binary without ML-DSA with
  `identity.ErrPostQuantumUnavailable`. `ClaimedReplyIDs` reads the ids a
  reply names without verifying it, as the key for finding its pending
  request.
- `frame.SignProviderStream` and `SignCallerStream`, with `OpenStream`,
  `VerifyProviderStream` and `VerifyCallerStream`: macula 11.0.0's stream
  frames for a verified STREAM_OPEN (D25). A provider's STREAM_DATA,
  STREAM_END, STREAM_ERROR and STREAM_REPLY carry a signed object under
  `MACULA-PQ-STREAM-V1` with the provider's key on its first frame only, and a
  caller's STREAM_DATA, STREAM_END and STREAM_ERROR one under
  `MACULA-PQ-CALLER-STREAM-V1` that verifies with the STREAM_OPEN's key. Each
  frame names its stream by request_id and request_hash, and each side numbers
  its own frames from 0. A builder takes `StreamDataFields`,
  `StreamEndFields`, `StreamErrorFields` or `StreamReplyFields` and refuses
  what its receiver would, in macula's order: a key that is not the expected
  sender, or an open that is not a verified STREAM_OPEN (`ErrUnsignable`); a
  frame its side does not send, a caller's STREAM_REPLY or its STREAM_DATA in
  a server_stream (`ErrNotAllowed`); a STREAM_ERROR's code over 64 bytes or
  message over 256, or either not UTF-8; a body or payload the wire cannot
  carry; and a field out of its range or set (`ErrOutOfRange`). A verifier
  holds a `StreamState` and returns the next one with each frame, which
  replaces it: a `StreamState` value accepts at most one frame, and a copy
  kept or shared accepts the same seq again, so a stream's state has one
  owner. `OpenStream` keeps its own copies of the open's key and mode. Ending
  the stream on a STREAM_ERROR, or on a STREAM_END with role both, is the
  stream session's; the verifiers refuse only a side's frames after its own
  STREAM_END. A verifier refuses
  with `ErrMalformedFrame`, `ErrStreamEnded`,
  `identity.ErrObjectSignatureInvalid`, `ErrKeyIDMismatch`,
  `ErrRequestMismatch`, `ErrNotTheTarget` or `ErrSeqMismatch`, and in a
  binary without ML-DSA with `identity.ErrPostQuantumUnavailable`.
- `frame.SignPublish` and `VerifyPublication`: macula 11.0.0's publications
  (D17). A PUBLISH carries a signed object under `MACULA-PQ-PUBLICATION-V1`
  from the publisher's identity key. Its tbs holds no frame type, so the same
  bytes ride in every EVENT and GOSSIP made from it. `SignPublish` refuses, in
  the order of macula's `publish/2`, a key that is not an identity key
  (`ErrUnsignable`), a seq or published_at of 2^53 or more (`ErrOutOfRange`),
  a topic over 512 bytes or not UTF-8, a payload the wire cannot carry, and a
  ttl_ms over one hour (`ErrOutOfRange`).
  `VerifyPublication` reads a PUBLISH, EVENT or GOSSIP and returns the
  publication with its hash and `ExpiresAt`. It refuses with
  `ErrMalformedFrame`, `identity.ErrObjectSignatureInvalid`,
  `ErrKeyIDMismatch`, or a `FreshnessError` wrapping `ErrNotYetValid`
  (published more than 5 minutes ahead) or `ErrExpired` (past its ttl_ms, or
  10 minutes without one, plus 5 minutes), and in a binary without ML-DSA with
  `identity.ErrPostQuantumUnavailable`.
- `record`: macula 11.0.0's records, the signed object under
  `MACULA-PQ-RECORD-V1`, as `macula_record` has them for 11.0.0.
  `record.Sign` refuses, in macula's order, a key whose purpose does not fit
  the type (`ErrKeyPurposeMismatch`; a Go key signs the types an identity key
  signs), a lifetime that runs backwards or past its type's maximum
  (`ErrLifetimeReversed`, `ErrLifetimeTooLong`), a payload that names another
  signer (`ErrKeyIDMismatch`), a tbs or payload a verifier would refuse, read
  from the tbs decoded under the decoding rule, so among them an empty subject,
  a payload nested too deep and a duplicate or byte-string map key at any
  depth (`ErrMalformed`), and a record over 256 KiB (`ErrRecordTooLarge`), so
  it signs no record a verifier refuses for anything but its clock.
  `record.Verify` reads a record's wire form in macula's
  order: its size, its shape, its signature, a tbs of exactly its fields,
  created_at and expires_at within 5 minutes of the verifier's clock
  (`ErrNotYetValid`, `ErrExpired`), the lifetime of its type, its type's
  payload rules (`ErrMalformed`) and its named signer. It returns a
  `record.Verified`, which only `Verify` makes and whose `Record` method hands
  out a copy, so nothing a caller does afterwards changes the record it holds.
  A type lives at most 48
  hours for a node record or content announcement, 5 minutes for a procedure
  advertisement or station endpoint, 6 hours for realm stations, an org
  directory or a procedure delegation, 30 days for a realm member endorsement,
  7 days for a domain record and 30 days otherwise; a tombstone lives its
  withdrawn type's maximum plus 10 minutes. A record is named by its signer's
  node_id on the node-signed types and by its key id on every other type.
  `NewNodeRecord` and `ReadNodeRecord` build and read node records. A
  coordinate travels as text and reads back only from text of at most 32
  bytes, an optional minus, digits, then optionally a dot and digits, within
  -90 to 90 for lat and -180 to 180 for lng, as `macula_record` reads it, and
  `NewNodeRecord` refuses a coordinate outside its range
  (`ErrInvalidCoordinate`). `Envelope` builds domain records and refuses
  an empty subject (`ErrInvalidSubject`), which a verifier refuses as
  malformed. `Refresh` signs a record again with a new version, and
  `PayloadBounded` checks a payload before signing.
  `NewProcedureAdvertisement` and `ReadProcedureAdvertisement` build and read
  procedure advertisements, whose provider authorization, an org directory and
  a procedure delegation, travels in the payload and is never parsed by a
  storing verifier. macula 11.0.0 has no other form: the builder refuses to
  build one (`ErrAuthorizationFormUnsupported`), and the reader reports any
  other authorization map, a certificate chain among them, as the
  `UnsupportedAuthorization` form, which `VerifyAuthorization` refuses.
  `NewContentAnnouncement` and `ReadContentAnnouncement`,
  `NewStationEndpoint` and `ReadStationEndpoint`, and `NewTombstone` and
  `ReadTombstone` build and read those records; a tombstone takes the slot of
  the record it withdraws and outlives it by the clock tolerance, and
  `ReadTombstone` refuses a withdrawn type outside 1 to 255. `StorageKey`
  derives a record's DHT storage key, and `ProcedureKey`, `ContentKey`,
  `StationEndpointKey`, `OrgDirectoryKey` and `ProcedureDelegationKey` derive
  the keys a lookup needs.
  `VerifyAuthorization` checks a procedure advertisement's provider
  authorization against a caller's `Trust`, the realm key, as `macula_record`'s
  `verify_authorization` does. It takes a `record.Verified`, so only a record
  `Verify` returned reaches it. `ProcedureOrg` reads the procedure's org
  namespace. The org directory, signed by the realm key, must name the
  advertisement's realm and the procedure's org, and the procedure delegation,
  signed by the org key the directory names, must name the advertiser
  (`ReadOrgDirectory`, `ReadProcedureDelegation`); the advertisement expires
  no later than either. An authorization in any other form is
  `ErrAuthorizationFormUnsupported`, and each refusal has its own error, from
  `ErrNoAuthorization` to `ErrAuthorizationOutlived`.

### Fixed

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
