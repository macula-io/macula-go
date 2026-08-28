# macula-go-sdk

Go port of the [macula-rust-sdk](https://github.com/macula-io/macula-rust-sdk)
wire protocol — same client/leaf side of Macula's mesh, ported per the
same spec ([`plans/PLAN_WIRE_PROTOCOL.md`](plans/PLAN_WIRE_PROTOCOL.md),
carried over from the Rust port since the protocol itself isn't
language-specific).

## Status: walking skeleton, live-verified

**Built and confirmed working against the real production fleet
(`station-de-frankfurt.macula.io`), 2026-08-28:**

- Deterministic/canonical CBOR codec (`cbor/`) — hand-rolled, not a
  generic library, for the same reason the Rust port didn't use one:
  this protocol's canonical form deliberately diverges from RFC 8949
  (always-binary64 floats, map keys sorted by their own *encoded*
  bytes). Verified against hand-derived byte vectors for every
  minimal-length-encoding boundary, the map-key-sort rule specifically,
  and round-trip decode/re-encode identity.
- Ed25519 identity + S/Kademlia puzzle-hardening (`identity/`).
- The frame envelope, CONNECT/HELLO/GOODBYE, and Ed25519 sign/verify
  (`frame/`) — cross-checked **byte-for-byte, including the signature
  itself**, against the exact same fixed test vector
  `macula-rust-sdk/src/frame.rs` uses (which was itself checked against
  a live Erlang reference). See `frame/reference_vector_test.go`.
- QUIC/TLS transport with WebPKI, pubkey-pinned, and insecure trust
  modes (`transport/`).
- The CONNECT/HELLO handshake and `Session` (`connection/`) —
  `connection/live_test.go` (behind the `live` build tag) dials the
  real fleet and completes a full handshake: `accepted=true`.

**Not yet built:** unary RPC (CALL/RESULT/ERROR), PubSub, content
transfer, streaming RPC. See the Rust port's own README for what full
parity looks like — this crate is following the same order it was
built in.

## Testing

```bash
go test ./...                                              # default suite, no network
go test -tags=live ./connection/... -run TestLive -v       # dials the real fleet
```

## Related projects

| Project | Description |
|---|---|
| [macula-rust-sdk](https://github.com/macula-io/macula-rust-sdk) | The Rust port — same protocol, built first, more complete |
| [macula](https://github.com/macula-io/macula) | The reference SDK (Erlang/OTP) |
| [macula-station](https://github.com/macula-io/macula-station) | The station: DHT, SWIM, routing, peering |

## License

Not yet decided — will match `macula-rust-sdk`'s dual Apache-2.0/MIT
once this is further along.
