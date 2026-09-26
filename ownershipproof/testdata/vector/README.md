# Ownership proof v2 vector

Written by `scripts/interop/erlang_ownership_proof.escript emit`, which compiles
mcl_om 0.32.0's `mcl_om_ownership_proof` (mcl-om `91e59d87b1966e0cf33578a3437dcc11e3f0621c`)
and runs it on macula 12.11.1, OTP 28.4.3, in
`ghcr.io/macula-io/macula-ci-otp:20260923-1352@sha256:aff1d39bc4aa29d13044b90b38e9b7f4b757d50818cc11c5bb7e84cdbf82ac70`.

| File | What it is |
|------|------------|
| `message.hex` | `mcl_om_ownership_proof:message/6` for the inputs `ownershipproof_test.go` names (realm sha256("io.macula"), procedure `mcl-graph/learn_link`, timestamp 1790000000000, nonce 00..0f, and fields of every CBOR type), with the identity below |
| `identity.hex` | the node_id of a pq_hybrid key made for the run |
| `public_key.hex` | that key's carried public key (3,118 bytes) |
| `signature.hex` | its composite signature over `message.hex` (5,139 bytes) |

The other direction is `goownershipproof` into `erlang_ownership_proof.escript verify`:
mcl_om verifies a payload macula-go signed, delivered through macula's frame codec,
and refuses it with one field changed (`bad_signature`) and sent twice (`replayed`).
