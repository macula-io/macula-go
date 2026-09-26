# Interop with macula's Erlang modules

These scripts check macula-go's post-quantum identity against a compiled macula, in both directions.

- macula's `macula_node_keys` checks node keys made by macula-go. It checks the carried form, the signature and the
  node_id or key id, and it refuses altered signature halves.
- macula's `macula_key_bindings` checks TLS and CONNECT bindings and status statements made by macula-go. Each must
  verify and be refused wherever macula refuses it. A copy with one byte of its tbs or signature changed must be
  refused as a signature that does not verify.
- macula writes bindings and statements of its own, and `identity/binding_interop_test.go` verifies them, including
  altered copies.

- macula's `macula_handshake` accepts the CONNECT macula-go sends to a macula CHALLENGE, is handed its empty
  `member_endorsement`, and answers a CHALLENGE macula-go made (`erlang_handshake.escript` around
  `gohandshake`). The frames macula made go to `handshake/testdata/erlang_handshake.json`, which
  `handshake/erlang_interop_test.go` checks in every `go test`.

- macula's `macula_frame` verifies the control frames a client link sends (ADVERTISE, UNADVERTISE, SUBSCRIBE,
  UNSUBSCRIBE, GOODBYE) as macula-go neighbour-signs them in `pq_hybrid` and sends them in `pq_pure`, and refuses one
  read at the wrong seq (`goneighbour` into `erlang_neighbour.escript verify`). macula's own frames go to
  `frame/testdata/erlang_neighbour.json` for `frame/neighbour_test.go`.

`emit_erlang_composite.escript` writes a `pq_hybrid` composite that macula's `macula_node_keys` signed into
`identity/testdata/lamps_mldsa87_rsa4096_pss_sha512/` (`otp_message.bin`, `otp_pk.bin`, `otp_sig.bin`), for
`identity/node_key_test.go` to verify:

```sh
escript scripts/interop/emit_erlang_composite.escript <macula lib dir>/ebin identity/testdata/lamps_mldsa87_rsa4096_pss_sha512
```

`emit_erlang_manifest.escript` writes manifests macula's `macula_manifest` builds (their MCIDs, root and chunk hashes,
and deterministic CBOR as a CALL payload carries them) to `manifest/testdata/erlang_manifests.json`, which
`manifest/erlang_manifest_test.go` checks byte for byte in every `go test`:

```sh
escript scripts/interop/emit_erlang_manifest.escript <macula lib dir> manifest/testdata/erlang_manifests.json
```

`gocontent` and `erlang_content.escript` share and fetch node-served content (macula 12.6.0, D27) through one
station, each side sharing the same byte pattern, so either checks the other's content by its SHA-384. Share on one
side, fetch its MCID on the other, then fetch again after it is unshared (`not_shared`). `gocontent -pad-chunk` shares
as a dishonest sharer would, so macula's fetcher can be seen refusing it (`block_size_mismatch`):

```sh
go run ./scripts/interop/gocontent -host <host> -port <port> -node <station node_id> -realm <realm hex> -share 600000 -hold 1m
escript scripts/interop/erlang_content.escript <macula lib dir> <host> <port> <station node_id> <realm hex> fetch <mcid hex>
```

`copy_own_namespace_fixtures.sh` copies macula's own-namespace fixtures (signed advertisements under
`~<node_id>/<name>`, and the verdicts `macula_record` reaches on them) to `record/testdata/own_namespace`, which
`record/own_namespace_fixtures_test.go` holds macula-go to in every `go test`:

```sh
scripts/interop/copy_own_namespace_fixtures.sh <macula checkout> [git ref, origin/main by default]
```

`godevicerequest` proves `devicerequest` against a live realm with a fresh key that is never saved: a v2 join session
over HTTP (201), the same request with its device_info changed after signing (401 bad_proof), and, with `-station`, a
membership UCAN over the mesh naming the fresh node:

```sh
go run ./scripts/interop/godevicerequest -realm-key <file of the realm key in hex> -station host:port@<node id hex>
```

`copy_e2e_seal_vectors.sh` copies macula's E2E seal scheme 1 vectors and their spec
(`test/vectors/e2e_seal_v1.json`, `E2E_SEAL_V1.md`) to `seal/testdata`, which `seal/vectors_test.go` holds
macula-go to in every `go test`, both sides of the key agreement byte for byte:

```sh
scripts/interop/copy_e2e_seal_vectors.sh <macula checkout> [git ref, origin/main by default]
```

## Running

Compile macula at the revision to check, then point the script at the compiled application:

```sh
(cd <macula checkout> && rebar3 compile)
scripts/interop/run.sh <macula checkout>/_build/default/lib/macula [fixtures file]
```

The script needs Go and OTP 28's `erl` and `escript` on the PATH. It loads macula's modules and NIFs as compiled,
since macula's strict decoder reads its element budget from `macula_cbor_nif`. It prints one line per check, and exits
non-zero when any check fails.

To refresh the test data, give it `identity/testdata/erlang_bindings.json` as the fixtures file.

## Against a live station

`golivelink` dials one running macula 12 station with `stationlink` and reports the handshake (time, TLS group, suite,
leaf), a `_macula.ping`, `_dht.*` finds and a put of its own signed node record, and a publication heard back as an
event. With `-serve` it then serves `golivelink/echo` under a throwaway test realm, whose org directory and delegation it
signs and puts in the station's DHT, and calls it every `-every` for `-serve` from a second node's `pool`, by direct
dial. Before the calls it serves and opens two streams the same way: `golivelink/watch`, a server stream of three chunks,
and `golivelink/count`, a client stream the provider answers with a reply:

```sh
go run ./scripts/interop/golivelink -host 127.0.0.1 -port 44330 -profile pq_hybrid -node <station node_id, 64 hex>
go run ./scripts/interop/golivelink ... -hold 0s -serve 90s -every 15s
```

Point it only at a station you run for the purpose: it puts records in the station's DHT.

`goownershipproof` and `erlang_ownership_proof.escript` check ownership proof v2 (mcl-om#7) against mcl_om's own
`mcl_om_ownership_proof`, compiled from an mcl-om checkout. `emit` writes `ownershipproof/testdata/vector` (the
message mcl_om builds, and a signature an Erlang key made over it), which `ownershipproof/ownershipproof_test.go`
checks in every `go test`. `verify` delivers a payload macula-go signed through macula's frame codec and the station link's caller step
(`macula_station_link:with_caller/2`), as a handler receives it, and needs mcl_om to accept it once, refuse it with
one field changed, and refuse it sent again. The proof carries the time it was signed, so run `verify` within 60 s
of `goownershipproof`:

```sh
go run ./scripts/interop/goownershipproof /tmp/go_payload.txt
escript scripts/interop/erlang_ownership_proof.escript verify <macula lib dir>/ebin <mcl-om checkout>/src /tmp/go_payload.txt
escript scripts/interop/erlang_ownership_proof.escript emit <macula lib dir>/ebin <mcl-om checkout>/src ownershipproof/testdata/vector
```

