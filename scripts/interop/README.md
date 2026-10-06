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
  `handshake/erlang_interop_test.go` checks in every `go test`. The same runs in handshake version 5 (macula 13.2.0):
  macula accepts macula-go's v5 CONNECT and answers macula-go's CHALLENGE in version 5, and macula-go accepts
  macula's v5 CONNECT and verifies the session proof in macula's v5 HELLO. A file cannot carry a TLS exporter, so both
  stacks use one stand-in (HMAC-SHA256 keyed by the session's name over the label and the context): a proof message,
  exporter context order or capability encoding that differs between the stacks fails there. The station's throwaway
  key stays in the run's work file, never in the fixture.

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

`copy_ucan_vectors.sh` copies macula's UCAN vectors (`test/vectors/ucan_v1.json`, `UCAN_V1.md`) to `ucan/testdata`,
which `ucan/vectors_test.go` holds macula-go to: every verdict `macula_ucan:authorize/3` reaches, in both profiles. The
reverse: `goucan` mints tokens with macula-go, and `erlang_ucan.escript` authorizes them with `macula_ucan`:

```sh
scripts/interop/copy_ucan_vectors.sh <macula checkout> [git ref, origin/main by default]
go run ./scripts/interop/goucan > go_ucans.json
escript scripts/interop/erlang_ucan.escript <macula lib dir> go_ucans.json
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

## Handshake v5 on real TLS sessions

`v5.sh` runs a bare macula station (`erlang_v5_station.escript`: `macula_peering` on a loopback listener, in the
macula CI image) and dials it with `gov5link`, macula-go's `stationlink`. Each side derives E from its own TLS
exporter (quinn's, Go's `crypto/tls`), so a label, context order or exporter that differs fails the handshake. The
station probes the link with `liveness_ping` every 500 ms for the hold, so the link must answer. It passes when the
link is v5 on SecP384r1MLKEM1024 and not resumed, and every connection that ended did so after the client's GOODBYE.
The group is the station's rustls choice from the client's offer, so this is where macula-go is held to the group a
real station negotiates:

```sh
MACULA_BUILD=<compiled macula checkout, 13.2.0 or later> scripts/interop/v5.sh pq_hybrid
```

The other direction, macula's client to macula-go's station, is `sealed.sh`: its `teststation` answers v5.
`CI_RUNNER_CGROUP_PARENT` puts the station's container in that cgroup.

## Against a live station

`golivelink` dials one running macula 12 station with `stationlink` and reports the handshake (time, TLS group, suite,
leaf), a `_macula.ping`, `_dht.*` finds and a put of its own signed node record, and a publication heard back as an
event. With `-serve` it then serves `golivelink/echo` under a throwaway test realm, whose org directory and delegation it
signs and puts in the station's DHT, and calls it every `-every` for `-serve` from a second node's `pool`, by direct
dial. Before the calls it serves and opens two streams the same way: `golivelink/watch`, a server stream of three chunks,
and `golivelink/count`, a client stream the provider answers with a reply. Its throwaway realm is named
(`golivelink-<hex>`, its id the name's SHA-256), so it also serves `golivelink/gated` and `golivelink/gated_watch`
gated on a fresh root node, and checks the provider's answers through the station: no token `unauthorized`, the root's
grant served, and a proof no token names `malformed_frame`, for a call and an open alike:

```sh
go run ./scripts/interop/golivelink -host 127.0.0.1 -port 44330 -profile pq_hybrid -node <station node_id, 64 hex>
go run ./scripts/interop/golivelink ... -hold 0s -serve 90s -every 15s
```

Point it only at a station you run for the purpose: it puts records in the station's DHT.

`transport`'s `TestDialTargetSettlesOnSecP384r1MLKEM1024WithALiveStation` dials a live station's TLS alone, puts
nothing, and fails unless it settles on SecP384r1MLKEM1024 (skipped unless `MACULA_GO_LIVE_STATION` is set):

```sh
MACULA_GO_LIVE_STATION=<host>:<port> go test -run LiveStation -v ./transport
```

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


## Sealed calls and streams (macula 13, E2E seal scheme 1)

`sealed.sh` runs macula-go's test station and, through it, both directions in
one profile: an Erlang macula 13 provider (`erlang_sealed.escript serve`,
`kem_advertise` on, a call and a server stream in its own namespace, both
`confidential => required`, their advertisements published for direct dial)
called and streamed to by `gosealed call`, sealed to the key its advertisement
names, and then called in the clear from a station link to it as an explicit
target (the pool itself refuses `ConfidentialOff`), which it must refuse
`sealed_required`; then a Go provider (`gosealed serve`, `KEMAdvertise`, both
procedures `ConfidentialRequired`, a handler that refuses anything that did
not arrive sealed) called and streamed to by `erlang_sealed.escript call` as
macula's direct dial does, and called in the clear at its station
(`call_station/8`, `confidential => off`), which it must refuse. The Erlang side
runs in macula's pinned CI image with the host's network.

```sh
MACULA_BUILD=<macula checkout at v13.x, compiled> scripts/interop/sealed.sh pq_hybrid
MACULA_BUILD=<macula checkout at v13.x, compiled> scripts/interop/sealed.sh pq_pure
```

`MACULA_BUILD` may also be a rebar3 project that depends on macula from hex
(`{deps, [{macula, "13.0.1"}]}`), compiled in the same image: the script
reads `_build/default/lib/macula` and its dependencies beside it.

The Erlang caller also calls with `confidential => off` by direct dial.
macula 13.0.0 seals that call anyway (it honours `off` only on an explicit
target), where macula-go's pool refuses it; macula 13.0.1 refuses it too, as
`{error, {confidentiality, off_needs_explicit_target}}`. With
`MACULA_OFF_REFUSED=1` the script requires exactly that refusal.

Last run (2026-09-27, `macula-ci-otp@sha256:aff1d39b...`):

- macula 13.0.1 from hex (tag v13.0.1 = 92137b94), compiled as a rebar3
  dependency, with `MACULA_OFF_REFUSED=1`: both profiles, both ways,
  `sealed call` and `sealed stream` answered, `clear call` refused
  `sealed_required`, `off by direct dial` refused
  `off_needs_explicit_target`, exit 0.
- macula v13.0.0: the same, except `off by direct dial` sealed (exit 1 under
  `MACULA_OFF_REFUSED=1`, as it must be).

CI runs the Go leg on every PR and master push, and on a `v*` tag before the release
is published (`.github/workflows/sealed-interop.yml`): macula from hex at the version
above, compiled in the same image, both profiles, `MACULA_OFF_REFUSED=1`. The tag's
release carries the log as `sealed-interop-<tag>.log`. Move the workflow's
`MACULA_VERSION` together with the version recorded here.

### The TypeScript leg (`SEALED_PEER=ts`)

`SEALED_PEER=ts` runs the same two directions with @macula-io/ts in place of
macula-go: `tssealed` (TypeScript over macula-go's shared library, from npm at
the version `tssealed/package-lock.json` pins; needs node and npm), with
`MACULA_SEALED_PEER=ts` telling `erlang_sealed.escript` whose texts to expect.

```sh
SEALED_PEER=ts MACULA_BUILD=<compiled macula v13.x> MACULA_OFF_REFUSED=1 scripts/interop/sealed.sh pq_hybrid
SEALED_PEER=ts MACULA_BUILD=<compiled macula v13.x> MACULA_OFF_REFUSED=1 scripts/interop/sealed.sh pq_pure
```

**Not covered by the TypeScript caller:** `gosealed call` also calls the
Erlang provider in the clear as an explicit target and expects
`sealed_required`. @macula-io/ts has no API for an explicit-target clear call,
so `tssealed call` checks instead that `confidential: "off"` is refused
(`invalid_argument`). A provider's `sealed_required` refusal is still checked in
the other direction: `erlang_sealed.escript call` makes its `call_station/8`
clear call against `tssealed serve`.

Since @macula-io/ts 0.25.0 (macula-go v0.19.0) `tssealed call` also takes the
caller's seal report of the call (`callReport`) and of the stream
(`Stream.report()`, after the provider's first chunk) and requires each to say
`sealed` 1, the Erlang provider's node id and a 16-hex key id; both are printed.

`PODMAN_CPUS`, when set, caps the Erlang container (`podman --cpus`); unset,
the Go runs are as before.

Last run (2026-09-28, `macula-ci-otp@sha256:aff1d39b...`, @macula-io/ts 0.24.0
on macula-go v0.18.0's shared library):

- macula 13.0.1 from hex, compiled as a rebar3 dependency, with
  `MACULA_OFF_REFUSED=1`: both profiles, both ways. A TypeScript caller:
  `sealed call` and `sealed stream` answered by the Erlang provider, `off`
  refused `invalid_argument`. A TypeScript provider: `sealed call` and `sealed
  stream` answered, `clear call` refused `sealed_required`, `off by direct
  dial` refused `off_needs_explicit_target`. Exit 0.
