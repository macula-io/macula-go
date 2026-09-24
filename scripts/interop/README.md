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

`emit_erlang_composite.escript` writes a `pq_hybrid` composite that macula's `macula_node_keys` signed into
`identity/testdata/lamps_mldsa87_rsa4096_pss_sha512/` (`otp_message.bin`, `otp_pk.bin`, `otp_sig.bin`), for
`identity/node_key_test.go` to verify:

```sh
escript scripts/interop/emit_erlang_composite.escript <macula lib dir>/ebin identity/testdata/lamps_mldsa87_rsa4096_pss_sha512
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
