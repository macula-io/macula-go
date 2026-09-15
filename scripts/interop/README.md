# Interop with macula's Erlang modules

These scripts check macula-go's post-quantum identity against a compiled macula, in both directions.

- macula's `macula_node_keys` checks node keys made by macula-go. It checks the carried form, the signature and the
  node_id or key id, and it refuses altered signature halves.
- macula's `macula_key_bindings` checks TLS and CONNECT bindings and status statements made by macula-go. Each must
  verify and be refused wherever macula refuses it. A copy with one byte of its tbs or signature changed must be
  refused as a signature that does not verify.
- macula writes bindings and statements of its own, and `identity/binding_interop_test.go` verifies them, including
  altered copies.

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
