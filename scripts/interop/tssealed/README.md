# tssealed

@macula-io/ts's side of `scripts/interop/sealed.sh` (`SEALED_PEER=ts`): the
TypeScript twin of `gosealed`, over macula-go's shared library from npm at the
version `package-lock.json` pins.

- `serve`: a pool with `kemAdvertise: 1` serves `~<self>/vault` (a call) and
  `~<self>/watch` (a server stream), both `confidential: "required"`; a handler
  that sees a request with `sealed` 0 refuses it.
- `call`: calls `~<provider>/vault` and opens `~<provider>/watch` with
  `confidential: "required"`, expecting the Erlang provider's texts, then checks
  that `confidential: "off"` is refused (`invalid_argument`). It takes the
  caller's seal report of the call and of the stream (@macula-io/ts 0.25.0) and
  requires each to say `sealed` 1, the provider called and a 16-hex key id.

**Not covered here:** `gosealed call` also calls the provider in the clear as an
explicit target and expects `sealed_required`. @macula-io/ts has no API for an
explicit-target clear call, so the TypeScript caller cannot make that check. The
provider's `sealed_required` refusal is still checked in the other direction, by
`erlang_sealed.escript`'s `call_station/8` clear call against `tssealed serve`.
