#!/usr/bin/env escript
main([Dir]) ->
    Msg = <<"macula V8 hybrid signature test vector v1">>,
    ok = file:write_file(filename:join(Dir, "message.bin"), Msg),
    %% Brainpool ECDSA: standard OTP API
    try
        {BPub, BPriv} = crypto:generate_key(ecdh, brainpoolP384r1),
        BSig = crypto:sign(ecdsa, sha384, Msg, [BPriv, brainpoolP384r1]),
        true = crypto:verify(ecdsa, sha384, Msg, BSig, [BPub, brainpoolP384r1]),
        ok = file:write_file(filename:join(Dir, "bp384_pub_uncompressed.bin"), BPub),
        ok = file:write_file(filename:join(Dir, "bp384_sig_der.bin"), BSig),
        io:format("brainpoolP384r1 ECDSA/SHA-384: OK pub=~pB sig=~pB (DER)~n", [byte_size(BPub), byte_size(BSig)])
    catch C1:E1 -> io:format("brainpoolP384r1 FAILED: ~p:~p~n", [C1, E1])
    end,
    %% ML-DSA-87: try the plausible API shapes, report which one works
    Variants = [
        {"generate_key(mldsa87,[]) / sign(mldsa87,none,M,Priv)",
         fun() -> {P,S} = crypto:generate_key(mldsa87, []), {P, S, fun(M) -> crypto:sign(mldsa87, none, M, S) end, fun(M,G) -> crypto:verify(mldsa87, none, M, G, P) end} end},
        {"generate_key(mldsa,mldsa87) / sign(mldsa,none,M,[Priv,mldsa87])",
         fun() -> {P,S} = crypto:generate_key(mldsa, mldsa87), {P, S, fun(M) -> crypto:sign(mldsa, none, M, [S, mldsa87]) end, fun(M,G) -> crypto:verify(mldsa, none, M, G, [P, mldsa87]) end} end},
        {"generate_key(mldsa87,undefined) / sign(mldsa87,none,M,Priv)",
         fun() -> {P,S} = crypto:generate_key(mldsa87, undefined), {P, S, fun(M) -> crypto:sign(mldsa87, none, M, S) end, fun(M,G) -> crypto:verify(mldsa87, none, M, G, P) end} end}
    ],
    try_variants(Variants, Msg, Dir).

try_variants([], _, _) -> io:format("ML-DSA-87: no variant worked~n");
try_variants([{Name, F} | Rest], Msg, Dir) ->
    try
        {P, S, Sign, Verify} = F(),
        Sig = Sign(Msg),
        true = Verify(Msg, Sig),
        ok = file:write_file(filename:join(Dir, "mldsa87_pub.bin"), P),
        ok = file:write_file(filename:join(Dir, "mldsa87_sig.bin"), Sig),
        io:format("ML-DSA-87 OK via ~s: pub=~pB priv=~pB sig=~pB~n",
                  [Name, byte_size(P), size_of(S), byte_size(Sig)])
    catch C:E ->
        io:format("  variant failed: ~s -> ~p:~P~n", [Name, C, E, 6]),
        try_variants(Rest, Msg, Dir)
    end.

size_of(B) when is_binary(B) -> byte_size(B);
size_of(T) -> T.
