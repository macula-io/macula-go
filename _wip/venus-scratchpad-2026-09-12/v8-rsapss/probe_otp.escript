#!/usr/bin/env escript
main(_) ->
    io:format("OTP ~s, ~p~n", [erlang:system_info(otp_release), crypto:info_lib()]),
    T0 = erlang:monotonic_time(millisecond),
    {Pub, Priv} = crypto:generate_key(rsa, {4096, 65537}),
    io:format("RSA-4096 keygen ~p ms; public key = ~p terms (~p), private key = ~p terms~n",
              [erlang:monotonic_time(millisecond) - T0, length(Pub),
               [is_binary(X) || X <- Pub], length(Priv)]),
    [E, N | _] = Pub,
    io:format("E = ~p, N = ~p bits~n", [binary:decode_unsigned(E), bit_size(N)]),
    Msg = <<"probe message, not the vector">>,
    Opts = [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, 48}, {rsa_mgf1_md, sha384}],
    Sig = crypto:sign(rsa, sha384, Msg, Priv, Opts),
    Ok = crypto:verify(rsa, sha384, Msg, Sig, Pub, Opts),
    io:format("RSA-PSS SHA-384, MGF1-SHA-384, salt 48: verify=~p, signature ~p bytes~n", [Ok, byte_size(Sig)]),
    WrongSalt = crypto:verify(rsa, sha384, Msg, Sig, Pub,
                              [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, 32}, {rsa_mgf1_md, sha384}]),
    io:format("  same signature checked with salt 32 (must be false): ~p~n", [WrongSalt]),
    WrongMgf = crypto:verify(rsa, sha384, Msg, Sig, Pub,
                             [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, 48}, {rsa_mgf1_md, sha256}]),
    io:format("  same signature checked with MGF1-SHA-256 (must be false): ~p~n", [WrongMgf]),
    {MP, MS} = crypto:generate_key(mldsa87, []),
    MSig = crypto:sign(mldsa87, none, <<"M-prime">>, MS),
    io:format("ML-DSA-87, empty context: verify=~p~n", [crypto:verify(mldsa87, none, <<"M-prime">>, MSig, MP)]),
    Ctx = try crypto:sign(mldsa87, none, <<"x">>, MS, [{context, <<"label">>}]) of
              _ -> "accepted a {context, _} option"
          catch C:Er -> io_lib:format("refused a {context, _} option: ~p:~P", [C, Er, 5])
          end,
    io:format("ML-DSA-87 with a context string: ~s~n", [Ctx]).
