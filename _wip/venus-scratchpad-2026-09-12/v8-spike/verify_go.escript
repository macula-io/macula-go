#!/usr/bin/env escript
main([Vec, Out]) ->
    {ok, Msg} = file:read_file(filename:join(Vec, "message.bin")),
    {ok, BPub} = file:read_file(filename:join(Out, "go_bp384_pub.bin")),
    {ok, BSig} = file:read_file(filename:join(Out, "go_bp384_sig_der.bin")),
    B = crypto:verify(ecdsa, sha384, Msg, BSig, [BPub, brainpoolP384r1]),
    io:format("  Go brainpool signature verifies in OTP: ~p~n", [B]),
    {ok, MPub} = file:read_file(filename:join(Out, "go_mldsa87_pub.bin")),
    {ok, MSig} = file:read_file(filename:join(Out, "go_mldsa87_sig.bin")),
    M = crypto:verify(mldsa87, none, Msg, MSig, MPub),
    io:format("  Go ML-DSA-87 signature verifies in OTP: ~p~n", [M]),
    case B andalso M of true -> halt(0); false -> halt(1) end.
