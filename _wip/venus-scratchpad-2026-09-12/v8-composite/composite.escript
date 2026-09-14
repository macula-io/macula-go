#!/usr/bin/env escript
-define(PREFIX, <<"CompositeAlgorithmSignatures2025">>).
-define(LABEL, <<"MACULA-ML-DSA-87-PS384">>).
-define(REF, "436f6d706f73697465416c676f726974686d5369676e617475726573323032354d4143554c412d4d4c2d4453412d38372d505333383400e4f23edffade3a0a47087a2f675e84d4ed9c126f824e93c09ae81c09033b82d3ef4b9c62d5bbc6238b99df1bec305ed30456cd776dca2e8182ecc35e4c72b7f7").
-define(PSS, [{rsa_padding, rsa_pkcs1_pss_padding}, {rsa_pss_saltlen, 48}, {rsa_mgf1_md, sha384}]).

mprime(M, Label) -> <<?PREFIX/binary, Label/binary, 0:8, (crypto:hash(sha512, M))/binary>>.

verify(M, Pub, Sig) -> verify(M, Pub, Sig, ?LABEL).
verify(M, <<MLPub:2592/binary, Der/binary>>, <<MLSig:4627/binary, RSig/binary>>, Label) ->
    MP = mprime(M, Label),
    {'RSAPublicKey', N, E} = public_key:der_decode('RSAPublicKey', Der),
    A = crypto:verify(mldsa87, none, MP, MLSig, MLPub),
    B = crypto:verify(rsa, sha384, MP, RSig, [E, N], ?PSS),
    A andalso B;
verify(_, _, _, _) -> false.

check(true, What) -> io:format("  ok:   ~s~n", [What]);
check(false, What) -> io:format("  FAIL: ~s~n", [What]), halt(1).

main(["gen", Dir]) ->
    M = <<"macula-composite-vector">>,
    MP = mprime(M, ?LABEL),
    check(byte_size(MP) =:= 119, "M' is 119 bytes"),
    check(MP =:= binary:decode_hex(list_to_binary(?REF)), "M' matches Mercury's reference byte for byte"),
    {MLPub, MLPriv} = crypto:generate_key(mldsa87, []),
    {[E, N], RsaPriv} = crypto:generate_key(rsa, {4096, 65537}),
    MLSig = crypto:sign(mldsa87, none, MP, MLPriv),
    RSig = crypto:sign(rsa, sha384, MP, RsaPriv, ?PSS),
    Der = public_key:der_encode('RSAPublicKey', {'RSAPublicKey', binary:decode_unsigned(N), binary:decode_unsigned(E)}),
    check(byte_size(MLSig) =:= 4627, "ML-DSA-87 signature is 4,627 bytes"),
    check(byte_size(RSig) =:= 512, "RSA-PSS signature is 512 bytes"),
    check(byte_size(Der) =:= 526, "DER RSAPublicKey is 526 bytes"),
    Pub = <<MLPub/binary, Der/binary>>,
    Sig = <<MLSig/binary, RSig/binary>>,
    check(byte_size(Sig) =:= 5139, "composite signature is 5,139 bytes"),
    ok = file:write_file(filename:join(Dir, "message.bin"), M),
    ok = file:write_file(filename:join(Dir, "otp_composite_pub.bin"), Pub),
    ok = file:write_file(filename:join(Dir, "otp_composite_sig.bin"), Sig),
    check(verify(M, Pub, Sig), "OTP composite verifies in OTP"),
    <<X0, R0/binary>> = Sig,
    check(not verify(M, Pub, <<(X0 bxor 1), R0/binary>>), "altered ML-DSA half is refused"),
    <<P1:4627/binary, X1, R1/binary>> = Sig,
    check(not verify(M, Pub, <<P1/binary, (X1 bxor 1), R1/binary>>), "altered RSA-PSS half is refused"),
    check(not verify(M, Pub, Sig, <<"COMPSIG-MLDSA87-RSA4096-PSS-SHA512">>), "a different label is refused");
main(["verify", Dir, Who]) ->
    {ok, M} = file:read_file(filename:join(Dir, "message.bin")),
    {ok, Pub} = file:read_file(filename:join(Dir, Who ++ "_composite_pub.bin")),
    {ok, Sig} = file:read_file(filename:join(Dir, Who ++ "_composite_sig.bin")),
    check(verify(M, Pub, Sig), Who ++ " composite verifies in OTP").
