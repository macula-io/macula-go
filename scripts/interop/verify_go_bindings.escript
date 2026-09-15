#!/usr/bin/env escript
%% Checks TLS and CONNECT bindings and status statements made by macula-go with macula's own macula_key_bindings:
%% each verifies, each is refused where macula refuses it, and a copy with one byte of its tbs or its signature
%% changed is refused as a signature that does not verify.
%%
%%   escript verify_go_bindings.escript <ebin with macula's modules> <go_binding_artifacts.json>
-mode(compile).

-define(MINUTE, 60000).
-define(DAY, 86400000).
-define(MLDSA_SIGNATURE_SIZE, 4627).

main([Ebin, Path]) ->
    true = code:add_patha(Ebin),
    {ok, Bin} = file:read_file(Path),
    Results = lists:flatmap(fun checks/1, json:decode(Bin)),
    lists:foreach(fun({Name, Passed}) -> io:format("~s ~s~n", [verdict(Passed), Name]) end, Results),
    Failed = [Name || {Name, false} <- Results],
    io:format("bindings: ~b checks, ~b failed~n", [length(Results), length(Failed)]),
    halt(exit_status(Failed)).

checks(#{<<"profile">> := ProfileName, <<"now_ms">> := Now, <<"identity_key">> := IdentityHex,
         <<"node_id">> := NodeIdHex, <<"leaf">> := LeafHex, <<"tls_binding">> := Tls, <<"tls_status">> := TlsStatus,
         <<"connect_key">> := ConnectHex, <<"connect_binding">> := Connect, <<"connect_status">> := ConnectStatus}) ->
    Made = #{profile => profile(ProfileName),
             now => Now,
             identity => binary:decode_hex(IdentityHex),
             leaf => binary:decode_hex(LeafHex),
             connect_key => binary:decode_hex(ConnectHex),
             tls => envelope(Tls),
             tls_status => envelope(TlsStatus),
             connect => envelope(Connect),
             connect_status => envelope(ConnectStatus)},
    Name = fun(What) -> iolist_to_binary([ProfileName, ": ", What]) end,
    as_made_checks(Made, binary:decode_hex(NodeIdHex), Name) ++ altered_checks(Made, Name).

as_made_checks(#{profile := Profile, now := Now, identity := Identity, leaf := Leaf, connect_key := ConnectKey,
                 tls := TlsEnvelope, tls_status := TlsStatus, connect := ConnectEnvelope,
                 connect_status := ConnectStatus}, NodeId, Name) ->
    TlsResult = macula_key_bindings:verify_tls_binding(TlsEnvelope, Identity, Profile, Leaf, Now),
    [{Name("the node_id is the one macula derives"), NodeId =:= macula_node_keys:node_id(Identity, Profile)},
     {Name("the TLS binding verifies, for that node_id"),
      TlsResult =:= {ok, #{use => tls, node_id => macula_node_keys:node_id(Identity, Profile),
                           not_after => Now + 7 * ?DAY}}},
     {Name("the TLS status verifies"),
      is_ok(macula_key_bindings:verify_status(TlsStatus, TlsEnvelope, Identity, Profile, Now))},
     {Name("the CONNECT binding verifies"),
      is_ok(macula_key_bindings:verify_connect_binding(ConnectEnvelope, Identity, Profile, ConnectKey, Now))},
     {Name("the CONNECT status verifies"),
      is_ok(macula_key_bindings:verify_status(ConnectStatus, ConnectEnvelope, Identity, Profile, Now))},
     {Name("the TLS binding is refused for another leaf"),
      refused(binding_key_mismatch,
              macula_key_bindings:verify_tls_binding(TlsEnvelope, Identity, Profile, <<Leaf/binary, 0>>, Now))},
     {Name("the CONNECT binding is refused as a TLS binding"),
      refused(binding_signature_invalid,
              macula_key_bindings:verify_tls_binding(ConnectEnvelope, Identity, Profile, ConnectKey, Now))},
     {Name("the TLS status is refused for the CONNECT binding"),
      refused(status_binding_mismatch,
              macula_key_bindings:verify_status(TlsStatus, ConnectEnvelope, Identity, Profile, Now))},
     {Name("the TLS binding is refused 7 days and 6 minutes on"),
      refused(binding_expired,
              macula_key_bindings:verify_tls_binding(TlsEnvelope, Identity, Profile, Leaf, Now + 7 * ?DAY + 6 * ?MINUTE))},
     {Name("the TLS status is refused an hour and 6 minutes on"),
      refused(status_expired,
              macula_key_bindings:verify_status(TlsStatus, TlsEnvelope, Identity, Profile, Now + 66 * ?MINUTE))}].

%% Every binding and statement with one tbs byte changed, and with one signature byte changed in each half the
%% profile signs with, is refused as a signature that does not verify.
altered_checks(#{profile := Profile} = Made, Name) ->
    lists:flatmap(fun({What, Alter}) -> altered_checks(Made, Name, What, Alter) end, alterations(Profile)).

altered_checks(#{profile := Profile, now := Now, identity := Identity, leaf := Leaf, connect_key := ConnectKey,
                 tls := Tls, tls_status := TlsStatus, connect := Connect, connect_status := ConnectStatus},
               Name, What, Alter) ->
    [{Name(["the TLS binding with ", What, " is refused"]),
      refused(binding_signature_invalid,
              macula_key_bindings:verify_tls_binding(Alter(Tls), Identity, Profile, Leaf, Now))},
     {Name(["the CONNECT binding with ", What, " is refused"]),
      refused(binding_signature_invalid,
              macula_key_bindings:verify_connect_binding(Alter(Connect), Identity, Profile, ConnectKey, Now))},
     {Name(["the TLS status with ", What, " is refused"]),
      refused(status_signature_invalid,
              macula_key_bindings:verify_status(Alter(TlsStatus), Tls, Identity, Profile, Now))},
     {Name(["the CONNECT status with ", What, " is refused"]),
      refused(status_signature_invalid,
              macula_key_bindings:verify_status(Alter(ConnectStatus), Connect, Identity, Profile, Now))}].

alterations(Profile) ->
    [{"a changed tbs byte", fun(#{tbs := Tbs} = E) -> E#{tbs := flip(Tbs, byte_size(Tbs) div 2)} end}
     | [{["a changed signature byte at ", integer_to_list(Offset)],
         fun(#{signature := Signature} = E) -> E#{signature := flip(Signature, Offset)} end}
        || Offset <- signature_offsets(Profile)]].

signature_offsets(pq_pure) -> [10];
signature_offsets(pq_hybrid) -> [10, ?MLDSA_SIGNATURE_SIZE + 10].

envelope(#{<<"tbs">> := Tbs, <<"signature">> := Signature}) ->
    #{tbs => binary:decode_hex(Tbs), signature => binary:decode_hex(Signature)}.

flip(Bin, Offset) ->
    <<Head:Offset/binary, Byte, Tail/binary>> = Bin,
    <<Head/binary, (Byte bxor 1), Tail/binary>>.

is_ok({ok, _}) -> true;
is_ok(_Other) -> false.

refused(Reason, {error, Reason}) -> true;
refused(_Reason, _Other) -> false.

profile(<<"pq_pure">>) -> pq_pure;
profile(<<"pq_hybrid">>) -> pq_hybrid.

verdict(true) -> "ok  ";
verdict(false) -> "FAIL".

exit_status([]) -> 0;
exit_status(_Failed) -> 1.
