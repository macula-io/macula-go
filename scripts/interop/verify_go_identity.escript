#!/usr/bin/env escript
%% Checks node-key artifacts made by macula-go with macula's own macula_node_keys: the carried form, the signature,
%% its refusal when altered, and the node_id and key id.
%%
%%   escript verify_go_identity.escript <ebin with macula's modules> <go_identity_artifacts.json>
-mode(compile).

main([Ebin, Path]) ->
    true = code:add_patha(Ebin),
    {ok, Bin} = file:read_file(Path),
    Results = lists:flatmap(fun checks/1, json:decode(Bin)),
    lists:foreach(fun({Name, Passed}) -> io:format("~s ~s~n", [verdict(Passed), Name]) end, Results),
    Failed = [Name || {Name, false} <- Results],
    io:format("identity: ~b checks, ~b failed~n", [length(Results), length(Failed)]),
    halt(exit_status(Failed)).

checks(#{<<"profile">> := ProfileName, <<"purpose">> := Purpose, <<"key">> := KeyHex, <<"message">> := MessageHex,
         <<"signature">> := SignatureHex, <<"key_id">> := KeyIdHex} = Artifact) ->
    Profile = profile(ProfileName),
    Key = binary:decode_hex(KeyHex),
    Message = binary:decode_hex(MessageHex),
    Signature = binary:decode_hex(SignatureHex),
    Name = fun(What) -> iolist_to_binary([ProfileName, " ", Purpose, " key: ", What]) end,
    [{Name("the carried key is well formed"), macula_node_keys:carried_key_well_formed(Key, Profile)},
     {Name("the signature verifies"), macula_node_keys:verify(Message, Signature, Key, Profile)},
     {Name("the signature does not verify for another message"),
      not macula_node_keys:verify(<<Message/binary, 0>>, Signature, Key, Profile)},
     {Name("an altered ML-DSA-87 half is refused"),
      not macula_node_keys:verify(Message, flip(Signature, 10), Key, Profile)},
     {Name("the key id matches"), binary:decode_hex(KeyIdHex) =:= expected_key_id(Purpose, Key, Profile)}]
    ++ node_id_checks(Artifact, Name, Key, Profile)
    ++ hybrid_checks(Profile, Name, Message, Signature, Key).

node_id_checks(#{<<"node_id">> := NodeIdHex}, Name, Key, Profile) ->
    [{Name("the node_id matches"), binary:decode_hex(NodeIdHex) =:= macula_node_keys:node_id(Key, Profile)}];
node_id_checks(_Artifact, _Name, _Key, _Profile) ->
    [].

hybrid_checks(pq_hybrid, Name, Message, Signature, Key) ->
    [{Name("an altered RSA-PSS half is refused"),
      not macula_node_keys:verify(Message, flip(Signature, 4627 + 10), Key, pq_hybrid)},
     {Name("the composite is refused under pq_pure"), not macula_node_keys:verify(Message, Signature, Key, pq_pure)}];
hybrid_checks(pq_pure, _Name, _Message, _Signature, _Key) ->
    [].

expected_key_id(<<"identity">>, Key, Profile) -> macula_node_keys:node_id(Key, Profile);
expected_key_id(_OtherPurpose, Key, Profile) -> macula_node_keys:key_id(Key, Profile).

profile(<<"pq_pure">>) -> pq_pure;
profile(<<"pq_hybrid">>) -> pq_hybrid.

flip(Bin, Offset) ->
    <<Head:Offset/binary, Byte, Tail/binary>> = Bin,
    <<Head/binary, (Byte bxor 1), Tail/binary>>.

verdict(true) -> "ok  ";
verdict(false) -> "FAIL".

exit_status([]) -> 0;
exit_status(_Failed) -> 1.
