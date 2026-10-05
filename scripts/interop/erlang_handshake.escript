#!/usr/bin/env escript
%% The handshake across stacks, with macula's own macula_handshake. Two steps, around gohandshake:
%%
%%   escript erlang_handshake.escript challenge <ebin> <erlang_challenges.json>
%%       a macula station's CHALLENGE per profile, for macula-go to answer
%%   escript erlang_handshake.escript answer <ebin> <erlang_challenges.json> <go_handshake.json> <fixture.json>
%%       macula accepts macula-go's CONNECTs (and checks each member_endorsement arrives empty) and answers
%%       macula-go's CHALLENGEs; writes the fixture handshake/erlang_interop_test.go verifies
%%
%% Both steps run in version 4 and in version 5 (macula docs/design/DESIGN_NEIGHBOUR_CHANNEL_BINDING.md). Version 5 binds to
%% a TLS exporter, which a file cannot carry, so both stacks use the same stand-in: HMAC-SHA256 keyed by the session's
%% name over the label and the context, session "session_a". A proof over another context order, message or
%% capability encoding than macula's fails in the other stack. The challenge step keeps each station's throwaway key
%% in the work file, never in the fixture, so the answer step can sign the station's v5 session proof.
%%
%% Every step runs at macula's own test instant, so the fixture stays valid. MACULA_REVISION names macula in the
%% fixture's generator.
-mode(compile).

-define(NOW, 1789000000000).
-define(MINUTE, 60000).
-define(HOUR, 3600000).
-define(DAY, 86400000).
-define(LEAF, <<"a leaf certificate, as its listener presents it">>).
-define(CAPABILITIES, 5).

main(["challenge", Ebin, Out]) ->
    true = code:add_patha(Ebin),
    Entries = [challenge_entry(P) || P <- [pq_pure, pq_hybrid]],
    ok = file:write_file(Out, json:encode(#{<<"entries">> => Entries})),
    io:format("wrote ~b macula CHALLENGEs~n", [length(Entries)]),
    halt(0);
main(["answer", Ebin, ChallengesPath, GoPath, Out]) ->
    true = code:add_patha(Ebin),
    Challenges = entries(ChallengesPath),
    Go = entries(GoPath),
    Results = [answer(P, maps:get(P, Challenges), maps:get(P, Go)) || P <- [<<"pq_pure">>, <<"pq_hybrid">>]],
    Checks = lists:append([C || {C, _Entry} <- Results]),
    lists:foreach(fun({Name, Ok}) -> io:format("~s ~s~n", [verdict(Ok), Name]) end, Checks),
    Failed = [N || {N, false} <- Checks],
    io:format("handshake: ~b checks, ~b failed~n", [length(Checks), length(Failed)]),
    Fixture = #{<<"generator">> => iolist_to_binary(["macula_handshake at macula ", os:getenv("MACULA_REVISION", "unknown"),
                                                      ", OTP ", erlang:system_info(otp_release)]),
                <<"now">> => ?NOW, <<"leaf">> => binary:encode_hex(?LEAF, lowercase),
                <<"entries">> => [E || {_C, E} <- Results]},
    ok = file:write_file(Out, json:encode(Fixture)),
    halt(case Failed of [] -> 0; _ -> 1 end).

challenge_entry(Profile) ->
    {ok, StationId} = macula_node_keys:generate(identity, Profile),
    Public = macula_node_keys:public_key(StationId),
    Binding = macula_key_bindings:tls_binding(StationId, ?LEAF, ?NOW, ?NOW + 7 * ?DAY),
    Status = macula_key_bindings:status_statement(StationId, Binding, ?NOW, ?NOW + ?HOUR),
    Challenge = macula_handshake:challenge(#{profile => Profile, identity_key => Public,
                                             tls_binding => Binding, tls_status => Status}),
    #{<<"profile">> => atom_to_binary(Profile), <<"now">> => ?NOW, <<"leaf">> => hex(?LEAF),
      <<"challenge">> => hex(Challenge),
      <<"station_node_id">> => hex(macula_node_keys:node_id(Public, Profile)),
      <<"station_key">> => hex(term_to_binary(StationId))}.

answer(ProfileName, ErlangChallenge, Go) ->
    Profile = binary_to_existing_atom(ProfileName),
    Name = fun(What) -> iolist_to_binary([ProfileName, ": ", What]) end,
    Station = #{profile => Profile, challenge => unhex(maps:get(<<"challenge">>, ErlangChallenge)), leaf => ?LEAF,
                puzzle => #{difficulty => 0, mode => enforce}, capabilities => ?CAPABILITIES, now => ?NOW + ?MINUTE},
    Accepted = macula_handshake:accept_connect(unhex(maps:get(<<"connect">>, Go)), Station),
    StationKey = binary_to_term(unhex(maps:get(<<"station_key">>, ErlangChallenge))),
    StationV5 = Station#{export => stand_in(<<"session_a">>),
                         sign_session_proof => fun(_ClientNodeId, Message) ->
                                                   {ok, macula_node_keys:sign(Message, StationKey)}
                                               end},
    AcceptedV5 = macula_handshake:accept_connect(unhex(maps:get(<<"connect_v5">>, Go)), StationV5),
    {ErlangConnect, Answered} = answer_go_challenge(Profile, Go, #{}),
    {ErlangConnectV5, AnsweredV5} = answer_go_challenge(Profile, Go, #{version => 5, export => stand_in(<<"session_a">>)}),
    Checks = [{Name("macula accepts macula-go's CONNECT"), accepted(Accepted)},
              {Name("macula is handed an empty member_endorsement"), endorsement(Accepted) =:= <<>>},
              {Name("macula answers macula-go's CHALLENGE"), Answered},
              {Name("macula accepts macula-go's v5 CONNECT, in version 5"), version(AcceptedV5) =:= 5},
              {Name("macula answers macula-go's CHALLENGE in version 5"), AnsweredV5}],
    Entry = #{<<"profile">> => ProfileName,
              <<"erlang_challenge">> => maps:get(<<"challenge">>, ErlangChallenge),
              <<"erlang_station_node_id">> => maps:get(<<"station_node_id">>, ErlangChallenge),
              <<"go_challenge">> => maps:get(<<"challenge">>, Go),
              <<"erlang_connect">> => hex(ErlangConnect),
              <<"go_connect_v5">> => maps:get(<<"connect_v5">>, Go),
              <<"erlang_hello_v5">> => hex(hello(AcceptedV5)),
              <<"erlang_connect_v5">> => hex(ErlangConnectV5)},
    {Checks, Entry}.

%% The exporter stand-in both stacks use: the same session, label, context and length give the same bytes.
stand_in(Session) ->
    fun(Label, Context, Length) -> {ok, binary:part(crypto:mac(hmac, sha256, Session, [Label, Context]), 0, Length)} end.

version({accepted, #{version := Version}, _Hello}) -> Version;
version({refused, Reason, _Hello}) -> io:format("accept_connect v5 refused: ~p~n", [Reason]), refused.

hello({_Verdict, _ClientOrReason, Hello}) -> Hello.

answer_go_challenge(Profile, Go, V5) ->
    {ok, ClientId} = macula_node_keys:generate(identity, Profile),
    {ok, Connect} = macula_node_keys:generate(connect, Profile),
    ConnectPublic = macula_node_keys:public_key(Connect),
    Binding = macula_key_bindings:connect_binding(ClientId, ConnectPublic, ?NOW, ?NOW + ?DAY),
    Status = macula_key_bindings:status_statement(ClientId, Binding, ?NOW, ?NOW + ?HOUR),
    Session = #{profile => Profile, expected_node_id => unhex(maps:get(<<"station_node_id">>, Go)), leaf => ?LEAF,
                identity_key => macula_node_keys:public_key(ClientId), connect_key => Connect,
                connect_binding => Binding, connect_status => Status, capabilities => ?CAPABILITIES,
                now => ?NOW + ?MINUTE},
    case macula_handshake:answer_challenge(unhex(maps:get(<<"challenge">>, Go)), maps:merge(Session, V5)) of
        {ok, Connect1, _Station, _ExpectHello} -> {Connect1, true};
        {error, Reason} -> io:format("answer_challenge: ~p~n", [Reason]), {<<>>, false}
    end.

accepted({accepted, _Client, _Hello}) -> true;
accepted({refused, Reason, _Hello}) -> io:format("accept_connect refused: ~p~n", [Reason]), false.

endorsement({accepted, #{member_endorsement := E}, _Hello}) -> E;
endorsement(_) -> undefined.

entries(Path) ->
    {ok, Bin} = file:read_file(Path),
    #{<<"entries">> := Es} = json:decode(Bin),
    maps:from_list([{maps:get(<<"profile">>, E), E} || E <- Es]).

hex(B) -> binary:encode_hex(B, lowercase).
unhex(H) -> binary:decode_hex(H).

verdict(true) -> "ok  ";
verdict(false) -> "FAIL".
