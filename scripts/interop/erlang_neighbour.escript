#!/usr/bin/env escript
%% Neighbour-signed control frames across stacks, with macula's own macula_frame (D17).
%%
%%   escript erlang_neighbour.escript emit <ebin> <fixture.json>
%%       macula builds and neighbour-signs a client link's control frames (ADVERTISE, UNADVERTISE, SUBSCRIBE,
%%       UNSUBSCRIBE, GOODBYE) in pq_hybrid, and builds them unsigned in pq_pure, for frame/neighbour_interop_test.go
%%   escript erlang_neighbour.escript verify <ebin> <go_neighbour.json>
%%       macula decodes and verifies the frames macula-go signed (scripts/interop/goneighbour)
-mode(compile).

main(["emit", Ebin, Out]) ->
    true = code:add_patha(Ebin),
    Entries = [emit(P) || P <- [pq_hybrid, pq_pure]],
    ok = file:write_file(Out, json:encode(#{<<"generator">> => <<"macula_frame at macula v12.1.0, OTP 28">>,
                                             <<"entries">> => Entries})),
    io:format("wrote neighbour frames for ~b profiles~n", [length(Entries)]),
    halt(0);
main(["verify", Ebin, Path]) ->
    true = code:add_patha(Ebin),
    {ok, Bin} = file:read_file(Path),
    #{<<"entries">> := Entries} = json:decode(Bin),
    Checks = lists:append([verify(E) || E <- Entries]),
    lists:foreach(fun({Name, Ok}) -> io:format("~s ~s~n", [verdict(Ok), Name]) end, Checks),
    Failed = [N || {N, false} <- Checks],
    io:format("neighbour: ~b checks, ~b failed~n", [length(Checks), length(Failed)]),
    halt(case Failed of [] -> 0; _ -> 1 end).

frames() ->
    Realm = binary:copy(<<3>>, 32),
    Subscriber = binary:copy(<<1>>, 32),
    [macula_frame:advertise(#{advertisement => <<"a signed procedure_advertisement record">>}),
     macula_frame:unadvertise(#{withdrawal => <<"a signed withdrawal record">>}),
     macula_frame:subscribe(#{topic => <<"io.macula/mcl-news/news/wire/news_item_reported_v1">>, realm => Realm,
                              subscriber => Subscriber}),
     macula_frame:unsubscribe(#{topic => <<"io.macula/mcl-news/news/wire/news_item_reported_v1">>, realm => Realm,
                                subscriber => Subscriber}),
     macula_frame:goodbye(normal, <<"closing">>)].

emit(Profile) ->
    {ok, Key} = macula_node_keys:generate(identity, Profile),
    Connection = crypto:strong_rand_bytes(48),
    Frames = [begin
                  Signed = neighbour(macula_frame:neighbour_signed(Profile, maps:get(frame_type, F)), F, Key,
                                     Connection, Seq),
                  #{<<"frame_type">> => atom_to_binary(maps:get(frame_type, F)), <<"seq">> => Seq,
                    <<"bytes">> => hex(macula_frame:encode(Signed))}
              end || {Seq, F} <- lists:enumerate(0, frames())],
    #{<<"profile">> => atom_to_binary(Profile), <<"peer_key">> => hex(macula_node_keys:public_key(Key)),
      <<"connection">> => hex(Connection), <<"frames">> => Frames}.

%% pq_pure sends control frames as they are; only pq_hybrid neighbour-signs (D17).
neighbour(true, Frame, Key, Connection, Seq) ->
    macula_frame:sign_neighbour(Frame, Key, #{connection => Connection, seq => Seq});
neighbour(false, Frame, _Key, _Connection, _Seq) ->
    Frame.

verify(#{<<"profile">> := ProfileName, <<"peer_key">> := PeerKey, <<"connection">> := Connection,
         <<"frames">> := Frames}) ->
    Profile = binary_to_existing_atom(ProfileName),
    [begin
         Name = iolist_to_binary([ProfileName, " ", Type, " seq ", integer_to_binary(Seq)]),
         Opts = #{profile => Profile, peer_key => unhex(PeerKey), connection => unhex(Connection), seq => Seq},
         {Name, verified(macula_frame:decode(unhex(Bytes)), Opts, Type)}
     end || #{<<"frame_type">> := Type, <<"seq">> := Seq, <<"bytes">> := Bytes} <- Frames]
    ++ [{iolist_to_binary([ProfileName, " a frame read at the wrong seq is refused"]),
         wrong_seq_refused(Profile, PeerKey, Connection, hd(Frames))}].

verified({ok, Frame, <<>>}, Opts, Type) ->
    case macula_frame:verify_neighbour(Frame, Opts) of
        {ok, #{frame_type := T}} -> atom_to_binary(T) =:= Type;
        Other -> io:format("verify_neighbour: ~p~n", [Other]), false
    end;
verified(Other, _Opts, _Type) ->
    io:format("decode: ~p~n", [Other]), false.

wrong_seq_refused(pq_pure, _PeerKey, _Connection, _Frame) ->
    true;
wrong_seq_refused(Profile, PeerKey, Connection, #{<<"seq">> := Seq, <<"bytes">> := Bytes}) ->
    {ok, Frame, <<>>} = macula_frame:decode(unhex(Bytes)),
    Opts = #{profile => Profile, peer_key => unhex(PeerKey), connection => unhex(Connection), seq => Seq + 1},
    macula_frame:verify_neighbour(Frame, Opts) =:= {error, malformed_frame}.

hex(B) -> binary:encode_hex(B, lowercase).
unhex(H) -> binary:decode_hex(H).

verdict(true) -> "ok  ";
verdict(false) -> "FAIL".
