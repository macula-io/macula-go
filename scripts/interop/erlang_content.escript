#!/usr/bin/env escript
%% Shares or fetches node-served content (macula 12.6.0, D27) through one
%% station, as macula's own sharer and fetcher do, for the cross-check against
%% macula-go's pool (scripts/interop/gocontent).
%%
%%   escript erlang_content.escript <macula lib dir> <host> <port> <station node_id hex> <realm hex> share <bytes> <hold s> <after s>
%%   escript erlang_content.escript <macula lib dir> <host> <port> <station node_id hex> <realm hex> fetch <mcid hex>
%%
%% Shared bytes are the pattern I rem 251, the same as gocontent's. The node
%% identity is a fresh throwaway in a temporary directory, never the
%% operator's.
main([Lib, Host, Port, Station, Realm | Command]) ->
    [true = code:add_patha(Dir) || Dir <- filelib:wildcard(filename:join([Lib, "..", "*", "ebin"]))],
    Tmp = string:trim(os:cmd("mktemp -d")),
    ok = application:load(macula),
    ok = application:set_env(macula, crypto_profile, pq_hybrid),
    ok = application:set_env(macula, node_identity_path, filename:join(Tmp, "node_identity")),
    {ok, _} = application:ensure_all_started(macula),
    {ok, Pool} = macula:connect([#{host => list_to_binary(Host), port => list_to_integer(Port),
                                   expected_node_id => binary:decode_hex(list_to_binary(Station))}], #{}),
    up(Pool, 100),
    R = binary:decode_hex(list_to_binary(Realm)),
    run(Pool, R, Command),
    os:cmd("rm -rf " ++ Tmp),
    halt(0).

up(_Pool, 0) -> io:format("no link came up~n"), halt(1);
up(Pool, N) -> healthy(macula:status(Pool), Pool, N).

healthy({ok, #{healthy_links := Healthy, self_node_id := Self}}, _Pool, _N) when Healthy > 0 ->
    io:format("node ~s~n", [binary:encode_hex(Self, lowercase)]);
healthy(_NotYet, Pool, N) ->
    timer:sleep(100),
    up(Pool, N - 1).

run(Pool, Realm, ["share", Size, Hold, After]) ->
    Data = pattern(list_to_integer(Size)),
    T0 = erlang:monotonic_time(millisecond),
    {ok, Mcid} = macula:share_content(Pool, Realm, Data),
    io:format("shared ~s ~b bytes sha384 ~s in ~b ms~n",
              [binary:encode_hex(Mcid, lowercase), byte_size(Data), sum(Data), erlang:monotonic_time(millisecond) - T0]),
    timer:sleep(list_to_integer(Hold) * 1000),
    ok = macula:unshare_content(Pool, Realm, Mcid),
    io:format("unshared~n"),
    timer:sleep(list_to_integer(After) * 1000);
run(Pool, Realm, ["fetch", McidHex]) ->
    T0 = erlang:monotonic_time(millisecond),
    Answer = macula:get_content(Pool, Realm, binary:decode_hex(list_to_binary(McidHex))),
    Took = erlang:monotonic_time(millisecond) - T0,
    fetched(Answer, Took).

fetched({ok, Data}, Took) ->
    io:format("fetched ~b bytes sha384 ~s in ~b ms~n", [byte_size(Data), sum(Data), Took]);
fetched({error, Reason}, Took) ->
    io:format("error in ~b ms: ~p~n", [Took, Reason]).

pattern(N) -> << <<(I rem 251)>> || I <- lists:seq(0, N - 1) >>.

sum(Data) -> binary:encode_hex(crypto:hash(sha384, Data), lowercase).
