#!/usr/bin/env escript
%% macula's side of the live handshake v5 check (scripts/interop/v5.sh): a bare macula station (macula_peering on a
%% loopback macula_quic listener, with its statement issuer) that accepts connections, probes each with liveness_ping
%% every 500 ms, prints "station <host> <port> <node_id hex>" once listening, then after <hold s> the handshake
%% counters and a verdict: PASS when at least one client connected on v5, none on v4, and every connection that ended
%% did so gracefully (drained, after the client's GOODBYE): one closed for any other reason, a missed liveness_pong
%% (peer_liveness_lost), a malformed or wrongly signed frame, fails.
%%
%%   escript erlang_v5_station.escript <macula lib dir> <profile> <hold s>
-mode(compile).

main([Lib, ProfileName, HoldS]) ->
    [true = code:add_patha(Dir) || Dir <- filelib:wildcard(filename:join([Lib, "..", "*", "ebin"]))],
    Profile = list_to_atom(ProfileName),
    ok = application:load(macula),
    ok = application:set_env(macula, crypto_profile, Profile),
    {ok, _} = application:ensure_all_started(macula),
    {ok, Identity} = macula_node_keys:generate(identity, Profile),
    {ok, TlsKey} = macula_node_keys:generate(tls, Profile),
    {ok, {CertPem, KeyPem}} = macula_quic:generate_self_signed_cert(crypto:strong_rand_bytes(32),
                                                                     [<<"localhost">>, <<"127.0.0.1">>]),
    Dir = filename:join("/tmp", "macula-v5-station-" ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_path(Dir),
    Cert = filename:join(Dir, "station.crt"),
    Key = filename:join(Dir, "station.key"),
    ok = file:write_file(Cert, CertPem),
    ok = file:write_file(Key, KeyPem),
    [{'Certificate', Der, not_encrypted}] = public_key:pem_decode(CertPem),
    {ok, Issuer} = macula_statement_issuer:start_link(#{identity => fun() -> Identity end, owner => self(),
                                                        clock => fun() -> erlang:system_time(millisecond) end}),
    ok = macula_statement_issuer:register_tls_leaf(Issuer, Der, TlsKey),
    Port = free_port(),
    {ok, Listener} = macula_quic:listen(<<"127.0.0.1">>, Port, [{cert, Cert}, {key, Key}, {alpn, [<<"macula">>]},
                                                                  {idle_timeout_ms, 30000},
                                                                  {keep_alive_interval_ms, 5000}]),
    ok = macula_quic:async_accept(Listener),
    {ok, NodeId} = macula_node_keys:node_id(Identity),
    io:format("station 127.0.0.1 ~b ~s~n", [Port, binary:encode_hex(NodeId, lowercase)]),
    Opts = #{identity => Identity, issuer => Issuer, capabilities => 1, controlling_pid => self(),
             puzzle => #{mode => off}, liveness_interval_ms => 500, liveness_max_misses => 2},
    Ended = serve(Opts, erlang:monotonic_time(millisecond) + list_to_integer(HoldS) * 1000, []),
    Counters = macula_peering:handshake_counters(),
    io:format("counters: ~0p~n", [Counters]),
    [io:format("ended: ~0p~n", [E]) || E <- Ended],
    Pass = maps:get(v5_connections, Counters) >= 1 andalso maps:get(v4_connections, Counters) =:= 0
           andalso lists:all(fun(Reason) -> Reason =:= drained end, Ended),
    io:format("verdict: ~s~n", [verdict(Pass)]),
    halt(exit_code(Pass)).

serve(Opts, Until, Ended) ->
    Left = max(0, Until - erlang:monotonic_time(millisecond)),
    receive
        {quic, new_conn, Conn, _Info} ->
            {ok, _Pid} = macula_peering:accept(Conn, Opts),
            serve(Opts, Until, Ended);
        {macula_peering, connected, _Pid, ClientId} ->
            io:format("connected ~s~n", [binary:encode_hex(ClientId, lowercase)]),
            serve(Opts, Until, Ended);
        {macula_peering, disconnected, _Pid, Reason} ->
            serve(Opts, Until, [Reason | Ended]);
        _Other ->
            serve(Opts, Until, Ended)
    after Left ->
        lists:reverse(Ended)
    end.

free_port() ->
    {ok, S} = gen_udp:open(0, [binary, {ip, {127, 0, 0, 1}}]),
    {ok, P} = inet:port(S),
    ok = gen_udp:close(S),
    P.

verdict(true) -> "PASS";
verdict(false) -> "FAIL".

exit_code(true) -> 0;
exit_code(false) -> 1.
