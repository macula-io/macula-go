#!/usr/bin/env escript
%% Writes TLS and CONNECT bindings and status statements made by macula's own macula_key_bindings, for macula-go to
%% verify. Times are fixed, so the file can live as test data.
%%
%%   escript emit_erlang_bindings.escript <ebin with macula's modules> <fixtures file> <macula revision>
-mode(compile).

-define(NOW, 1789000000000).
-define(HOUR, 3600000).
-define(DAY, 86400000).
-define(LEAF, <<"a leaf certificate, as its listener presents it">>).

main([Ebin, OutPath, Revision]) ->
    true = code:add_patha(Ebin),
    Doc = #{<<"generator">> => iolist_to_binary(["macula_key_bindings and macula_node_keys at macula ", Revision,
                                                 ", OTP ", erlang:system_info(otp_release)]),
            <<"entries">> => [made(Profile) || Profile <- [pq_pure, pq_hybrid]]},
    ok = filelib:ensure_dir(OutPath),
    ok = file:write_file(OutPath, [json:format(Doc), $\n]),
    io:format("wrote ~s~n", [OutPath]).

made(Profile) ->
    {ok, Identity} = macula_node_keys:generate(identity, Profile),
    {ok, Connect} = macula_node_keys:generate(connect, Profile),
    {ok, NodeId} = macula_node_keys:node_id(Identity),
    ConnectPublic = macula_node_keys:public_key(Connect),
    Tls = macula_key_bindings:tls_binding(Identity, ?LEAF, ?NOW, ?NOW + 7 * ?DAY),
    ConnectBinding = macula_key_bindings:connect_binding(Identity, ConnectPublic, ?NOW, ?NOW + 7 * ?DAY),
    #{<<"profile">> => atom_to_binary(Profile),
      <<"now_ms">> => ?NOW,
      <<"identity_key">> => hex(macula_node_keys:public_key(Identity)),
      <<"node_id">> => hex(NodeId),
      <<"leaf">> => hex(?LEAF),
      <<"tls_binding">> => envelope(Tls),
      <<"tls_status">> => envelope(macula_key_bindings:status_statement(Identity, Tls, ?NOW, ?NOW + ?HOUR)),
      <<"connect_key">> => hex(ConnectPublic),
      <<"connect_binding">> => envelope(ConnectBinding),
      <<"connect_status">> =>
          envelope(macula_key_bindings:status_statement(Identity, ConnectBinding, ?NOW, ?NOW + ?HOUR))}.

envelope(#{tbs := Tbs, signature := Signature}) ->
    #{<<"tbs">> => hex(Tbs), <<"signature">> => hex(Signature)}.

hex(Bin) ->
    binary:encode_hex(Bin, lowercase).
