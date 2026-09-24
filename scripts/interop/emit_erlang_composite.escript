#!/usr/bin/env escript
%% Writes a pq_hybrid composite signed by macula's own macula_node_keys, for macula-go's tests to verify:
%% otp_message.bin, otp_pk.bin (the key as carried) and otp_sig.bin, into <out dir>. The key is fresh each run;
%% macula verifies its own signature before anything is written.
%%
%%   escript emit_erlang_composite.escript <ebin with macula's modules> <out dir>
-mode(compile).

main([Ebin, OutDir]) ->
    true = code:add_patha(Ebin),
    Message = <<"macula-go interop: a composite macula signed">>,
    {ok, Key} = macula_node_keys:generate(identity, pq_hybrid),
    Public = macula_node_keys:public_key(Key),
    Signature = macula_node_keys:sign(Message, Key),
    true = macula_node_keys:verify(Message, Signature, Public, pq_hybrid),
    ok = file:write_file(filename:join(OutDir, "otp_message.bin"), Message),
    ok = file:write_file(filename:join(OutDir, "otp_pk.bin"), Public),
    ok = file:write_file(filename:join(OutDir, "otp_sig.bin"), Signature),
    io:format("wrote a pq_hybrid composite: key ~b bytes, signature ~b bytes~n", [byte_size(Public), byte_size(Signature)]),
    halt(0).
