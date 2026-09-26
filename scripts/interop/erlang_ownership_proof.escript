#!/usr/bin/env escript
%%! -noshell
%% Ownership proof v2 (mcl-om#7) across macula-go and mcl_om, with mcl_om's own
%% mcl_om_ownership_proof compiled from an mcl-om checkout.
%%
%%   escript erlang_ownership_proof.escript emit <macula ebin> <mcl-om src> <out dir>
%%   escript erlang_ownership_proof.escript verify <macula ebin> <mcl-om src> <go payload file>
%%
%% emit writes ownershipproof/testdata/vector: message/6's bytes for the inputs
%% ownershipproof_test.go names, with the identity of a pq_hybrid key made here,
%% its carried public key and its signature over the message.
%%
%% verify reads a payload goownershipproof signed, delivers it as a handler
%% receives it (a CALL frame through macula_frame encode, decode and
%% verify_request, then the station's caller merged in, as mcl-om's own tests
%% do), and verifies it with verify_asserted_by/3. The same payload with one
%% field changed must be refused as bad_signature, and the genuine one sent
%% again as replayed. Exits 1 otherwise.

-define(PROCEDURE, <<"mcl-graph/learn_link">>).
-define(TIMESTAMP, 1790000000000).
-define(MODULES, [mcl_om_wire, mcl_om_ownership_proof_replay, mcl_om_ownership_proof]).

main(["emit", Ebin, Src, OutDir]) ->
    setup(Ebin, Src),
    Key = node_key(),
    Identity = node_id(Key),
    Message = mcl_om_ownership_proof:message(Identity, realm(), ?PROCEDURE, ?TIMESTAMP, nonce(), fields()),
    Signature = macula_node_keys:sign(Message, Key),
    Public = macula_node_keys:public_key(Key),
    true = macula_node_keys:verify(Message, Signature, Public, profile()),
    ok = filelib:ensure_dir(filename:join(OutDir, "x")),
    [write(OutDir, Name, Bytes) || {Name, Bytes} <- [{"message.hex", Message}, {"identity.hex", Identity},
                                                     {"public_key.hex", Public}, {"signature.hex", Signature}]],
    io:format("emitted: message ~b bytes, public key ~b, signature ~b~n",
              [byte_size(Message), byte_size(Public), byte_size(Signature)]);
main(["verify", Ebin, Src, File]) ->
    setup(Ebin, Src),
    {ok, Raw} = file:read_file(File),
    [PayloadHex, RealmHex, Procedure | _] = binary:split(Raw, <<"\n">>, [global, trim_all]),
    Realm = binary:decode_hex(RealmHex),
    {ok, Decoded} = macula_record_cbor:decode_strict(binary:decode_hex(PayloadHex)),
    Payload = peer_value(Decoded),
    {ok, _} = mcl_om_ownership_proof_replay:start_link(),
    Check = fun(P) -> mcl_om_ownership_proof:verify_asserted_by(delivered(P, Realm, Procedure), Procedure, Realm) end,
    Genuine = Check(Payload),
    Tampered = Check(Payload#{{text, <<"weight">>} => 4}),
    Replayed = Check(Payload),
    io:format("go-signed: ~p; one field changed: ~p; the same proof again: ~p~n", [Genuine, Tampered, Replayed]),
    case {Genuine, Tampered, Replayed} of
        {ok, {error, bad_signature}, {error, replayed}} -> ok;
        _ -> halt(1)
    end;
main(_) ->
    io:format(standard_error, "usage: erlang_ownership_proof.escript emit|verify <macula ebin> <mcl-om src> <file or dir>~n", []),
    halt(2).

%% macula's modules, and mcl_om's three proof modules compiled from source.
setup(Ebin, Src) ->
    true = code:add_patha(Ebin),
    [load(Src, M) || M <- ?MODULES],
    ok = application:set_env(macula, crypto_profile, pq_hybrid).

load(Src, Module) ->
    Path = filename:join(Src, atom_to_list(Module) ++ ".erl"),
    {ok, Module, Beam} = compile:file(Path, [binary, report_errors]),
    {module, Module} = code:load_binary(Module, Path, Beam).

realm() -> crypto:hash(sha256, <<"io.macula">>).
nonce() -> list_to_binary(lists:seq(0, 15)).

%% Every CBOR type a payload carries, in the canonical form message/6 takes.
%% A text key named caller is a signed field like any other: only the
%% station's atom caller is stripped.
fields() ->
    #{{text, <<"subject">>} => {text, <<"entity:alpha">>},
      {text, <<"predicate">>} => {text, <<"knows">>},
      {text, <<"object">>} => {text, <<"entity:beta">>},
      {text, <<"confidence">>} => 0.75,
      {text, <<"weight">>} => 3,
      {text, <<"offset">>} => -7,
      {text, <<"digest">>} => <<1, 2, 3>>,
      {text, <<"note">>} => null,
      {text, <<"tags">>} => [{text, <<"a">>}, {text, <<"b">>}],
      {text, <<"metadata">>} => #{{text, <<"source">>} => {text, <<"field-notes">>},
                                  {text, <<"page">>} => 12},
      {text, <<"caller">>} => {text, <<"a text key named caller is signed">>}}.

profile() ->
    {ok, P} = macula_crypto_profile:configured(),
    P.

node_key() ->
    {ok, K} = macula_node_keys:generate(identity, profile(), #{puzzle_difficulty => 0}),
    K.

node_id(Key) ->
    {ok, Id} = macula_node_keys:node_id(Key),
    Id.

write(Dir, Name, Bytes) ->
    ok = file:write_file(filename:join(Dir, Name), [binary:encode_hex(Bytes, lowercase), $\n]).

%% macula_frame's peer_value/1: null reads as undefined, nothing else changes.
peer_value(null) -> undefined;
peer_value(List) when is_list(List) -> [peer_value(E) || E <- List];
peer_value(Map) when is_map(Map) -> maps:map(fun(_K, V) -> peer_value(V) end, Map);
peer_value(Other) -> Other.

delivered(Payload, Realm, Procedure) ->
    Spec = #{request_id => crypto:strong_rand_bytes(16),
             realm => Realm,
             procedure => Procedure,
             target => node_id(node_key()),
             deadline => erlang:system_time(millisecond) + 60_000,
             payload => Payload},
    Frame = macula_frame:call(Spec, node_key()),
    {ok, Decoded, <<>>} = macula_frame:decode(macula_frame:encode(Frame)),
    {ok, #{payload := Delivered, caller := CallerId}} = macula_frame:verify_request(Decoded, profile()),
    Delivered#{caller => CallerId}.
