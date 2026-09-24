#!/usr/bin/env escript
%% Writes manifests macula's macula_manifest builds, for macula-go's manifest
%% package to check byte for byte: each case's MCID, root hash, chunk hashes
%% and chunk MCIDs, and the manifest's deterministic CBOR as a CALL payload
%% carries it (created fixed, so the bytes are stable).
%%
%%   escript scripts/interop/emit_erlang_manifest.escript <macula lib dir> manifest/testdata/erlang_manifests.json
main([Lib, Out]) ->
    [true = code:add_patha(filename:join([Lib, "..", App, "ebin"])) || App <- ["macula", "gproc", "telemetry"]],
    true = code:add_patha(filename:join(Lib, "ebin")),
    Cases = [manifest_case(<<"blob">>, pattern(600000), 262144),
             manifest_case(<<"odd">>, pattern(2500), 1000),
             manifest_case(<<"exact">>, pattern(3000), 1000),
             manifest_case(<<"empty">>, <<>>, 262144),
             manifest_case(<<"naïve"/utf8>>, pattern(10), 4)],
    Block = <<"hello, macula">>,
    Json = ["{\"manifests\":[", lists:join(",", Cases), "],",
            "\"block\":{\"data_hex\":\"", hex(Block), "\",\"mcid_hex\":\"",
            hex(<<2, 16#55, (crypto:hash(sha384, Block))/binary>>), "\"}}\n"],
    ok = file:write_file(Out, Json),
    io:format("wrote ~s~n", [Out]).

pattern(N) -> << <<(I rem 251)>> || I <- lists:seq(0, N - 1) >>.

manifest_case(Name, Data, ChunkSize) ->
    {ok, M0, _Chunks} = macula_manifest:create(Data, #{name => Name, chunk_size => ChunkSize}),
    M = M0#{created => 1789000000},
    #{mcid := Mcid, root_hash := Root, chunks := Chunks} = M,
    ChunkMcids = [begin {ok, C} = macula_manifest:chunk_mcid(M, I), hex(C) end
                  || I <- lists:seq(0, length(Chunks) - 1)],
    Wire = macula_cbor_nif:pack_deterministic(to_wire(M)),
    ["{\"name\":\"", hex(Name), "\",\"size\":", integer_to_list(byte_size(Data)),
     ",\"chunk_size\":", integer_to_list(ChunkSize),
     ",\"mcid_hex\":\"", hex(Mcid), "\",\"root_hex\":\"", hex(Root), "\",",
     "\"chunk_hashes\":[", lists:join(",", [["\"", hex(H), "\""] || #{hash := H} <- Chunks]), "],",
     "\"chunk_mcids\":[", lists:join(",", [["\"", C, "\""] || C <- ChunkMcids]), "],",
     "\"wire_hex\":\"", hex(Wire), "\"}"].

%% As macula_frame:to_wire/1 puts a payload on the wire: atoms and keys as
%% text, binaries as byte strings.
to_wire(M) when is_map(M) -> maps:fold(fun(K, V, Acc) -> Acc#{{text, atom_to_binary(K)} => to_wire(V)} end, #{}, M);
to_wire(L) when is_list(L) -> [to_wire(E) || E <- L];
to_wire(A) when is_atom(A) -> {text, atom_to_binary(A)};
to_wire(V) -> V.

hex(B) -> binary_to_list(binary:encode_hex(B, lowercase)).
