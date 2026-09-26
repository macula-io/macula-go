/*
 * macula.h: the C ABI over macula-go's macula 12 API, shared by every
 * binding that is not written in Go (.NET, Python, PHP, TypeScript).
 *
 * Built from macula-go's own module:
 *   go build -buildmode=c-shared  -o libmacula.so ./cabi   (or .dylib / .dll)
 *   go build -buildmode=c-archive -o libmacula.a  ./cabi
 *
 * This header is the contract; cabi/CONTRACT.md says what every call means.
 * cabi's tests fail if the exported functions and this header disagree.
 * A change to an existing declaration changes MACULA_ABI_VERSION; a new
 * function does not, and says since which macula-go version it exists.
 */
#ifndef MACULA_H
#define MACULA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MACULA_ABI_VERSION 1

/* An opaque handle to a Go value: a key, pool, subscription, served
 * procedure, pending call, stream, or cancel token. 0 is never a handle. */
typedef uintptr_t macula_handle;

/* Stream modes. */
#define MACULA_STREAM_SERVER 0
#define MACULA_STREAM_CLIENT 1
#define MACULA_STREAM_BIDI   2

/* ---- The library ------------------------------------------------------ */

/* MACULA_ABI_VERSION of the library loaded, to compare with this header's. */
int32_t macula_abi_version(void);

/* Free a string or byte buffer the library returned. NULL is a no-op. */
void macula_free_string(char *s);
void macula_free_bytes(uint8_t *b);

/* ---- Cancellation ------------------------------------------------------ */

/* A cancel token. Pass it to any number of blocking calls (0 = none);
 * macula_cancel ends every one of them that is still running with the error
 * kind "cancelled", and every later call given it at once. It is safe from
 * any thread, any number of times. Free it once no call uses it any more;
 * a call already running holds what it needs, so freeing early is safe. */
macula_handle macula_cancel_new(void);
void macula_cancel(macula_handle cancel);
void macula_cancel_free(macula_handle cancel);

/* ---- Node keys --------------------------------------------------------- */

/* profile is "pq_hybrid" or "pq_pure"; NULL is "pq_hybrid". */
macula_handle macula_key_generate(const char *profile, macula_handle cancel, char **err_out);
macula_handle macula_key_load(const char *path, const char *profile, char **err_out);
/* Load the key at path, or generate one and save it there (owner-only). */
macula_handle macula_key_load_or_create(const char *path, const char *profile, macula_handle cancel, char **err_out);
void macula_key_save(macula_handle key, const char *path, char **err_out);
void macula_key_node_id(macula_handle key, uint8_t out_node_id[32], char **err_out);
uint8_t *macula_key_public_key(macula_handle key, size_t *out_len, char **err_out);
char *macula_key_profile(macula_handle key, char **err_out);
uint8_t *macula_key_sign(macula_handle key, const uint8_t *data, size_t data_len, size_t *out_len, char **err_out);
/* 1 when signature is valid over data for public_key (as carried), else 0. */
int32_t macula_verify(const uint8_t *data, size_t data_len, const uint8_t *signature, size_t signature_len,
                      const uint8_t *public_key, size_t public_key_len, const char *profile, char **err_out);
void macula_key_free(macula_handle key);

/* ---- Device request proofs (realm proof v2, macula-realm#29) ----------- */
/* Since macula-go v0.14.0. */

#define MACULA_REQUEST_HTTP 0 /* an HTTP body, under the realm's JSON rule */
#define MACULA_REQUEST_MESH 1 /* a mesh payload, as it goes on the wire */

/* A v2 proof that key made request_json (a JSON object, its "proof" left
 * out) for procedure in realm, now, with a fresh nonce:
 * {"v":2,"timestamp","nonce","signature"}. A request with a "caller" field is
 * invalid_argument (since macula-go v0.17.0): the caller is the signer. */
char *macula_key_device_request_proof(macula_handle key, const uint8_t realm[32], const char *procedure,
                                      const char *request_json, int32_t rule, char **err_out);
/* The exact bytes such a proof signs, for a given timestamp and nonce: what a
 * binding checks the realm's vector with. */
uint8_t *macula_device_request_message(const uint8_t *public_key, size_t public_key_len, const uint8_t realm[32],
                                       const char *procedure, int64_t timestamp_ms, const uint8_t nonce[16],
                                       const char *request_json, int32_t rule, size_t *out_len, char **err_out);

/* ---- Ownership proofs (v2, mcl-om#7) ----------------------------------- */
/* Since macula-go v0.16.0. */

/* payload_json (a JSON object) with an "asserted_by" block by which key's
 * node authorises its other fields for procedure in realm, now, with a fresh
 * nonce; an asserted_by already there is replaced. A payload carrying
 * "caller" is refused (invalid_argument): a station replaces it with the
 * caller it authenticated. Send the result as the payload. */
char *macula_key_ownership_proof(macula_handle key, const uint8_t realm[32], const char *procedure,
                                 const char *payload_json, char **err_out);
/* The exact bytes such a proof signs, for a given identity (node_id),
 * timestamp and nonce, over fields_json: a payload, of which the fields are
 * all but "asserted_by" and a text "caller", as a verifier reads a delivered
 * payload. Unlike macula_key_ownership_proof it does not refuse a "caller":
 * it mirrors the verifier, not the signer. What a binding checks mcl_om's
 * vector with. */
uint8_t *macula_ownership_proof_message(const uint8_t identity[32], const uint8_t realm[32], const char *procedure,
                                        int64_t timestamp_ms, const uint8_t nonce[16], const char *fields_json,
                                        size_t *out_len, char **err_out);

/* ---- UCANs (macula 12, D7) --------------------------------------------- */
/* Since macula-go v0.17.0. */

/* key's token for the node audience_node_id, granting caps_json (a JSON array
 * of {"with","can"}, each "with" an MRI) until exp_s (Unix seconds).
 * options_json (NULL for none): {"nbf","nnc","fct","prf"}, prf a list of at
 * most one parent's proof id. key is an identity key. */
char *macula_ucan_create(macula_handle key, const uint8_t audience_node_id[32], const char *caps_json, int64_t exp_s,
                         const char *options_json, char **err_out);
/* The proof id a child's "prf" names a token by: lowercase hex SHA-384 of its
 * text. */
char *macula_ucan_proof_id(const char *token, char **err_out);

/* ---- Pool -------------------------------------------------------------- */

/* seeds_json: [{"host","port","node_id"}]. options_json (NULL for defaults):
 * {"realm_trust": {"<realm hex>": "<realm key hex>"}, "replication_factor",
 * "max_seeds", "max_direct_links", "respawn_delay_ms", "timeout_ms",
 * "kem_advertise"}. kem_advertise (0 or 1, since macula-go v0.18.0) names
 * this node's KEM key in its confidential procedures' advertisements: enable
 * it only once every station runs macula 12.11 or later. */
macula_handle macula_pool_connect(macula_handle key, const char *seeds_json, const char *options_json,
                                  macula_handle cancel, char **err_out);
/* Closes every link, subscription and served procedure; frees the handle. */
void macula_pool_close(macula_handle pool);
void macula_pool_node_id(macula_handle pool, uint8_t out_node_id[32], char **err_out);
/* [{"station","host","port","direct","up"}] */
char *macula_pool_status(macula_handle pool, char **err_out);
/* The pool's next event: {"kind":"link","station","direct","up","error"} or
 * {"kind":"issuer_error","error"}; see "Inboxes" in CONTRACT.md. */
char *macula_pool_events_next(macula_handle pool, int64_t timeout_ms, macula_handle cancel, int32_t *closed,
                              char **err_out);

/* ---- Calls ------------------------------------------------------------- */

/* provider_node_id NULL: any provider the realm trusts. Returns the result. */
char *macula_pool_call(macula_handle pool, const uint8_t realm[32], const char *procedure, const char *payload_json,
                       const uint8_t *provider_node_id, int64_t timeout_ms, macula_handle cancel, char **err_out);
/* macula_pool_call presenting a UCAN (NULL: none) and its chain's proofs,
 * proofs_json a JSON array of tokens (NULL: none). A gated provider that
 * refuses it answers a provider error of code "unauthorized", or
 * "malformed_frame" for a proof no token in the chain names. Since macula-go
 * v0.17.0. */
char *macula_pool_call_with(macula_handle pool, const uint8_t realm[32], const char *procedure,
                            const char *payload_json, const uint8_t *provider_node_id, const char *ucan,
                            const char *proofs_json, int64_t timeout_ms, macula_handle cancel, char **err_out);
/* A call with its options as JSON (NULL for none): {"provider": "<node_id
 * hex>", "ucan", "proofs": [...], "confidential": "preferred"|"required"|"off"}.
 * A call that cannot be kept confidential fails with the kind
 * "confidentiality". Since macula-go v0.18.0. */
char *macula_pool_call_opts(macula_handle pool, const uint8_t realm[32], const char *procedure, const char *payload_json,
                            const char *options_json, int64_t timeout_ms, macula_handle cancel, char **err_out);
/* [{"node","station"}], freshest first. */
char *macula_pool_providers(macula_handle pool, const uint8_t realm[32], const char *procedure, int64_t timeout_ms,
                            macula_handle cancel, char **err_out);

/* ---- Publish / subscribe ----------------------------------------------- */

/* ttl_ms 0: the default (10 minutes). */
void macula_pool_publish(macula_handle pool, const uint8_t realm[32], const char *topic, const char *payload_json,
                         int64_t ttl_ms, char **err_out);
macula_handle macula_pool_subscribe(macula_handle pool, const uint8_t realm[32], const char *topic, char **err_out);
/* {"publisher","realm","topic","seq","published_at","payload","delivered_via"} */
char *macula_subscription_next(macula_handle subscription, int64_t timeout_ms, macula_handle cancel,
                               int32_t *closed, char **err_out);
/* Events the pool dropped because the inbox was full. */
uint64_t macula_subscription_dropped(macula_handle subscription, char **err_out);
void macula_subscription_stop(macula_handle subscription);

/* ---- Serving ----------------------------------------------------------- */

/* procedure is "~<own node_id hex>/<name>" (the node's own namespace) or
 * "<org>/<name>" under an org that delegated it to this node. */
macula_handle macula_pool_serve(macula_handle pool, const uint8_t realm[32], const char *procedure, char **err_out);
macula_handle macula_pool_serve_stream(macula_handle pool, const uint8_t realm[32], const char *procedure,
                                       int32_t mode, char **err_out);
/* Serve a procedure only to callers whose UCAN policy_json accepts:
 * {"kind":"ucan_required","issuer":"<node_id hex>"} (a chain rooted at that
 * node's identity key) or {"kind":"realm_member_required","key_id":"<hex>",
 * "can"} (rooted at that realm key, granting that can). Refused calls and
 * opens never reach the inbox. Since macula-go v0.17.0. */
macula_handle macula_pool_serve_gated(macula_handle pool, const uint8_t realm[32], const char *procedure,
                                      const char *policy_json, char **err_out);
macula_handle macula_pool_serve_stream_gated(macula_handle pool, const uint8_t realm[32], const char *procedure,
                                             int32_t mode, const char *policy_json, char **err_out);
/* Serve with options as JSON (NULL for none): {"policy": <a policy_json>,
 * "confidential": "preferred"|"required"|"off"}. Since macula-go v0.18.0. */
macula_handle macula_pool_serve_opts(macula_handle pool, const uint8_t realm[32], const char *procedure,
                                     const char *options_json, char **err_out);
macula_handle macula_pool_serve_stream_opts(macula_handle pool, const uint8_t realm[32], const char *procedure,
                                            int32_t mode, const char *options_json, char **err_out);
/* The next call (*out_item: a pending call) or stream session (*out_item: a
 * stream), and its request {"caller","realm","procedure","payload","deadline_ms",
 * "sealed"} ("sealed" 0 or 1, since macula-go v0.18.0). */
char *macula_served_next(macula_handle served, int64_t timeout_ms, macula_handle cancel, macula_handle *out_item,
                         int32_t *closed, char **err_out);
/* Answer a pending call, once: with a result, or with an error the caller
 * receives as a provider error of code "handler_error" and detail message.
 * An answer after the call's deadline is "answered". The handle ends with its
 * first answer, or when its procedure stops; it is never freed by the caller. */
void macula_pending_reply(macula_handle pending, const char *result_json, char **err_out);
void macula_pending_error(macula_handle pending, const char *message, char **err_out);
/* Withdraws the procedure everywhere; frees the handle. */
void macula_served_stop(macula_handle served, char **err_out);

/* ---- Streams ----------------------------------------------------------- */

/* deadline_ms: how far ahead the open's signed deadline lies (30 s when 0),
 * which bounds the provider's admission, not the stream's life; timeout_ms:
 * to open it. */
macula_handle macula_pool_open_stream(macula_handle pool, const uint8_t realm[32], const char *procedure, int32_t mode,
                                      const char *payload_json, const uint8_t *provider_node_id, int64_t deadline_ms,
                                      int64_t timeout_ms, macula_handle cancel, char **err_out);
/* macula_pool_open_stream presenting a UCAN and its chain's proofs, as
 * macula_pool_call_with does; a gated provider refuses one with a stream
 * error. Since macula-go v0.17.0. */
macula_handle macula_pool_open_stream_with(macula_handle pool, const uint8_t realm[32], const char *procedure,
                                           int32_t mode, const char *payload_json, const uint8_t *provider_node_id,
                                           const char *ucan, const char *proofs_json, int64_t deadline_ms,
                                           int64_t timeout_ms, macula_handle cancel, char **err_out);
/* macula_pool_open_stream with options as JSON, macula_pool_call_opts'
 * set. Since macula-go v0.18.0. */
macula_handle macula_pool_open_stream_opts(macula_handle pool, const uint8_t realm[32], const char *procedure,
                                           int32_t mode, const char *payload_json, const char *options_json,
                                           int64_t deadline_ms, int64_t timeout_ms, macula_handle cancel,
                                           char **err_out);
char *macula_stream_request(macula_handle stream, char **err_out);
void macula_stream_send_bytes(macula_handle stream, const uint8_t *data, size_t data_len, char **err_out);
void macula_stream_send_json(macula_handle stream, const char *value_json, char **err_out);
void macula_stream_close_send(macula_handle stream, char **err_out);
void macula_stream_reply(macula_handle stream, const char *payload_json, char **err_out);
void macula_stream_abort(macula_handle stream, const char *code, const char *message, char **err_out);
void macula_stream_close(macula_handle stream, char **err_out);
/* {"kind":"data","encoding","body"} | {"kind":"end","role"} |
 * {"kind":"reply","payload"} | {"kind":"eof"} |
 * {"kind":"error","code","message","relay"}; timeout_ms 0 waits for ever. */
char *macula_stream_recv(macula_handle stream, int64_t timeout_ms, macula_handle cancel, char **err_out);
/* Aborts the stream first when it has not ended. */
void macula_stream_free(macula_handle stream);

/* ---- Content (node-served, D27) ---------------------------------------- */

void macula_pool_share_content(macula_handle pool, const uint8_t realm[32], const uint8_t *data, size_t data_len,
                               const char *name, int64_t timeout_ms, macula_handle cancel, uint8_t out_mcid[50],
                               char **err_out);
void macula_pool_unshare_content(macula_handle pool, const uint8_t realm[32], const uint8_t mcid[50],
                                 int64_t timeout_ms, macula_handle cancel, char **err_out);
/* options_json (NULL for defaults): {"max_bytes","max_chunks","parallel","chunk_timeout_ms"}. */
uint8_t *macula_pool_get_content(macula_handle pool, const uint8_t realm[32], const uint8_t mcid[50],
                                 const char *options_json, int64_t timeout_ms, macula_handle cancel, size_t *out_len,
                                 char **err_out);

/* ---- DHT records ------------------------------------------------------- */

/* {"type","key_id","created_at","expires_at","payload","wire"} */
char *macula_pool_find_record(macula_handle pool, const uint8_t key[32], int64_t timeout_ms, macula_handle cancel,
                              char **err_out);
/* {"records": [...], "dropped"} */
char *macula_pool_find_records(macula_handle pool, const uint8_t key[32], int64_t timeout_ms, macula_handle cancel,
                               char **err_out);
char *macula_pool_find_records_by_type(macula_handle pool, int32_t record_type, int64_t timeout_ms,
                                       macula_handle cancel, char **err_out);
void macula_pool_put_record(macula_handle pool, const uint8_t *wire, size_t wire_len, int64_t timeout_ms,
                            macula_handle cancel, char **err_out);

#ifdef __cplusplus
}
#endif

#endif /* MACULA_H */
