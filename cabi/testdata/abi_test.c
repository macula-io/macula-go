/*
 * abi_test.c drives libmacula through macula.h alone, as a binding does:
 * keys, a pool per node, serving and calling in a node's own namespace,
 * answering from the inbox, a cancel from another thread, publish and
 * subscribe, a server stream, content, device request and ownership proofs,
 * UCAN-gated serving, sealed calls and streams, error kinds, and freeing. The realm is named "abi", which a UCAN grants in. abi_test.go
 * builds it against the built library and runs it with two in-process
 * stations:
 *
 *   abi_test <key dir> <seeds json> <realm hex> <options json> <device request vector hex>
 *            <ownership proof vector hex> <ownership proof identity hex>
 *
 * It prints "ok" last, or fails with the step that went wrong.
 */
#define _POSIX_C_SOURCE 200809L
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "macula.h"

static void fail(const char *step, char *err) {
  fprintf(stderr, "FAIL %s: %s\n", step, err ? err : "(no error)");
  exit(1);
}

/* check fails the test when err is set, and frees nothing: a failing test
 * exits. */
static void check(const char *step, char *err) {
  if (err) fail(step, err);
}

/* expect_kind checks *err is a JSON error of kind, frees it, and sets *err
 * back to NULL for the next call. */
static void expect_kind(const char *step, char **err, const char *kind) {
  char wanted[64];
  if (!*err) fail(step, NULL);
  snprintf(wanted, sizeof wanted, "\"kind\":\"%s\"", kind);
  if (!strstr(*err, wanted)) fail(step, *err);
  macula_free_string(*err);
  *err = NULL;
}

static void expect_contains(const char *step, const char *text, const char *want) {
  if (!text || !strstr(text, want)) {
    fprintf(stderr, "FAIL %s: %s lacks %s\n", step, text ? text : "(null)", want);
    exit(1);
  }
}

static void hex_to(const char *hex, uint8_t *out, size_t n) {
  for (size_t i = 0; i < n; i++) sscanf(hex + 2 * i, "%2hhx", &out[i]);
}

static void to_hex(const uint8_t *in, size_t n, char *out) {
  for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", in[i]);
  out[2 * n] = 0;
}

static macula_handle join(const char *dir, const char *name, const char *seeds, const char *options) {
  char path[512], step[64];
  char *err = NULL;
  snprintf(path, sizeof path, "%s/%s.key", dir, name);
  snprintf(step, sizeof step, "load_or_create %s", name);
  macula_handle key = macula_key_load_or_create(path, "pq_pure", 0, &err);
  check(step, err);
  /* A second load of the same file is the same node. */
  macula_handle again = macula_key_load(path, "pq_pure", &err);
  check("key_load", err);
  uint8_t a[32], b[32];
  macula_key_node_id(key, a, &err);
  check("key_node_id", err);
  macula_key_node_id(again, b, &err);
  check("key_node_id again", err);
  if (memcmp(a, b, 32) != 0) fail("a reloaded key is another node", NULL);
  macula_key_free(again);
  snprintf(step, sizeof step, "pool_connect %s", name);
  macula_handle pool = macula_pool_connect(key, seeds, options, 0, &err);
  check(step, err);
  macula_key_free(key);
  return pool;
}

static void own_procedure(macula_handle pool, const char *name, char *out) {
  uint8_t id[32];
  char hex[65], *err = NULL;
  macula_pool_node_id(pool, id, &err);
  check("pool_node_id", err);
  to_hex(id, 32, hex);
  sprintf(out, "~%s/%s", hex, name);
}

/* The provider's side of one call: take it, check it, answer it. */
struct provider_args {
  macula_handle served;
};

static void *provide_one(void *p) {
  struct provider_args *args = p;
  macula_handle pending = 0;
  int32_t closed = 0;
  char *err = NULL;
  char *request = macula_served_next(args->served, 20000, 0, &pending, &closed, &err);
  check("served_next", err);
  expect_contains("the served request", request, "\"payload\":{\"n\":9007199254740993}");
  macula_free_string(request);
  macula_pending_reply(pending, "{\"echo\":{\"$bytes\":\"AQI=\"},\"big\":-9223372036854775808}", &err);
  check("pending_reply", err);
  /* The handle ended with its first answer. */
  macula_pending_reply(pending, "null", &err);
  expect_kind("a second answer", &err, "invalid_handle");
  return NULL;
}

/* provide_sealed answers one sealed call, checking it says it came sealed. */
static void *provide_sealed(void *p) {
  struct provider_args *args = p;
  macula_handle pending = 0;
  int32_t closed = 0;
  char *err = NULL;
  char *request = macula_served_next(args->served, 20000, 0, &pending, &closed, &err);
  check("served_next of a sealed call", err);
  expect_contains("the sealed request", request, "\"sealed\":1");
  expect_contains("the sealed request", request, "\"payload\":{\"n\":9007199254740993}");
  macula_free_string(request);
  macula_pending_reply(pending, "{\"echo\":{\"$bytes\":\"AQI=\"}}", &err);
  check("pending_reply to a sealed call", err);
  return NULL;
}

/* cancel_later cancels a token after a moment, from another thread. */
static void *cancel_later(void *p) {
  struct timespec pause = {0, 300 * 1000 * 1000};
  nanosleep(&pause, NULL);
  macula_cancel(*(macula_handle *)p);
  return NULL;
}

int main(int argc, char **argv) {
  if (argc != 8) {
    fprintf(stderr, "usage: abi_test <key dir> <seeds json> <realm hex> <options json> <device request vector hex> "
                    "<ownership proof vector hex> <ownership proof identity hex>\n");
    return 2;
  }
  const char *dir = argv[1], *seeds = argv[2], *options = argv[4];
  uint8_t realm[32];
  hex_to(argv[3], realm, 32);
  char *err = NULL;

  if (macula_abi_version() != MACULA_ABI_VERSION) fail("abi version", NULL);

  /* Error kinds, and handles of another kind. */
  macula_pool_status(0, &err);
  expect_kind("status of handle 0", &err, "invalid_handle");
  macula_key_generate("pq_nothing", 0, &err);
  expect_kind("an unknown profile", &err, "invalid_argument");

  macula_handle provider = join(dir, "provider", seeds, options);
  macula_handle caller = join(dir, "caller", seeds, options);
  macula_key_free(provider); /* a pool handle is not a key: nothing happens */

  char *status = macula_pool_status(provider, &err);
  check("pool_status", err);
  expect_contains("pool_status", status, "\"up\":1");
  macula_free_string(status);

  int32_t closed = 0;
  char *event = macula_pool_events_next(provider, 5000, 0, &closed, &err);
  check("pool_events_next", err);
  expect_contains("the first pool event", event, "\"kind\":\"link\"");
  macula_free_string(event);

  /* A call to a procedure in the provider's own namespace. */
  char echo[128];
  own_procedure(provider, "echo", echo);
  macula_handle served = macula_pool_serve(provider, realm, echo, &err);
  check("pool_serve", err);
  pthread_t thread;
  struct provider_args args = {served};
  pthread_create(&thread, NULL, provide_one, &args);
  char *result = macula_pool_call(caller, realm, echo, "{\"n\":9007199254740993}", NULL, 20000, 0, &err);
  check("pool_call", err);
  expect_contains("the call's result", result, "\"echo\":{\"$bytes\":\"AQI=\"}");
  expect_contains("the call's result", result, "\"big\":-9223372036854775808");
  macula_free_string(result);
  pthread_join(thread, NULL);

  macula_pool_call(caller, realm, echo, "true", NULL, 5000, 0, &err);
  expect_kind("a boolean payload", &err, "invalid_argument");

  /* A call nobody answers, cancelled from another thread. */
  macula_handle token = macula_cancel_new();
  pthread_create(&thread, NULL, cancel_later, &token);
  macula_pool_call(caller, realm, echo, "null", NULL, 30000, token, &err);
  expect_kind("a cancelled call", &err, "cancelled");
  pthread_join(thread, NULL);
  macula_pool_call(caller, realm, echo, "null", NULL, 30000, token, &err);
  expect_kind("a call given a cancelled token", &err, "cancelled");
  macula_cancel_free(token);

  /* The unanswered call waits in the inbox; a wait that times out is empty. */
  macula_handle pending = 0;
  char *stale = macula_served_next(served, 1000, 0, &pending, &closed, &err);
  check("served_next of the cancelled call", err);
  macula_free_string(stale);
  macula_served_stop(served, &err);
  check("served_stop", err);
  macula_served_stop(served, &err);
  expect_kind("a second served_stop", &err, "invalid_handle");

  /* Publish and subscribe. */
  macula_handle sub = macula_pool_subscribe(caller, realm, "abi.news", &err);
  check("pool_subscribe", err);
  char *heard = NULL;
  for (int i = 0; i < 50 && !heard; i++) {
    macula_pool_publish(provider, realm, "abi.news", "{\"headline\":\"cabi\"}", 0, &err);
    check("pool_publish", err);
    heard = macula_subscription_next(sub, 200, 0, &closed, &err);
    check("subscription_next", err);
  }
  expect_contains("the event", heard, "\"headline\":\"cabi\"");
  macula_free_string(heard);
  if (macula_subscription_dropped(sub, &err) != 0) fail("dropped events", err);
  macula_subscription_stop(sub);

  /* A server stream. */
  char count[128];
  own_procedure(provider, "count", count);
  macula_handle streaming = macula_pool_serve_stream(provider, realm, count, MACULA_STREAM_SERVER, &err);
  check("pool_serve_stream", err);
  macula_handle stream = macula_pool_open_stream(caller, realm, count, MACULA_STREAM_SERVER, "{\"to\":2}", NULL, 20000,
                                                 20000, 0, &err);
  check("pool_open_stream", err);
  macula_handle session = 0;
  char *open = macula_served_next(streaming, 20000, 0, &session, &closed, &err);
  check("served_next of a session", err);
  expect_contains("the session's request", open, "\"payload\":{\"to\":2}");
  macula_free_string(open);
  macula_stream_send_json(session, "{\"n\":1}", &err);
  check("stream_send_json", err);
  const uint8_t raw[] = {7, 8};
  macula_stream_send_bytes(session, raw, sizeof raw, &err);
  check("stream_send_bytes", err);
  macula_stream_reply(session, "\"done\"", &err);
  check("stream_reply", err);
  const char *want[] = {"\"body\":{\"n\":1}", "\"body\":{\"$bytes\":\"Bwg=\"}", "\"kind\":\"reply\"", "\"kind\":\"eof\""};
  for (int i = 0, seen = 0; seen < 4 && i < 16; i++) {
    char *frame = macula_stream_recv(stream, 10000, 0, &err);
    check("stream_recv", err);
    if (strstr(frame, want[seen])) seen++;
    if (strstr(frame, "\"kind\":\"eof\"") && seen < 4) fail("the stream ended early", frame);
    if (seen == 4) {
      macula_free_string(frame);
      break;
    }
    macula_free_string(frame);
  }
  macula_stream_free(stream);
  macula_stream_free(session);
  macula_served_stop(streaming, &err);
  check("served_stop of the stream", err);

  /* Content. */
  size_t size = 600000;
  uint8_t *data = malloc(size);
  for (size_t i = 0; i < size; i++) data[i] = (uint8_t)(i * 31);
  uint8_t mcid[50];
  macula_pool_share_content(provider, realm, data, size, "blob", 20000, 0, mcid, &err);
  check("share_content", err);
  size_t got_len = 0;
  uint8_t *got = macula_pool_get_content(caller, realm, mcid, "{\"parallel\":2}", 30000, 0, &got_len, &err);
  check("get_content", err);
  if (got_len != size || memcmp(got, data, size) != 0) fail("the content differs", NULL);
  macula_free_bytes(got);
  macula_pool_unshare_content(provider, realm, mcid, 20000, 0, &err);
  check("unshare_content", err);
  macula_pool_get_content(caller, realm, mcid, NULL, 20000, 0, &got_len, &err);
  expect_kind("unshared content", &err, "not_shared");
  free(data);

  /* A key signs and verifies. */
  macula_handle key = macula_key_load_or_create("/nonexistent-dir/x.key", NULL, 0, &err);
  if (!err || key) fail("a key saved where it cannot be", NULL);
  macula_free_string(err);
  err = NULL;
  char path[512];
  snprintf(path, sizeof path, "%s/signer.key", dir);
  key = macula_key_load_or_create(path, "pq_pure", 0, &err);
  check("signer key", err);
  size_t sig_len = 0, pub_len = 0;
  uint8_t *sig = macula_key_sign(key, (const uint8_t *)"msg", 3, &sig_len, &err);
  check("key_sign", err);
  uint8_t *pub = macula_key_public_key(key, &pub_len, &err);
  check("key_public_key", err);
  if (macula_verify((const uint8_t *)"msg", 3, sig, sig_len, pub, pub_len, "pq_pure", &err) != 1) fail("verify", err);
  if (macula_verify((const uint8_t *)"msh", 3, sig, sig_len, pub, pub_len, "pq_pure", &err) != 0) fail("verify other", err);
  char *profile = macula_key_profile(key, &err);
  check("key_profile", err);
  expect_contains("key_profile", profile, "pq_pure");
  macula_free_string(profile);
  macula_free_bytes(sig);
  macula_free_bytes(pub);
  macula_key_free(key);

  /* The realm's device request vector, through the ABI; then a proof. */
  {
    const char *vector_hex = argv[5];
    size_t vector_len = strlen(vector_hex) / 2;
    uint8_t *vector = malloc(vector_len);
    hex_to(vector_hex, vector, vector_len);
    uint8_t pub[2592], io_macula[32], nonce[16] = {0};
    memset(pub, 0x07, sizeof pub);
    hex_to("abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1", io_macula, 32);
    size_t message_len = 0;
    uint8_t *message = macula_device_request_message(pub, sizeof pub, io_macula, "macula_realm.join_session",
        1790000000000, nonce, "{\"device_info\": {\"hostname\": \"laptop.local\", \"note\": null}, \"n\": 1e2, \"z\": -0.0, \"f\": 1.5}",
        MACULA_REQUEST_HTTP, &message_len, &err);
    check("device_request_message", err);
    if (message_len != vector_len || memcmp(message, vector, vector_len) != 0) fail("the device request message is not the realm's vector", NULL);
    macula_free_bytes(message);
    free(vector);
    macula_device_request_message(pub, sizeof pub, io_macula, "macula_realm.join_session", 1, nonce, "{\"ok\": true}",
        MACULA_REQUEST_HTTP, &message_len, &err);
    expect_kind("a boolean in a device request", &err, "invalid_argument");

    char keypath[512];
    snprintf(keypath, sizeof keypath, "%s/device.key", dir);
    macula_handle device = macula_key_load_or_create(keypath, "pq_pure", 0, &err);
    check("device key", err);
    char *proof = macula_key_device_request_proof(device, io_macula, "macula_realm.membership_ucan",
        "{\"public_key\": \"a2V5\", \"ttl_seconds\": 3600}", MACULA_REQUEST_MESH, &err);
    check("device_request_proof", err);
    expect_contains("the proof", proof, "\"v\":2");
    expect_contains("the proof", proof, "\"nonce\":\"");
    expect_contains("the proof", proof, "\"signature\":\"");
    macula_free_string(proof);
    macula_key_free(device);
  }

  /* mcl_om's ownership proof vector, through the ABI; then a signed payload. */
  {
    const char *vector_hex = argv[6];
    size_t vector_len = strlen(vector_hex) / 2;
    uint8_t *vector = malloc(vector_len);
    hex_to(vector_hex, vector, vector_len);
    uint8_t identity[32], io_macula[32], nonce[16];
    hex_to(argv[7], identity, 32);
    hex_to("abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1", io_macula, 32);
    for (int i = 0; i < 16; i++) nonce[i] = (uint8_t)i;
    const char *fields = "{\"subject\": \"entity:alpha\", \"predicate\": \"knows\", \"object\": \"entity:beta\", "
        "\"confidence\": 0.75, \"weight\": 3, \"offset\": -7, \"digest\": {\"$bytes\": \"AQID\"}, \"note\": null, "
        "\"tags\": [\"a\", \"b\"], \"metadata\": {\"source\": \"field-notes\", \"page\": 12}, "
        "\"caller\": \"a caller is sent, not signed\"}";
    size_t message_len = 0;
    uint8_t *message = macula_ownership_proof_message(identity, io_macula, "mcl-graph/learn_link", 1790000000000,
        nonce, fields, &message_len, &err);
    check("ownership_proof_message", err);
    if (message_len != vector_len || memcmp(message, vector, vector_len) != 0) fail("the ownership proof message is not mcl_om's vector", NULL);
    macula_free_bytes(message);
    free(vector);
    macula_ownership_proof_message(identity, io_macula, "mcl-graph/learn_link", 1, nonce, "[1]", &message_len, &err);
    expect_kind("ownership fields that are not an object", &err, "invalid_argument");

    char keypath[512];
    snprintf(keypath, sizeof keypath, "%s/owner.key", dir);
    macula_handle owner = macula_key_load_or_create(keypath, "pq_pure", 0, &err);
    check("owner key", err);
    char *signed_payload = macula_key_ownership_proof(owner, io_macula, "mcl-graph/learn_link",
        "{\"subject\": \"entity:alpha\", \"weight\": 3}", &err);
    check("key_ownership_proof", err);
    expect_contains("the signed payload", signed_payload, "\"asserted_by\":{");
    expect_contains("the signed payload", signed_payload, "\"v\":2");
    expect_contains("the signed payload", signed_payload, "\"public\":\"");
    expect_contains("the signed payload", signed_payload, "\"subject\":\"entity:alpha\"");
    macula_free_string(signed_payload);
    macula_key_ownership_proof(owner, io_macula, "mcl-graph/learn_link", "{\"ok\": true}", &err);
    expect_kind("a boolean in an ownership-proven payload", &err, "invalid_argument");
    macula_key_ownership_proof(owner, io_macula, "mcl-graph/learn_link", "{\"a\": 1, \"caller\": \"me\"}", &err);
    expect_kind("a caller in an ownership-proven payload", &err, "invalid_argument");
    macula_key_free(owner);
  }

  /* A UCAN: minted by a root node for the caller, and presented to a
   * procedure gated on that root. */
  {
    char rootpath[512], policy[256], root_hex[65], gated[128], watch[128];
    uint8_t root_id[32], caller_id[32];
    snprintf(rootpath, sizeof rootpath, "%s/root.key", dir);
    macula_handle root = macula_key_load_or_create(rootpath, "pq_pure", 0, &err);
    check("root key", err);
    macula_key_node_id(root, root_id, &err);
    check("root node_id", err);
    to_hex(root_id, 32, root_hex);
    macula_pool_node_id(caller, caller_id, &err);
    check("caller node_id", err);
    char *ucan = macula_ucan_create(root, caller_id, "[{\"with\":\"mri:realm:abi\",\"can\":\"invoke\"}]",
                                    (int64_t)time(NULL) + 60, NULL, &err);
    check("ucan_create", err);
    if (strlen(ucan) < 100 || !strchr(ucan, '.')) fail("not a token", ucan);
    char *proof_id = macula_ucan_proof_id(ucan, &err);
    check("ucan_proof_id", err);
    if (strlen(proof_id) != 96) fail("a proof id is 96 hex characters", proof_id);
    macula_free_string(proof_id);
    macula_ucan_create(root, caller_id, "{}", 1, NULL, &err);
    expect_kind("caps that are not a list", &err, "invalid_argument");
    macula_key_free(root);

    snprintf(policy, sizeof policy, "{\"kind\":\"ucan_required\",\"issuer\":\"%s\"}", root_hex);
    own_procedure(provider, "gated", gated);
    macula_pool_serve_gated(provider, realm, gated, "{\"kind\":\"open\"}", &err);
    expect_kind("an open policy to a gated serve", &err, "invalid_argument");
    served = macula_pool_serve_gated(provider, realm, gated, policy, &err);
    check("pool_serve_gated", err);
    macula_pool_call_with(caller, realm, gated, "null", NULL, NULL, NULL, 20000, 0, &err);
    if (!err || !strstr(err, "\"code\":\"unauthorized\"")) fail("a call without a token", err);
    expect_kind("a call without a token", &err, "provider_error");
    macula_pool_call_with(caller, realm, gated, "null", NULL, ucan, "[1]", 20000, 0, &err);
    expect_kind("proofs that are not tokens", &err, "invalid_argument");
    args.served = served;
    pthread_create(&thread, NULL, provide_one, &args);
    result = macula_pool_call_with(caller, realm, gated, "{\"n\":9007199254740993}", NULL, ucan, "[]", 20000, 0, &err);
    check("pool_call_with", err);
    expect_contains("the gated call's result", result, "\"echo\":{\"$bytes\":\"AQI=\"}");
    macula_free_string(result);
    pthread_join(thread, NULL);
    macula_served_stop(served, &err);
    check("served_stop of the gated procedure", err);

    own_procedure(provider, "watch", watch);
    streaming = macula_pool_serve_stream_gated(provider, realm, watch, MACULA_STREAM_SERVER, policy, &err);
    check("pool_serve_stream_gated", err);
    stream = macula_pool_open_stream_with(caller, realm, watch, MACULA_STREAM_SERVER, "null", NULL, NULL, NULL, 20000,
                                          20000, 0, &err);
    check("pool_open_stream_with", err);
    char *refused = macula_stream_recv(stream, 10000, 0, &err);
    check("stream_recv of a refused open", err);
    expect_contains("a refused open", refused, "\"code\":\"unauthorized\"");
    macula_free_string(refused);
    macula_stream_free(stream);
    stream = macula_pool_open_stream_with(caller, realm, watch, MACULA_STREAM_SERVER, "{\"to\":1}", NULL, ucan, NULL,
                                          20000, 20000, 0, &err);
    check("pool_open_stream_with a token", err);
    open = macula_served_next(streaming, 20000, 0, &session, &closed, &err);
    check("served_next of a gated session", err);
    expect_contains("the gated session's request", open, "\"payload\":{\"to\":1}");
    macula_free_string(open);
    macula_stream_free(stream);
    macula_stream_free(session);
    macula_served_stop(streaming, &err);
    check("served_stop of the gated stream", err);
    macula_free_string(ucan);
  }

  /* Sealed end to end (macula 13): a node that names its KEM key, a procedure
   * that takes sealed calls only, a sealed call and a sealed stream to it, and
   * a clear call refused. */
  {
    char vault[128], watch[128];
    size_t len = strlen(options);
    if (len == 0 || options[len - 1] != '}') fail("the options to extend", NULL);
    char *keyed_options = malloc(len + 32);
    memcpy(keyed_options, options, len - 1);
    strcpy(keyed_options + len - 1, ", \"kem_advertise\": 1}");
    macula_handle keyed = join(dir, "keyed", seeds, keyed_options);
    free(keyed_options);
    own_procedure(keyed, "vault", vault);
    macula_pool_serve_opts(keyed, realm, vault, "{\"confidential\":\"maybe\"}", &err);
    expect_kind("a confidentiality outside its set", &err, "invalid_argument");
    macula_handle sealed = macula_pool_serve_opts(keyed, realm, vault, "{\"confidential\":\"required\"}", &err);
    check("pool_serve_opts", err);
    struct provider_args sealed_args = {sealed};
    pthread_create(&thread, NULL, provide_sealed, &sealed_args);
    char *answer = NULL;
    for (int i = 0; i < 100 && !answer; i++) {
      answer = macula_pool_call_opts(caller, realm, vault, "{\"n\":9007199254740993}", "{}", 20000, 0, &err);
      if (err && strstr(err, "\"kind\":\"no_provider\"")) {
        macula_free_string(err);
        err = NULL;
        struct timespec pause = {0, 100 * 1000 * 1000};
        nanosleep(&pause, NULL);
      }
    }
    check("pool_call_opts", err);
    expect_contains("the sealed call's result", answer, "\"echo\":{\"$bytes\":\"AQI=\"}");
    macula_free_string(answer);
    pthread_join(thread, NULL);
    macula_pool_call_opts(caller, realm, vault, "null", "{\"confidential\":\"off\"}", 20000, 0, &err);
    if (!err || !strstr(err, "\"code\":\"sealed_required\"")) fail("a clear call to a required procedure", err);
    expect_kind("a clear call to a required procedure", &err, "provider_error");
    macula_served_stop(sealed, &err);
    check("served_stop of the sealed procedure", err);

    own_procedure(keyed, "watch", watch);
    streaming = macula_pool_serve_stream_opts(keyed, realm, watch, MACULA_STREAM_SERVER, "{\"confidential\":\"required\"}", &err);
    check("pool_serve_stream_opts", err);
    stream = macula_pool_open_stream_opts(caller, realm, watch, MACULA_STREAM_SERVER, "{\"to\":1}", NULL, 20000, 20000, 0, &err);
    check("pool_open_stream_opts", err);
    open = macula_served_next(streaming, 20000, 0, &session, &closed, &err);
    check("served_next of a sealed session", err);
    expect_contains("the sealed session's request", open, "\"sealed\":1");
    expect_contains("the sealed session's request", open, "\"payload\":{\"to\":1}");
    macula_free_string(open);
    macula_stream_reply(session, "\"sealed reply\"", &err);
    check("stream_reply on a sealed stream", err);
    char *reply = NULL;
    for (int i = 0; i < 4 && !reply; i++) {
      char *frame = macula_stream_recv(stream, 10000, 0, &err);
      check("stream_recv of a sealed stream", err);
      if (strstr(frame, "\"kind\":\"reply\"")) reply = frame; else macula_free_string(frame);
    }
    expect_contains("the sealed stream's reply", reply, "\"payload\":\"sealed reply\"");
    macula_free_string(reply);
    macula_stream_free(stream);
    macula_stream_free(session);
    macula_served_stop(streaming, &err);
    check("served_stop of the sealed stream", err);
    macula_pool_close(keyed);
  }

  /* Closing a pool ends what it owns. */
  sub = macula_pool_subscribe(caller, realm, "abi.after", &err);
  check("subscribe before close", err);
  macula_pool_close(caller);
  char *after = macula_subscription_next(sub, 5000, 0, &closed, &err);
  check("subscription_next after close", err);
  if (after || closed != 1) fail("a subscription of a closed pool is not closed", after);
  macula_subscription_stop(sub);
  macula_pool_close(provider);
  macula_pool_status(provider, &err);
  expect_kind("a closed pool", &err, "invalid_handle");

  printf("ok\n");
  return 0;
}
