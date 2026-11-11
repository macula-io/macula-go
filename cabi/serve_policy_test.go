package main

import (
	"strings"
	"testing"

	"github.com/macula-io/macula-go/ucan"
)

// The ABI edge says who may call too: a serve whose options JSON names no
// policy is refused, rather than serving anyone by omission (macula-go#57,
// #60). Open is a policy the caller writes, {"policy":{"kind":"open"}}.
func TestServeOptionsNeedAPolicy(t *testing.T) {
	for _, gated := range []string{"macula_pool_serve_gated", "macula_pool_serve_stream_gated"} {
		for _, text := range []string{"", `{}`, `{"confidential":"off"}`, `{"confidential":"required"}`} {
			assertPolicyRequired(t, text, gated)
		}
	}
}

// assertPolicyRequired checks options that name no policy are refused, and the
// refusal teaches both fixes: the open policy, and the gated door its own
// caller would use — a stream's, not the call's.
func assertPolicyRequired(t *testing.T, text, gated string) {
	t.Helper()
	_, err := serveOptionsOf(text, gated)
	if kindOf(err) != kindInvalidArgument {
		t.Errorf("serve options %q for %s: %v, want invalid_argument", text, gated, err)
		return
	}
	for _, fix := range []string{`{"policy":{"kind":"open"}}`, gated} {
		if !strings.Contains(err.Error(), fix) {
			t.Errorf("serve options %q for %s refused with %q, want it to name %s", text, gated, err, fix)
		}
	}
}

// Open is a policy like any other in data, and the strictness of the other
// kinds holds: a field another kind names is refused beside it.
func TestOpenIsAPolicyTheOptionsJSONCanName(t *testing.T) {
	opts, err := serveOptionsOf(`{"policy":{"kind":"open"}}`, "macula_pool_serve_gated")
	if err != nil {
		t.Fatalf("serve options naming open: %v", err)
	}
	if _, open := opts.policy.(ucan.Open); !open {
		t.Fatalf("policy %#v, want ucan.Open", opts.policy)
	}
	for _, text := range []string{
		`{"policy":{"kind":"open","issuer":"00"}}`,
		`{"policy":{"kind":"open","key_id":"00"}}`,
		`{"policy":{"kind":"open","can":"invoke"}}`,
	} {
		if _, err := serveOptionsOf(text, "macula_pool_serve_gated"); kindOf(err) != kindInvalidArgument {
			t.Errorf("policy %s: %v, want invalid_argument", text, err)
		}
	}
}

// A gated serve is gated: open is refused there too, and the message names the
// door that does serve anyone, in the words of the _opts refusal, so the two
// refusals teach one fix (macula-go#57, #60).
func TestAGatedServeRefusesOpenAndNamesTheDoor(t *testing.T) {
	for _, text := range []string{``, `{"kind":"open"}`} {
		_, err := gatedPolicy(text)
		if kindOf(err) != kindInvalidArgument {
			t.Errorf("gated policy %q: %v, want invalid_argument", text, err)
			continue
		}
		for _, want := range []string{"macula_pool_serve_opts", `{"policy":{"kind":"open"}}`} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("gated policy %q refused with %q, want it to name %s", text, err, want)
			}
		}
	}
}

// ABI 2 is the version that went with the two deletions and the required
// policy: a binding written for ABI 1 refuses this library at load by
// comparing the number, so the number is what says the set changed.
func TestTheABIVersionIsTwo(t *testing.T) {
	if abiVersion != 2 {
		t.Errorf("abiVersion = %d, want 2: ABI 2 deleted macula_pool_serve and macula_pool_serve_stream and made "+
			"the _opts policy required", abiVersion)
	}
	if got := int(macula_abi_version()); got != abiVersion {
		t.Errorf("macula_abi_version() = %d, want abiVersion %d", got, abiVersion)
	}
}
