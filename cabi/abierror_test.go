package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

func errorJSON(t *testing.T, e *abiError) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(e.JSON()), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestErrorsClassifyToTheirKind(t *testing.T) {
	detail := "boom"
	for _, c := range []struct {
		err  error
		kind errorKind
	}{
		{fmt.Errorf("wrapped: %w", &stationlink.ProviderError{Code: "handler_error", Detail: &detail}), kindProviderError},
		{&stationlink.RelayError{Code: "no_route"}, kindRelayError},
		{stationlink.ErrCallTimeout, kindTimeout},
		{stationlink.ErrRecordNotFound, kindNotFound},
		{pool.ErrNotShared, kindNotShared},
		{errors.Join(pool.ErrContentUnavailable, errors.New("sharer 1: refused")), kindUnavailable},
		{pool.ErrClosed, kindClosed},
		{stationlink.ErrStreamClosed, kindClosed},
		{errAnswered, kindAnswered},
		{errInvalidHandle, kindInvalidHandle},
		{errors.New("anything"), kindFailed},
	} {
		if got := classify(nil, c.err).kind; got != c.kind {
			t.Errorf("%v: %s, want %s", c.err, got, c.kind)
		}
	}
}

func TestErrorKindFields(t *testing.T) {
	detail := "boom"
	provider := errorJSON(t, classify(nil, &stationlink.ProviderError{Code: "handler_error", Detail: &detail}))
	if provider["kind"] != "provider_error" || provider["code"] != "handler_error" || provider["detail"] != "boom" {
		t.Errorf("provider error: %v", provider)
	}
	noDetail := errorJSON(t, classify(nil, &stationlink.ProviderError{Code: "x"}))
	if d, ok := noDetail["detail"]; !ok || d != nil {
		t.Errorf("a provider error with no detail: %v, want detail null", noDetail)
	}
	unavailable := errorJSON(t, classify(nil, errors.Join(pool.ErrContentUnavailable, errors.New("sharer 1: refused"),
		errors.New("sharer 2: mismatch"))))
	failures, _ := unavailable["failures"].([]any)
	if len(failures) != 2 || failures[0] != "sharer 1: refused" {
		t.Errorf("unavailable: %v", unavailable)
	}
}

// A call's ended context says why it ended, whatever error that surfaced as.
func TestAnEndedContextNamesWhyItEnded(t *testing.T) {
	token := newCancelToken()
	ctx, cancel, err := withTimeout(token.ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	token.cancel(errTokenCancelled)
	if got := classify(ctx, errors.New("stream reset")).kind; got != kindCancelled {
		t.Errorf("a cancelled token: %s, want cancelled", got)
	}

	timed, cancelTimed, err := withTimeout(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelTimed()
	time.Sleep(10 * time.Millisecond)
	if got := classify(timed, errors.New("stream reset")).kind; got != kindTimeout {
		t.Errorf("a timeout: %s, want timeout", got)
	}

	if _, _, err := withTimeout(context.Background(), -1); classify(nil, err).kind != kindInvalidArgument {
		t.Errorf("a negative timeout: %v", err)
	}
}
