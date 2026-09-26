package main

// #include <stdint.h>
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

// errorKind is an error's fixed kind, the table in CONTRACT.md "Errors".
type errorKind string

const (
	kindCancelled       errorKind = "cancelled"
	kindTimeout         errorKind = "timeout"
	kindInvalidHandle   errorKind = "invalid_handle"
	kindInvalidArgument errorKind = "invalid_argument"
	kindProviderError   errorKind = "provider_error"
	kindRelayError      errorKind = "relay_error"
	kindNotFound        errorKind = "not_found"
	kindNoProvider      errorKind = "no_provider"
	kindNotShared       errorKind = "not_shared"
	kindUnavailable     errorKind = "unavailable"
	kindAnswered        errorKind = "answered"
	kindClosed          errorKind = "closed"
	kindRefused         errorKind = "refused"
	kindFailed          errorKind = "failed"
)

// abiError is an error as it crosses the ABI: a kind, a message for people,
// and the kind's own fields.
type abiError struct {
	kind    errorKind
	message string
	fields  map[string]any
}

func (e *abiError) Error() string { return string(e.kind) + ": " + e.message }

// JSON is the error as err_out carries it.
func (e *abiError) JSON() string {
	out := map[string]any{"kind": e.kind, "message": e.message}
	for k, v := range e.fields {
		out[k] = v
	}
	text, err := json.Marshal(out)
	if err != nil {
		panic(fmt.Sprintf("cabi: an error that does not encode: %v", err))
	}
	return string(text)
}

func newError(kind errorKind, format string, args ...any) *abiError {
	return &abiError{kind: kind, message: fmt.Sprintf(format, args...)}
}

var (
	errInvalidHandle = newError(kindInvalidHandle, "a handle this process does not hold, or of another kind")
	errAnswered      = newError(kindAnswered, "the call was already answered")
)

func invalidArgument(format string, args ...any) *abiError {
	return newError(kindInvalidArgument, format, args...)
}

// classify is err as the ABI reports it. ctx is the call's context, when it
// had one: a call whose context ended reports why it ended, whatever error
// that surfaced as, since a cancellation or timeout can arrive wrapped in
// anything.
func classify(ctx context.Context, err error) *abiError {
	var ae *abiError
	if errors.As(err, &ae) {
		return ae
	}
	if ctx != nil {
		switch context.Cause(ctx) {
		case nil:
		case errTokenCancelled:
			return newError(kindCancelled, "the call was cancelled")
		default:
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return newError(kindTimeout, "the call's timeout ran out")
			}
		}
	}
	var provider *stationlink.ProviderError
	var relay *stationlink.RelayError
	switch {
	case errors.As(err, &provider):
		var detail any
		if provider.Detail != nil {
			detail = *provider.Detail
		}
		return &abiError{kind: kindProviderError, message: err.Error(),
			fields: map[string]any{"code": provider.Code, "detail": detail}}
	case errors.As(err, &relay):
		return &abiError{kind: kindRelayError, message: err.Error(), fields: map[string]any{"code": relay.Code}}
	case errors.Is(err, stationlink.ErrCallTimeout), errors.Is(err, context.DeadlineExceeded):
		return newError(kindTimeout, "%v", err)
	case errors.Is(err, stationlink.ErrRecordNotFound):
		return newError(kindNotFound, "%v", err)
	case errors.Is(err, pool.ErrNotShared):
		return newError(kindNotShared, "%v", err)
	case errors.Is(err, pool.ErrContentUnavailable):
		return &abiError{kind: kindUnavailable, message: err.Error(), fields: map[string]any{"failures": failures(err)}}
	case errors.Is(err, pool.ErrClosed), errors.Is(err, stationlink.ErrClosed), errors.Is(err, stationlink.ErrStreamClosed),
		errors.Is(err, stationlink.ErrStopped):
		return newError(kindClosed, "%v", err)
	case errors.Is(err, pool.ErrNoProvider):
		return newError(kindNoProvider, "%v", err)
	}
	return newError(kindFailed, "%v", err)
}

// failures is each sharer's failure in a joined ErrContentUnavailable.
func failures(err error) []string {
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		return []string{}
	}
	out := []string{}
	for _, e := range joined.Unwrap() {
		if e != pool.ErrContentUnavailable {
			out = append(out, e.Error())
		}
	}
	return out
}

// setErr stores err in *errOut, for a call with no context of its own.
func setErr(errOut **C.char, err error) { setCtxErr(nil, errOut, err) }

// setCtxErr stores err, classified against the call's context, in *errOut.
func setCtxErr(ctx context.Context, errOut **C.char, err error) {
	if errOut == nil || err == nil {
		return
	}
	*errOut = cString(classify(ctx, err).JSON())
}
