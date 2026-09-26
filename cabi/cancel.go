package main

// #include <stdint.h>
import "C"

import (
	"context"
	"errors"
	"time"
)

// A cancel token is a context a binding cancels from any thread, ending every
// blocking call given it (CONTRACT.md "Cancellation").

// errTokenCancelled is the cause of a cancelled token's context, which tells
// a cancellation from a timeout however the call's error wraps it.
var errTokenCancelled = errors.New("cabi: cancelled")

type cancelToken struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
}

func newCancelToken() *cancelToken {
	ctx, cancel := context.WithCancelCause(context.Background())
	return &cancelToken{ctx: ctx, cancel: cancel}
}

//export macula_cancel_new
func macula_cancel_new() C.uintptr_t { return newHandle(newCancelToken()) }

//export macula_cancel
func macula_cancel(h C.uintptr_t) {
	if t, ok := valueOf[*cancelToken](h); ok {
		t.cancel(errTokenCancelled)
	}
}

//export macula_cancel_free
func macula_cancel_free(h C.uintptr_t) {
	if _, ok := valueOf[*cancelToken](h); ok {
		release(h)
	}
}

// callContext is a blocking call's context: its token's (none for 0), bounded
// by timeoutMs when positive. A handle that is not a token is an error.
func callContext(token C.uintptr_t, timeoutMs C.int64_t) (context.Context, context.CancelFunc, error) {
	base := context.Background()
	if token != 0 {
		t, ok := valueOf[*cancelToken](token)
		if !ok {
			return nil, nil, errInvalidHandle
		}
		base = t.ctx
	}
	return withTimeout(base, int64(timeoutMs))
}

// withTimeout bounds ctx by timeoutMs when it is positive; a negative one is
// refused.
func withTimeout(ctx context.Context, timeoutMs int64) (context.Context, context.CancelFunc, error) {
	switch {
	case timeoutMs < 0:
		return nil, nil, invalidArgument("a negative timeout_ms")
	case timeoutMs == 0:
		ctx, cancel := context.WithCancel(ctx)
		return ctx, cancel, nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	return ctx, cancel, nil
}
