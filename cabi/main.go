// Command cabi is macula-go's macula 12 API behind a C ABI, shared by every
// binding not written in Go. It is built as a library, never run:
//
//	go build -buildmode=c-shared  -o libmacula.so ./cabi
//	go build -buildmode=c-archive -o libmacula.a  ./cabi
//
// macula.h declares the ABI and CONTRACT.md says what every part of it means.
// Each exported function converts its C arguments and hands them to a Go
// function of the same area that does the work (keys.go, pool.go, calls.go,
// pubsub.go, serve.go, streams.go, content.go, records.go); those are what
// the Go tests exercise, and abi_test.go drives the built library from C.
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

// abiVersion is MACULA_ABI_VERSION in macula.h.
const abiVersion = 1

//export macula_abi_version
func macula_abi_version() C.int32_t { return abiVersion }

//export macula_free_string
func macula_free_string(s *C.char) { C.free(unsafe.Pointer(s)) }

//export macula_free_bytes
func macula_free_bytes(b *C.uint8_t) { C.free(unsafe.Pointer(b)) }

// valueOf resolves a handle to a value of type T, or ok false for a handle
// this process never issued, one already freed, or one of another type:
// cgo.Handle.Value panics on the first two.
func valueOf[T any](h C.uintptr_t) (v T, ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if h == 0 {
		return v, false
	}
	v, ok = cgo.Handle(h).Value().(T)
	return v, ok
}

func newHandle(v any) C.uintptr_t { return C.uintptr_t(cgo.NewHandle(v)) }

// release frees a handle, ignoring one already freed or never issued.
func release(h C.uintptr_t) {
	defer func() { _ = recover() }()
	if h != 0 {
		cgo.Handle(h).Delete()
	}
}

func goBytes(p *C.uint8_t, n C.size_t) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n))
}

// goString is a C string's text, or "" for NULL.
func goString(s *C.char) string {
	if s == nil {
		return ""
	}
	return C.GoString(s)
}

// fixed reads an n-byte buffer the caller owns, or false for NULL.
func fixed(p *C.uint8_t, n int) ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	return C.GoBytes(unsafe.Pointer(p), C.int(n)), true
}

// id32 is a 32-byte id, or false for NULL.
func id32(p *C.uint8_t) ([32]byte, bool) {
	b, ok := fixed(p, 32)
	if !ok {
		return [32]byte{}, false
	}
	return [32]byte(b), true
}

// writeFixed copies b into a buffer the caller owns.
func writeFixed(out *C.uint8_t, b []byte) {
	copy(unsafe.Slice((*byte)(unsafe.Pointer(out)), len(b)), b)
}

// cBytes mallocs a copy of b for the caller, who frees it with
// macula_free_bytes, and stores its length in *outLen.
func cBytes(b []byte, outLen *C.size_t) *C.uint8_t {
	*outLen = C.size_t(len(b))
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(C.CBytes(b))
}

func cString(s string) *C.char { return C.CString(s) }

func main() {}
