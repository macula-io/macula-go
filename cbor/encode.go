package cbor

import (
	"encoding/binary"
	"fmt"
	"math"
	"sort"
)

const (
	majorUInt   = 0
	majorNegInt = 1
	majorBytes  = 2
	majorText   = 3
	majorList   = 4
	majorMap    = 5
	majorFloat  = 7 // also carries Null (AI 22)

	aiNull  = 22
	aiF64   = 27
	ai1     = 24
	ai2     = 25
	ai4     = 26
	ai8     = 27
	maxInAI = 23 // values 0..23 encode inline in the head byte's low 5 bits
)

// Encode produces the deterministic wire bytes for v — see the package
// doc for what "deterministic" means here and why it differs from
// generic canonical CBOR.
func Encode(v Value) []byte {
	var buf []byte
	return appendValue(buf, v)
}

func appendValue(buf []byte, v Value) []byte {
	switch v.kind {
	case KindUInt:
		return appendHead(buf, majorUInt, v.uintV)
	case KindNegInt:
		return appendHead(buf, majorNegInt, v.uintV)
	case KindBytes:
		buf = appendHead(buf, majorBytes, uint64(len(v.bytesV)))
		return append(buf, v.bytesV...)
	case KindText:
		buf = appendHead(buf, majorText, uint64(len(v.textV)))
		return append(buf, v.textV...)
	case KindList:
		buf = appendHead(buf, majorList, uint64(len(v.listV)))
		for _, item := range v.listV {
			buf = appendValue(buf, item)
		}
		return buf
	case KindMap:
		return appendMap(buf, v.mapV)
	case KindNull:
		return append(buf, (majorFloat<<5)|aiNull)
	case KindFloat:
		buf = append(buf, (majorFloat<<5)|aiF64)
		var bits [8]byte
		binary.BigEndian.PutUint64(bits[:], math.Float64bits(v.floatV))
		return append(buf, bits[:]...)
	default:
		panic(fmt.Sprintf("cbor: Encode: unhandled kind %d", v.kind))
	}
}

// appendMap sorts entries by the bytewise order of their own ENCODED key
// bytes (encode each key independently first, then sort the
// (key_bytes, value_bytes) pairs by key_bytes as plain byte slices),
// per §4 — the one rule a naive port is most likely to get wrong.
func appendMap(buf []byte, entries []MapEntry) []byte {
	type pair struct{ keyBytes, valBytes []byte }
	pairs := make([]pair, len(entries))
	for i, e := range entries {
		pairs[i] = pair{
			keyBytes: appendValue(nil, e.Key),
			valBytes: appendValue(nil, e.Val),
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		return lessBytes(pairs[i].keyBytes, pairs[j].keyBytes)
	})
	buf = appendHead(buf, majorMap, uint64(len(pairs)))
	for _, p := range pairs {
		buf = append(buf, p.keyBytes...)
		buf = append(buf, p.valBytes...)
	}
	return buf
}

func lessBytes(a, b []byte) bool {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// appendHead writes major/AI plus minimal-length extra bytes for value —
// inline if <=23, else the smallest of 1/2/4/8 extra bytes that fits.
func appendHead(buf []byte, major byte, value uint64) []byte {
	head := major << 5
	switch {
	case value <= maxInAI:
		return append(buf, head|byte(value))
	case value <= 0xFF:
		buf = append(buf, head|ai1)
		return append(buf, byte(value))
	case value <= 0xFFFF:
		buf = append(buf, head|ai2)
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], uint16(value))
		return append(buf, b[:]...)
	case value <= 0xFFFFFFFF:
		buf = append(buf, head|ai4)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(value))
		return append(buf, b[:]...)
	default:
		buf = append(buf, head|ai8)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], value)
		return append(buf, b[:]...)
	}
}
