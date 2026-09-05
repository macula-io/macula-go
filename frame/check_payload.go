package frame

import (
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/macula-io/macula-go/cbor"
)

// CheckPayload reports whether v is admissible as a frame payload — the
// Go counterpart to macula_frame.erl's check_payload/1, called from the
// producer's own goroutine before a payload ever reaches a link, for
// the same reason the reference does it there: the actual encode
// happens later (this SDK's own writer goroutine, in the pool's case),
// with nothing watching for a value the codec can't represent. The two
// things this catches fail differently downstream, and both are worse
// than an immediate, attributable error: an oversized (>16MiB) payload
// trips frame.Encode's own synchronous cap check inside the writer
// goroutine, which this SDK treats as a fatal link error — the link
// dies and respawns, and (unless the caller stops) immediately retries
// the same oversized payload. A duplicate-key map does NOT kill
// anything — cbor's own encoder emits both pairs (it never dedupes),
// so the frame reaches the wire fine, and the collision instead
// resolves silently on the station's OWN decoder as last-write-wins:
// one of the two values is gone with no error anywhere, client or
// station side. Both are exactly the gap check_payload exists to close:
// give the caller a synchronous, attributable error instead of either
// failure mode.
//
// One thing macula_frame.erl's own check_value/2 checks doesn't apply to
// a Go caller at all: integer range (Go's int64/uint64 already can't
// represent anything outside what the wire encodes). Erlang-term
// categories like tuples/pids/funs also don't apply — cbor.Value has no
// constructor for any of those. What's left, and what a Go caller can
// still get wrong: a map key of a kind the wire has no key encoding for
// (matching check_key/2's own atom/binary/{text,_}/integer allow-list),
// two map keys that encode to the same wire bytes (see the
// last-write-wins collision above), a non-finite float (see below —
// this one is NOT in the reference, and deliberately goes further than
// it), and a payload whose encoded size exceeds the wire's frame cap.
//
// NON-FINITE FLOATS (NaN, +Inf, -Inf) ARE REJECTED, even though
// macula_frame.erl's own check_value/2 passes every float through
// unconditionally ("FLOATS ARE CARRIED", its own doc's words) — this is
// a deliberate DIVERGENCE from the reference, not an oversight. The
// reference can afford that because Erlang's own float type cannot hold
// a non-finite value in the first place (1.0/0.0 raises badarith, not a
// value) — check_value/2 passes every float through because there is no
// bad float for it to catch. Go's float64 has no such guarantee:
// cbor.Float(math.NaN()) constructs a value the wire will happily accept
// and BLAKE3/CBOR-encode, and the station's own NIF decoder has no
// finiteness guard on its binary64 path (unlike its half-float path,
// which does) — enif_make_double on a non-finite value raises badarg
// station-side, unattributed to this call. "Match the reference" means
// matching the SAFETY INVARIANT (a payload never carries an
// unencodable-in-practice float), not matching its exact clause, when
// the two languages don't share the invariant that clause relies on.
//
// The size check compares the PAYLOAD's own encoded bytes against
// MaxFrameBytes, not the whole frame's (payload plus envelope fields —
// frame_type, call_id, realm, signature, etc.), so a payload sitting
// within a few hundred bytes of the cap can still overflow the actual
// frame and be rejected downstream by frame.Encode's own check — which,
// same as the reference's own equivalent gap (its own doc: "a payload
// sitting just under still reaches the connection"), surfaces as a
// dead link rather than an attributed error for that one narrow case.
func CheckPayload(v cbor.Value) error {
	if err := walkAndCheck(v, nil); err != nil {
		return err
	}
	if n := len(cbor.Encode(v)); n > MaxFrameBytes {
		return fmt.Errorf("frame: payload at %s exceeds the %d-byte frame cap (encoded %d bytes)",
			pathString(nil), MaxFrameBytes, n)
	}
	return nil
}

// walkAndCheck recursively validates every value in the tree: a map's
// keys must each be a wire-encodable key kind and distinct from each
// other once encoded (matching macula_frame.erl's check_key/2 and
// then_keys_distinct/3), and no float anywhere may be non-finite (a
// deliberate divergence from the reference — see CheckPayload's own
// doc).
func walkAndCheck(v cbor.Value, path []string) error {
	if v.Kind() == cbor.KindFloat {
		f, _ := v.AsFloat()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return fmt.Errorf("frame: non-finite float at %s cannot be encoded", pathString(path))
		}
		return nil
	}
	switch v.Kind() {
	case cbor.KindMap:
		entries, _ := v.AsMap()
		seen := make(map[string]struct{}, len(entries))
		for _, e := range entries {
			if !isValidKeyKind(e.Key) {
				return fmt.Errorf("frame: map key at %s is not a supported key kind", pathString(path))
			}
			keyBytes := cbor.Encode(e.Key)
			if _, dup := seen[string(keyBytes)]; dup {
				return fmt.Errorf("frame: two keys in the map at %s collapse to the same wire key",
					pathString(path))
			}
			seen[string(keyBytes)] = struct{}{}
			// Not recursing into e.Key itself: isValidKeyKind already
			// restricts it to Text/Bytes/UInt/NegInt, none of which can
			// contain a nested float or a nested map's own key collision.
			if err := walkAndCheck(e.Val, append(path, keyLabel(e.Key))); err != nil {
				return err
			}
		}
	case cbor.KindList:
		items, _ := v.AsList()
		for i, item := range items {
			if err := walkAndCheck(item, append(path, strconv.Itoa(i))); err != nil {
				return err
			}
		}
	}
	return nil
}

// isValidKeyKind mirrors macula_frame.erl's own check_key/2: a wire key
// is an atom, {text, Binary}, a plain binary, or an integer — i.e., in
// cbor.Value terms, Text, Bytes, UInt, or NegInt. A Map, List, Null, or
// Float key has no wire-key encoding the reference (or this port)
// recognizes.
func isValidKeyKind(k cbor.Value) bool {
	switch k.Kind() {
	case cbor.KindText, cbor.KindBytes, cbor.KindUInt, cbor.KindNegInt:
		return true
	default:
		return false
	}
}

func pathString(path []string) string {
	if len(path) == 0 {
		return "the payload root"
	}
	return strings.Join(path, ".")
}

func keyLabel(k cbor.Value) string {
	if s, ok := k.AsText(); ok {
		return s
	}
	if b, ok := k.AsBytes(); ok {
		return string(b)
	}
	return "?"
}
