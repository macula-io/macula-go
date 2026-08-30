package frame

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/macula-io/macula-go/identity"
)

// These constants are copied verbatim from macula-rust's own
// src/frame.rs test module (connect_frame_matches_the_reference_byte_for_byte),
// which in turn built the exact same CONNECT frame
// macula_frame:connect/1 + macula_frame:sign/2 produced in a live
// rebar3 shell against the real Erlang reference — same identity, same
// fixed frame_id/sent_at_ms (injected explicitly; both implementations'
// own frame builders randomize these per call).
//
// This is the strongest cross-language check available without a live
// station: if this Go port produces the identical signature and encoded
// length the Rust port already proved matches the Erlang reference, the
// canonical-CBOR encoding, the field set, and the signing domain are all
// bit-for-bit compatible across three independent implementations, not
// just two.
const (
	vectorPub            = "B966A9812649C3D5542FF54954FE090C43FDA6574FE48A0DD326626CFAD29A83"
	vectorPriv           = "457F45FF5A09E172ED15CB20D6CB26B51AD15ED7308C12D478E8631F9CA03D4F"
	vectorPuzzleEvidence = "09D48C91CB46513ED2580BDCEA87C40DA508D4E50EC3DF2F701AFC55D1C5C0B2"
	vectorFrameID        = "0192E8B0F1A47000A1B2C3D4E5F60718"
	vectorSentAtMs       = int64(1_700_000_000_000)
	vectorSignature      = "CF6959A61A2F4D2046F0124C1DD56A6541265F36A24CB18CA8C45C95031854D6AECE5FB93E2AE7BA6C444A09C7C5DED195B6EB0D1CC8E487CCF6E4F0D903B409"
	vectorEncodedLen     = 375
)

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex fixture %q: %v", s, err)
	}
	return b
}

func TestConnectFrameMatchesTheRustPortByteForByte(t *testing.T) {
	pubBytes := hexBytes(t, vectorPub)
	privSeed := hexBytes(t, vectorPriv)
	puzzleEvidence := hexBytes(t, vectorPuzzleEvidence)
	frameID := hexBytes(t, vectorFrameID)

	id, err := identity.FromSeed(privSeed)
	if err != nil {
		t.Fatalf("identity.FromSeed: %v", err)
	}
	if !bytes.Equal(id.NodeID(), pubBytes) {
		t.Fatalf("derived pubkey doesn't match the fixture: got % X, want % X", id.NodeID(), pubBytes)
	}

	spec := NewConnectSpec(pubBytes, puzzleEvidence)
	unsigned := connectValue(spec, frameID, vectorSentAtMs)
	signed := Sign(unsigned, id)

	sigVal, ok := signed.Get("signature")
	if !ok {
		t.Fatal("signed frame has no signature field")
	}
	sigBytes, _ := sigVal.AsBytes()
	gotSig := hex.EncodeToString(sigBytes)
	wantSig := vectorSignature
	if !equalFoldHex(gotSig, wantSig) {
		t.Errorf("signature diverged from the reference (Rust port, itself checked against\n"+
			"the real Erlang implementation) -- canonical CBOR encoding or the signing\n"+
			"domain/bytes must differ somewhere.\n got  %s\n want %s", gotSig, wantSig)
	}

	encoded, err := Encode(signed)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(encoded) != vectorEncodedLen {
		t.Errorf("encoded length = %d, want %d", len(encoded), vectorEncodedLen)
	}

	// Round-trip: decode what was just built and verify it against the
	// known pubkey, exactly like a receiving station would.
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !decoded.Complete {
		t.Fatal("Decode: incomplete, expected a full frame")
	}
	if decoded.Consumed != len(encoded) {
		t.Errorf("Decode consumed %d, want %d", decoded.Consumed, len(encoded))
	}
	if err := Verify(decoded.Frame, pubBytes); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func equalFoldHex(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'a' && ca <= 'z' {
			ca -= 'a' - 'A'
		}
		if cb >= 'a' && cb <= 'z' {
			cb -= 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
