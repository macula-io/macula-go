package identity

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_signed_object_tests at merge-11.0.0: a
// signature covers Label || 0x00 || SHA-384(key as carried) || tbs, and a
// verifier reads an object in order: its shape, the carried key, the signature
// over tbs as received, tbs under the decoding rule, then alg.

const (
	objectLabel      = "MACULA-PQ-RECORD-V1"
	otherObjectLabel = "MACULA-PQ-REPLY-V1"
)

// objectTestFields are the fields the tests sign: a type and a payload map.
func objectTestFields() []cbor.MapEntry {
	return []cbor.MapEntry{
		{Key: cbor.Text("type"), Val: cbor.Uint64(1)},
		{Key: cbor.Text("payload"), Val: cbor.Map([]cbor.MapEntry{textEntry("name", "n1")})},
	}
}

// objectExpectedFields is the map a verifier reads back: the signed fields and
// alg for profile p, in the deterministic encoding.
func objectExpectedFields(p profile.Profile) []byte {
	return cbor.Encode(cbor.Map(append(objectTestFields(), textEntry("alg", sigAlg(p)))))
}

func signedTestObject(t *testing.T, key *NodeKey) Object {
	t.Helper()
	object, err := SignObject(objectLabel, objectTestFields(), key)
	if err != nil {
		t.Fatalf("SignObject: %v", err)
	}
	return object
}

func heldTestObject(t *testing.T, key *NodeKey) HeldObject {
	t.Helper()
	held, err := SignHeldObject(objectLabel, objectTestFields(), key)
	if err != nil {
		t.Fatalf("SignHeldObject: %v", err)
	}
	return held
}

// rawObject is an object signed by key over tbs bytes built by hand.
func rawObject(t *testing.T, key *NodeKey, tbs []byte) cbor.Value {
	t.Helper()
	carried := key.PublicKey()
	signature, err := key.Sign(objectSignedBytes(objectLabel, carried, tbs))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return Object{Key: carried, TBS: tbs, Signature: signature}.Value()
}

// objectWith is the map v with name set to value, replacing any value it held.
func objectWith(v cbor.Value, name string, value cbor.Value) cbor.Value {
	return cbor.Map(append(objectWithoutEntries(v, name), cbor.MapEntry{Key: cbor.Text(name), Val: value}))
}

// objectWithout is the map v without name.
func objectWithout(v cbor.Value, name string) cbor.Value {
	return cbor.Map(objectWithoutEntries(v, name))
}

func objectWithoutEntries(v cbor.Value, name string) []cbor.MapEntry {
	entries, _ := v.AsMap()
	kept := make([]cbor.MapEntry, 0, len(entries))
	for _, e := range entries {
		if key, _ := e.Key.AsText(); key != name {
			kept = append(kept, e)
		}
	}
	return kept
}

func objectCBORText(s string) []byte { return cbor.Encode(cbor.Text(s)) }

// A signed object carries its signer's key as carried, and verifies to that
// key, its tbs bytes as received and its fields with alg. Its signature covers
// the label, a zero byte, the SHA-384 of the key and the tbs.
func TestASignedObjectVerifiesToItsKeyTBSAndFields(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		object := signedTestObject(t, keys.identity)
		if !bytes.Equal(object.Key, keys.identity.PublicKey()) {
			t.Error("the object does not carry the signer's key as carried")
		}
		verified, err := VerifyObject(objectLabel, object.Value(), p)
		if err != nil {
			t.Fatalf("VerifyObject: %v", err)
		}
		if !bytes.Equal(verified.Key, object.Key) || !bytes.Equal(verified.TBS, object.TBS) {
			t.Error("the verified key or tbs differs from the object's")
		}
		if got := cbor.Encode(verified.Fields); !bytes.Equal(got, objectExpectedFields(p)) {
			t.Error("the verified fields are not the signed fields with alg")
		}
		keyHash := sha512.Sum384(object.Key)
		signed := append(append(append([]byte(objectLabel), 0), keyHash[:]...), object.TBS...)
		if !Verify(signed, object.Signature, object.Key, p) {
			t.Error("the signature does not cover label, a zero byte, the key's SHA-384 and tbs")
		}
	})
}

// A signed object whose signature cannot hold, under another label, with a
// changed signature or tbs, or with another valid key, is refused as a
// signature that does not verify.
func TestASignedObjectWhoseSignatureCannotHoldIsRefused(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		object := signedTestObject(t, keys.identity)
		v := object.Value()
		cases := []struct {
			name  string
			label string
			value cbor.Value
		}{
			{"another label", otherObjectLabel, v},
			{"a changed signature byte", objectLabel, objectWith(v, "signature", cbor.Bytes(flippedAt(object.Signature, 10)))},
			{"a changed tbs byte", objectLabel, objectWith(v, "tbs", cbor.Bytes(flippedAt(object.TBS, 10)))},
			{"another valid key", objectLabel, objectWith(v, "key", cbor.Bytes(keys.connect.PublicKey()))},
		}
		for _, c := range cases {
			_, err := VerifyObject(c.label, c.value, p)
			checkRefusal(t, c.name, err, ErrObjectSignatureInvalid)
		}
	})
}

// A signed object that is not exactly key, tbs and signature, each a byte
// string, with the key in the verifier's profile's carried form, is malformed.
func TestASignedObjectOfTheWrongShapeIsMalformed(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		object := signedTestObject(t, keys.identity)
		v := object.Value()
		cases := []struct {
			name    string
			value   cbor.Value
			profile profile.Profile
		}{
			{"a key not in carried form", objectWith(v, "key", cbor.Bytes(object.Key[:100])), p},
			{"an extra field", objectWith(v, "extra", cbor.Bytes(nil)), p},
			{"no signature", objectWithout(v, "signature"), p},
			{"a tbs that is not bytes", objectWith(v, "tbs", cbor.Text("x")), p},
			{"no key", objectWithout(v, "key"), p},
			{"the object under the other profile", v, otherProfile(p)},
			{"an object that holds no key", heldTestObject(t, keys.identity).Value(), p},
		}
		for _, c := range cases {
			_, err := VerifyObject(objectLabel, c.value, c.profile)
			checkRefusal(t, c.name, err, ErrObjectMalformed)
		}
	})
}

// An object whose verifier holds the key is only tbs and signature. It verifies
// with the held key and no other, since the key's hash is signed, and an object
// that carries a key is malformed to a held verifier.
func TestAHeldObjectVerifiesOnlyWithTheHeldKey(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		held := heldTestObject(t, keys.identity)
		if entries, _ := held.Value().AsMap(); len(entries) != 2 {
			t.Errorf("a held object has %d fields, want tbs and signature", len(entries))
		}
		verified, err := VerifyHeldObject(objectLabel, held.Value(), keys.identity.PublicKey(), p)
		if err != nil {
			t.Fatalf("VerifyHeldObject: %v", err)
		}
		if !bytes.Equal(verified.TBS, held.TBS) || !bytes.Equal(cbor.Encode(verified.Fields), objectExpectedFields(p)) {
			t.Error("the held object verifies to another tbs or fields")
		}
		_, err = VerifyHeldObject(objectLabel, held.Value(), keys.connect.PublicKey(), p)
		checkRefusal(t, "a held object with another key", err, ErrObjectSignatureInvalid)
		carrying := objectWith(held.Value(), "key", cbor.Bytes(keys.identity.PublicKey()))
		_, err = VerifyHeldObject(objectLabel, carrying, keys.identity.PublicKey(), p)
		checkRefusal(t, "an object that carries a key, to a held verifier", err, ErrObjectMalformed)
	})
}

// tbs is verified as the bytes received, in any key order and length width,
// and only then decoded under the decoding rule: a map naming alg as text,
// whose alg is the verifier's profile's.
func TestAnObjectTBSIsVerifiedAsReceivedThenDecodedStrictly(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		alg := append([]byte{0x63}, append([]byte("alg"), objectCBORText(sigAlg(p))...)...)
		unordered := append(append([]byte{0xa2, 0x78, 4}, []byte("type")...), 0x01)
		unordered = append(unordered, alg...)
		verified, err := VerifyObject(objectLabel, rawObject(t, keys.identity, unordered), p)
		if err != nil {
			t.Fatalf("a tbs with its keys out of order and a one-byte length width: %v", err)
		}
		if typ, _ := verified.Fields.Get("type"); typ.Kind() != cbor.KindUInt || !bytes.Equal(verified.TBS, unordered) {
			t.Error("the out-of-order tbs verifies to other bytes or fields")
		}

		other := append([]byte{0x63}, append([]byte("alg"), objectCBORText(sigAlg(otherProfile(p)))...)...)
		cases := []struct {
			name string
			tbs  []byte
			want error
		}{
			{"a tbs that is not a map", []byte{0x82, 0x01, 0x02}, ErrObjectMalformed},
			{"a tbs with a duplicate key", append(append([]byte{0xa2}, alg...), alg...), ErrObjectMalformed},
			{"a tbs with trailing bytes", append(append([]byte{0xa1}, alg...), 0x00), ErrObjectMalformed},
			{"a tbs without alg", append([]byte{0xa1, 0x64}, append([]byte("type"), 0x01)...), ErrObjectMalformed},
			{"alg naming the other profile", append([]byte{0xa1}, other...), ErrObjectAlgMismatch},
		}
		for _, c := range cases {
			_, err := VerifyObject(objectLabel, rawObject(t, keys.identity, c.tbs), p)
			checkRefusal(t, c.name, err, c.want)
		}
	})
}

// A signed object round-trips through its wire form, and a decoder takes its
// keys in any order but refuses an extra key, a value that is not bytes,
// trailing bytes and bytes that are not CBOR.
func TestASignedObjectRoundTripsThroughItsWireForm(t *testing.T) {
	keys := keysFor(t, profile.PQPure)
	object := signedTestObject(t, keys.identity)
	held := heldTestObject(t, keys.identity)

	if decoded, err := DecodeObject(cbor.Encode(object.Value())); err != nil || !sameObject(decoded, object) {
		t.Errorf("a carried object round trip: %v", err)
	}
	if decoded, err := DecodeHeldObject(cbor.Encode(held.Value())); err != nil ||
		!bytes.Equal(decoded.TBS, held.TBS) || !bytes.Equal(decoded.Signature, held.Signature) {
		t.Errorf("a held object round trip: %v", err)
	}

	reordered := append([]byte{0xa3}, objectCBORText("signature")...)
	reordered = append(reordered, cbor.Encode(cbor.Bytes(object.Signature))...)
	reordered = append(reordered, objectCBORText("tbs")...)
	reordered = append(reordered, cbor.Encode(cbor.Bytes(object.TBS))...)
	reordered = append(reordered, objectCBORText("key")...)
	reordered = append(reordered, cbor.Encode(cbor.Bytes(object.Key))...)
	if decoded, err := DecodeObject(reordered); err != nil || !sameObject(decoded, object) {
		t.Errorf("an object with its keys in another order: %v", err)
	}

	_, err := DecodeObject(cbor.Encode(objectWith(object.Value(), "extra", cbor.Bytes(nil))))
	checkRefusal(t, "an object with an extra key", err, ErrObjectMalformed)
	_, err = DecodeHeldObject(cbor.Encode(objectWith(held.Value(), "tbs", cbor.Text("x"))))
	checkRefusal(t, "a held object whose tbs is text", err, ErrObjectMalformed)
	_, err = DecodeHeldObject(append(cbor.Encode(held.Value()), 0x00))
	checkRefusal(t, "a held object with trailing bytes", err, ErrObjectMalformed)
	_, err = DecodeObject([]byte{0xff})
	checkRefusal(t, "bytes that are not CBOR", err, ErrObjectMalformed)
}

// A field to sign needs a text key of its own, and SignObject sets alg itself.
func TestSignObjectRefusesFieldsWithoutTextKeysOfTheirOwn(t *testing.T) {
	key := sharedKey(t, pureIdentityKey)
	if _, err := SignObject(objectLabel, []cbor.MapEntry{{Key: cbor.Uint64(1), Val: cbor.Null()}}, key); err == nil {
		t.Error("SignObject with an integer field key succeeded, want an error")
	}
	twice := []cbor.MapEntry{textEntry("name", "a"), textEntry("name", "b")}
	if _, err := SignObject(objectLabel, twice, key); err == nil {
		t.Error("SignObject with two fields named alike succeeded, want an error")
	}
	own := append(objectTestFields(), textEntry("alg", "classical"))
	object, err := SignObject(objectLabel, own, key)
	if err != nil {
		t.Fatalf("SignObject with an alg field: %v", err)
	}
	verified, err := VerifyObject(objectLabel, object.Value(), profile.PQPure)
	if err != nil || !bytes.Equal(cbor.Encode(verified.Fields), objectExpectedFields(profile.PQPure)) {
		t.Errorf("an alg the fields held was not replaced by the profile's: %v", err)
	}
	if _, err := SignObject(objectLabel, objectTestFields(), &NodeKey{}); !errors.Is(err, ErrEmptyNodeKey) {
		t.Errorf("SignObject with an empty key = %v, want ErrEmptyNodeKey", err)
	}
}

func sameObject(a, b Object) bool {
	return bytes.Equal(a.Key, b.Key) && bytes.Equal(a.TBS, b.TBS) && bytes.Equal(a.Signature, b.Signature)
}
