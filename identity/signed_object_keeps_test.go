package identity

import (
	"bytes"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// A verified object keeps what was verified. A caller that verifies bytes it
// still holds, a key and a tbs behind a cbor.Bytes it built, or the key it
// passes for a held object, and writes into them afterwards, changes neither the
// verified key nor the verified tbs.
func TestAVerifiedObjectKeepsTheKeyAndTBSItVerified(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		object := signedTestObject(t, keys.identity)
		key, tbs := bytes.Clone(object.Key), bytes.Clone(object.TBS)
		verified, err := VerifyObject(objectLabel, Object{Key: key, TBS: tbs, Signature: object.Signature}.Value(), p)
		if err != nil {
			t.Fatalf("VerifyObject: %v", err)
		}
		clear(key)
		clear(tbs)
		if !bytes.Equal(verified.Key, object.Key) || !bytes.Equal(verified.TBS, object.TBS) {
			t.Error("writing into the buffers of a verified object changed its verified key or tbs")
		}

		held := heldTestObject(t, keys.identity)
		heldKey, heldTBS := bytes.Clone(keys.identity.PublicKey()), bytes.Clone(held.TBS)
		verifiedHeld, err := VerifyHeldObject(objectLabel, HeldObject{TBS: heldTBS, Signature: held.Signature}.Value(), heldKey, p)
		if err != nil {
			t.Fatalf("VerifyHeldObject: %v", err)
		}
		clear(heldKey)
		clear(heldTBS)
		if !bytes.Equal(verifiedHeld.Key, keys.identity.PublicKey()) || !bytes.Equal(verifiedHeld.TBS, held.TBS) {
			t.Error("writing into the held key or the held object's tbs buffer changed its verified key or tbs")
		}
	})
}
