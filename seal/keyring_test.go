package seal

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/profile"
)

// A provider's KEM keys (macula 13, amendment A1): one current key, rotated
// every 24 hours, a replaced key still opening for 30 minutes and then gone,
// in memory only.
func TestAKeyringRotatesAndForgets(t *testing.T) {
	now := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	ring, err := NewKeyring(profile.PQPure, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	first := ring.Current()
	firstID := KeyID(first.PublicKey().Carried())
	if again := ring.Current(); KeyID(again.PublicKey().Carried()) != firstID {
		t.Fatal("the current key changed before its rotation")
	}

	now = now.Add(KeyLifetime - time.Second)
	if KeyID(ring.Current().PublicKey().Carried()) != firstID {
		t.Fatal("a key rotated before its lifetime")
	}
	now = now.Add(time.Second)
	second := ring.Current()
	secondID := KeyID(second.PublicKey().Carried())
	if secondID == firstID {
		t.Fatal("a key outlived its lifetime")
	}
	if _, held := ring.Find(firstID); !held {
		t.Fatal("a replaced key stopped opening at once")
	}
	now = now.Add(RetiredKeyKept - time.Second)
	if _, held := ring.Find(firstID); !held {
		t.Fatal("a replaced key went before its 30 minutes")
	}
	now = now.Add(time.Second)
	if _, held := ring.Find(firstID); held {
		t.Fatal("a replaced key outlived its 30 minutes")
	}
	if key, held := ring.Find(secondID); !held || KeyID(key.PublicKey().Carried()) != secondID {
		t.Fatal("the current key is not found by its id")
	}
	if _, held := ring.Find([KeyIDSize]byte{1}); held {
		t.Fatal("a key id the ring never held was found")
	}
}

func TestAKeyringIsOfItsProfile(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		ring, err := NewKeyring(p, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		if got := len(ring.Current().PublicKey().Carried()); got != CarriedSize(p) {
			t.Errorf("%s: a key of %d bytes, want %d", p, got, CarriedSize(p))
		}
	}
}
