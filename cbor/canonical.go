package cbor

import "fmt"

// Canonical reports whether every map in v holds its entries in the order
// Encode writes them: by their encoded key bytes, ascending. Decode keeps a
// map's keys in the order they arrived, and the decoding rule accepts any
// order, so a value read from the wire need not be canonical; a value this
// package encoded is. An error names the first map that is out of order.
func Canonical(v Value) error {
	switch v.Kind() {
	case KindMap:
		return canonicalMapValue(v)
	case KindList:
		return canonicalListValue(v)
	}
	return nil
}

func canonicalMapValue(v Value) error {
	entries, _ := v.AsMap()
	if err := canonicalMap(entries); err != nil {
		return err
	}
	for _, e := range entries {
		if err := Canonical(e.Key); err != nil {
			return err
		}
		if err := Canonical(e.Val); err != nil {
			return err
		}
	}
	return nil
}

func canonicalListValue(v Value) error {
	items, _ := v.AsList()
	for _, item := range items {
		if err := Canonical(item); err != nil {
			return err
		}
	}
	return nil
}

func canonicalMap(entries []MapEntry) error {
	for i := 1; i < len(entries); i++ {
		prev, cur := Encode(entries[i-1].Key), Encode(entries[i].Key)
		if lessBytes(cur, prev) {
			return fmt.Errorf("cbor: key %x follows %x", cur, prev)
		}
	}
	return nil
}
