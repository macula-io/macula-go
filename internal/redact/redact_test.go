package redact

import (
	"strings"
	"testing"
)

type carrier struct {
	Realm  [4]byte
	Name   string
	Token  []byte
	Proofs [][]byte
	Next   *int
}

func TestStructNamesSecretsBySize(t *testing.T) {
	c := carrier{Realm: [4]byte{0xab}, Name: "acme", Token: []byte("secret-token"), Proofs: [][]byte{[]byte("proof-one"), []byte("p2")}}
	got := Struct(&c, "Token", "Proofs")
	want := "{Realm:ab000000 Name:acme Token:<grant, 12 bytes> Proofs:<2 proofs, 11 bytes> Next:nil}"
	if got != want {
		t.Fatalf("Struct = %s\nwant      %s", got, want)
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "proof-one") {
		t.Fatalf("a secret leaked: %s", got)
	}
}

func TestStructOfANonStruct(t *testing.T) {
	if got := Struct(3); got != "<int>" {
		t.Fatalf("Struct(3) = %s", got)
	}
}
