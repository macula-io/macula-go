// Command goownershipproof writes a payload macula-go signed with an ownership
// proof v2, for erlang_ownership_proof.escript to verify with mcl_om's own
// mcl_om_ownership_proof after delivering it through macula's frame codec.
// The key is made for the run and never saved.
//
//	goownershipproof <out file>
//
// The file holds three lines: the payload's CBOR as hex, the realm id as hex,
// and the procedure. The payload's fields carry every CBOR type a payload can,
// and a caller added after signing, which the station removes.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/ownershipproof"
	"github.com/macula-io/macula-go/profile"
)

const procedure = "mcl-graph/learn_link"

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: goownershipproof <out file>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "goownershipproof:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	key, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQHybrid)
	if err != nil {
		return err
	}
	realm := sha256.Sum256([]byte("io.macula"))
	fields := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("subject"), Val: cbor.Text("entity:alpha")},
		{Key: cbor.Text("object"), Val: cbor.Text("entity:beta")},
		{Key: cbor.Text("confidence"), Val: cbor.Float(0.75)},
		{Key: cbor.Text("weight"), Val: cbor.Int(3)},
		{Key: cbor.Text("offset"), Val: cbor.Int(-7)},
		{Key: cbor.Text("digest"), Val: cbor.Bytes([]byte{1, 2, 3})},
		{Key: cbor.Text("note"), Val: cbor.Null()},
		{Key: cbor.Text("tags"), Val: cbor.List([]cbor.Value{cbor.Text("a"), cbor.Text("b")})},
		{Key: cbor.Text("metadata"), Val: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("source"), Val: cbor.Text("field-notes")},
			{Key: cbor.Text("page"), Val: cbor.Int(12)},
		})},
	})
	signed, err := ownershipproof.Attach(fields, key, realm, procedure)
	if err != nil {
		return err
	}
	// A sender that adds a caller after signing: the station removes it before
	// the handler reads the payload, so the proof still verifies.
	entries, _ := signed.AsMap()
	payload := cbor.Map(append(entries, cbor.MapEntry{Key: cbor.Text("caller"), Val: cbor.Text("claimed by the sender")}))
	body := fmt.Sprintf("%s\n%s\n%s\n", hex.EncodeToString(cbor.Encode(payload)), hex.EncodeToString(realm[:]), procedure)
	return os.WriteFile(out, []byte(body), 0o644)
}
