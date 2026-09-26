package ownershipproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

const vectorProcedure = "mcl-graph/learn_link"

var vectorTimestamp = time.UnixMilli(1790000000000)

func vectorFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vector", name))
	if err != nil {
		t.Fatal(err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vectorRealm() [32]byte { return sha256.Sum256([]byte("io.macula")) }

func vectorNonce() (n [NonceSize]byte) {
	for i := range n {
		n[i] = byte(i)
	}
	return n
}

// The fields of the vector, every CBOR type a payload carries. The entries
// are in no particular order: the encoding sorts them.
func vectorFields() cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("subject"), Val: cbor.Text("entity:alpha")},
		{Key: cbor.Text("predicate"), Val: cbor.Text("knows")},
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
}

func vectorIdentity(t *testing.T) [32]byte {
	var id [32]byte
	copy(id[:], vectorFile(t, "identity.hex"))
	return id
}

// The vector is mcl_om 0.32.0's mcl_om_ownership_proof:message/6 for these
// inputs, built by that module on macula 12.11.1 (testdata/vector/README.md).
func TestMessageReproducesMclOmsVector(t *testing.T) {
	got := Message(vectorIdentity(t), vectorRealm(), vectorProcedure, uint64(vectorTimestamp.UnixMilli()),
		vectorNonce(), vectorFields())
	if want := vectorFile(t, "message.hex"); !bytes.Equal(got, want) {
		t.Fatalf("the message differs from mcl_om's vector:\n got %x\nwant %x", got, want)
	}
}

// The vector's signature was made in Erlang by the key whose carried public
// key and node_id are beside it.
func vectorPayload(t *testing.T) cbor.Value {
	t.Helper()
	nonce := vectorNonce()
	proof := Proof{
		V: Version, Timestamp: uint64(vectorTimestamp.UnixMilli()),
		Nonce:     hex.EncodeToString(nonce[:]),
		Signature: hex.EncodeToString(vectorFile(t, "signature.hex")),
		Public:    hex.EncodeToString(vectorFile(t, "public_key.hex")),
	}
	id := vectorIdentity(t)
	entries, _ := vectorFields().AsMap()
	return cbor.Map(append(entries, cbor.MapEntry{Key: cbor.Text(Field),
		Val: AssertedBy{Identity: hex.EncodeToString(id[:]), Proof: proof}.Value()}))
}

func TestAnErlangSignedProofVerifies(t *testing.T) {
	got, err := Verify(vectorPayload(t), vectorProcedure, vectorRealm(), profile.PQHybrid, vectorTimestamp)
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity != vectorIdentity(t) || got.Nonce != vectorNonce() {
		t.Fatalf("verified %x nonce %x, want the vector's", got.Identity, got.Nonce)
	}
}

func withField(t *testing.T, payload cbor.Value, name string, value cbor.Value) cbor.Value {
	t.Helper()
	entries, _ := payload.AsMap()
	out := make([]cbor.MapEntry, 0, len(entries)+1)
	replaced := false
	for _, e := range entries {
		if k, _ := e.Key.AsText(); k == name {
			out = append(out, cbor.MapEntry{Key: e.Key, Val: value})
			replaced = true
			continue
		}
		out = append(out, e)
	}
	if !replaced {
		out = append(out, cbor.MapEntry{Key: cbor.Text(name), Val: value})
	}
	return cbor.Map(out)
}

func without(t *testing.T, payload cbor.Value, name string) cbor.Value {
	t.Helper()
	entries, _ := payload.AsMap()
	out := make([]cbor.MapEntry, 0, len(entries))
	for _, e := range entries {
		if k, _ := e.Key.AsText(); k != name {
			out = append(out, e)
		}
	}
	return cbor.Map(out)
}

func TestEveryAlterationOfTheErlangProofIsRefused(t *testing.T) {
	payload := vectorPayload(t)
	cases := map[string]struct {
		payload   cbor.Value
		procedure string
		realm     [32]byte
		now       time.Time
		want      error
	}{
		"a changed field":         {withField(t, payload, "weight", cbor.Int(4)), vectorProcedure, vectorRealm(), vectorTimestamp, ErrBadSignature},
		"an added field":          {withField(t, payload, "extra", cbor.Text("x")), vectorProcedure, vectorRealm(), vectorTimestamp, ErrBadSignature},
		"a dropped field":         {without(t, payload, "note"), vectorProcedure, vectorRealm(), vectorTimestamp, ErrBadSignature},
		"text changed to bytes":   {withField(t, payload, "subject", cbor.Bytes([]byte("entity:alpha"))), vectorProcedure, vectorRealm(), vectorTimestamp, ErrBadSignature},
		"an integer to a float":   {withField(t, payload, "weight", cbor.Float(3)), vectorProcedure, vectorRealm(), vectorTimestamp, ErrBadSignature},
		"another procedure":       {payload, "mcl-graph/forget_link", vectorRealm(), vectorTimestamp, ErrBadSignature},
		"another realm":           {payload, vectorProcedure, sha256.Sum256([]byte("elsewhere")), vectorTimestamp, ErrBadSignature},
		"a stale timestamp":       {payload, vectorProcedure, vectorRealm(), vectorTimestamp.Add(MaxSkew + time.Millisecond), ErrStaleProof},
		"a timestamp from ahead":  {payload, vectorProcedure, vectorRealm(), vectorTimestamp.Add(-MaxSkew - time.Millisecond), ErrStaleProof},
		"no asserted_by":          {without(t, payload, Field), vectorProcedure, vectorRealm(), vectorTimestamp, ErrMissingProof},
		"under the other profile": {payload, vectorProcedure, vectorRealm(), vectorTimestamp, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := profile.PQHybrid
			if name == "under the other profile" {
				p, c.want = profile.PQPure, ErrBadSignature
			}
			if _, err := Verify(c.payload, c.procedure, c.realm, p, c.now); !errors.Is(err, c.want) {
				t.Fatalf("Verify: %v, want %v", err, c.want)
			}
		})
	}
}

func assertedBy(t *testing.T, payload cbor.Value) (cbor.Value, cbor.Value) {
	t.Helper()
	block, ok := payload.Get(Field)
	if !ok {
		t.Fatal("no asserted_by")
	}
	proof, ok := block.Get("proof")
	if !ok {
		t.Fatal("no proof")
	}
	return block, proof
}

func TestAProofWhoseKeyDoesNotDeriveTheIdentityIsRefused(t *testing.T) {
	payload := vectorPayload(t)
	block, _ := assertedBy(t, payload)
	other := strings.Repeat("11", 32)
	entries, _ := block.AsMap()
	for i, e := range entries {
		if k, _ := e.Key.AsText(); k == "identity" {
			entries[i].Val = cbor.Text(other)
		}
	}
	payload = withField(t, payload, Field, cbor.Map(entries))
	if _, err := Verify(payload, vectorProcedure, vectorRealm(), profile.PQHybrid, vectorTimestamp); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("Verify: %v, want ErrBadSignature", err)
	}
}

func TestAVersionOtherThanTwoIsUnsupported(t *testing.T) {
	for _, v := range []cbor.Value{cbor.Int(1), cbor.Int(3), cbor.Text("2")} {
		payload := vectorPayload(t)
		block, proof := assertedBy(t, payload)
		proof = withField(t, proof, "v", v)
		block = withField(t, block, "proof", proof)
		payload = withField(t, payload, Field, block)
		if _, err := Verify(payload, vectorProcedure, vectorRealm(), profile.PQHybrid, vectorTimestamp); !errors.Is(err, ErrUnsupportedVersion) {
			t.Fatalf("v %v: %v, want ErrUnsupportedVersion", v, err)
		}
	}
}

func TestMalformedBlocksAreRefusedAsMclOmRefusesThem(t *testing.T) {
	payload := vectorPayload(t)
	block, proof := assertedBy(t, payload)
	cases := map[string]struct {
		payload cbor.Value
		want    error
	}{
		"asserted_by not a map":  {withField(t, payload, Field, cbor.Text("x")), ErrMissingProof},
		"identity not hex":       {withField(t, payload, Field, withField(t, block, "identity", cbor.Text(strings.Repeat("zz", 32)))), ErrInvalidIdentity},
		"identity short":         {withField(t, payload, Field, withField(t, block, "identity", cbor.Text("abcd"))), ErrInvalidIdentity},
		"proof missing":          {withField(t, payload, Field, without(t, block, "proof")), ErrMissingProof},
		"timestamp missing":      {withField(t, payload, Field, withField(t, block, "proof", without(t, proof, "timestamp"))), ErrMissingProof},
		"timestamp not a number": {withField(t, payload, Field, withField(t, block, "proof", withField(t, proof, "timestamp", cbor.Text("1")))), ErrMissingProof},
		"nonce short":            {withField(t, payload, Field, withField(t, block, "proof", withField(t, proof, "nonce", cbor.Text("00ff")))), ErrBadSignature},
		"signature not hex":      {withField(t, payload, Field, withField(t, block, "proof", withField(t, proof, "signature", cbor.Text("q")))), ErrBadSignature},
		"public missing":         {withField(t, payload, Field, withField(t, block, "proof", without(t, proof, "public"))), ErrBadSignature},
		"payload not a map":      {cbor.List(nil), ErrMissingProof},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Verify(c.payload, vectorProcedure, vectorRealm(), profile.PQHybrid, vectorTimestamp); !errors.Is(err, c.want) {
				t.Fatalf("Verify: %v, want %v", err, c.want)
			}
		})
	}
}

// mcl_om accepts a timestamp exactly MaxSkew away (=<), and refuses one a
// millisecond further.
func TestTheSkewBoundaryIsInclusive(t *testing.T) {
	payload := vectorPayload(t)
	for _, now := range []time.Time{vectorTimestamp.Add(MaxSkew), vectorTimestamp.Add(-MaxSkew)} {
		if _, err := Verify(payload, vectorProcedure, vectorRealm(), profile.PQHybrid, now); err != nil {
			t.Fatalf("at %v from the timestamp: %v", now.Sub(vectorTimestamp), err)
		}
	}
}

// macula_station_link:with_caller/2 removes a caller-sent text "caller"
// before the handler sees the payload, so it is not a signed field: signing
// it would sign bytes mcl_om can never rebuild.
func TestACallerFieldIsNotSigned(t *testing.T) {
	key, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQPure)
	if err != nil {
		t.Fatal(err)
	}
	withCaller := withField(t, vectorFields(), "caller", cbor.Text("claimed by the sender"))
	signed, err := Attach(withCaller, key, vectorRealm(), vectorProcedure)
	if err != nil {
		t.Fatal(err)
	}
	// As a handler receives it: the sender's caller removed (and the
	// station's own merged in, which mcl_om strips as an atom).
	delivered := without(t, signed, "caller")
	if _, err := Verify(delivered, vectorProcedure, vectorRealm(), profile.PQPure, time.Now()); err != nil {
		t.Fatalf("the delivered payload: %v", err)
	}
	fields, err := Fields(withCaller)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cbor.Encode(fields), cbor.Encode(vectorFields())) {
		t.Fatalf("Fields kept the caller: %v", fields)
	}
}

func TestSignSignsTheFieldsOfWhateverItIsGiven(t *testing.T) {
	key, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQPure)
	if err != nil {
		t.Fatal(err)
	}
	stale := withField(t, vectorFields(), Field, cbor.Text("an earlier block"))
	block, err := Sign(key, vectorRealm(), vectorProcedure, stale)
	if err != nil {
		t.Fatal(err)
	}
	payload := withField(t, vectorFields(), Field, block.Value())
	if _, err := Verify(payload, vectorProcedure, vectorRealm(), profile.PQPure, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// The payload exactly as mcl_om's make/6 and macula's frame put it on the
// wire: the block's hex as byte strings, keys from atoms.
func TestAnErlangMadePayloadFromTheWireVerifies(t *testing.T) {
	wire := vectorFile(t, "erlang_payload.hex")
	payload, err := cbor.Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := payload.Get(Field)
	proof, _ := block.Get("proof")
	sig, _ := proof.Get("signature")
	if sig.Kind() != cbor.KindBytes {
		t.Fatalf("the Erlang block's signature is %v on the wire, want a byte string", sig.Kind())
	}
	ts, _ := proof.Get("timestamp")
	ms, _ := ts.AsInt64()
	got, err := Verify(payload, vectorProcedure, vectorRealm(), profile.PQHybrid, time.UnixMilli(ms))
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity != vectorIdentity(t) {
		t.Fatalf("verified %x, want the vector's identity", got.Identity)
	}
}

func TestAttachSignsWhatVerifyReads(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			key, err := identity.GenerateKey(identity.PurposeIdentity, p)
			if err != nil {
				t.Fatal(err)
			}
			signed, err := Attach(vectorFields(), key, vectorRealm(), vectorProcedure)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Verify(signed, vectorProcedure, vectorRealm(), p, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if id, _ := key.NodeID(); got.Identity != id {
				t.Fatalf("verified identity %x, want the key's %x", got.Identity, id)
			}
			if _, err := Verify(withField(t, signed, "weight", cbor.Int(4)), vectorProcedure, vectorRealm(), p, time.Now()); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("a changed field: %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestAttachReplacesAnEarlierProof(t *testing.T) {
	key, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQPure)
	if err != nil {
		t.Fatal(err)
	}
	once, err := Attach(vectorFields(), key, vectorRealm(), vectorProcedure)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := Attach(once, key, vectorRealm(), vectorProcedure)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := twice.AsMap()
	count := 0
	for _, e := range entries {
		if k, _ := e.Key.AsText(); k == Field {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d asserted_by entries, want 1", count)
	}
	if _, err := Verify(twice, vectorProcedure, vectorRealm(), profile.PQPure, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestAttachRefusesAPayloadThatIsNotAMap(t *testing.T) {
	key, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQPure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Attach(cbor.Text("x"), key, vectorRealm(), vectorProcedure); !errors.Is(err, ErrNotAMap) {
		t.Fatalf("Attach: %v, want ErrNotAMap", err)
	}
}
