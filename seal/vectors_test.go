package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// The vectors are macula's test/vectors/e2e_seal_v1.json, copied by
// scripts/interop/copy_e2e_seal_vectors.sh. A Rust generator made them and
// macula's Erlang macula_seal reproduces them; every test here holds
// macula-go to the same bytes, the recipient's side byte for byte, as
// testdata/E2E_SEAL_V1.md's "What an SDK must pass" asks.

type hexBytes []byte

func (h *hexBytes) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	*h = b
	return err
}

type vectorRecipient struct {
	KeyAsCarried hexBytes `json:"key_as_carried"`
	KeyHash      hexBytes `json:"key_hash"`
	KeyID        hexBytes `json:"key_id"`
	MLKEMDk      hexBytes `json:"mlkem_dk"`
	MLKEMEk      hexBytes `json:"mlkem_ek"`
	MLKEMSeed    hexBytes `json:"mlkem_seed"`
	P384Priv     hexBytes `json:"p384_priv"`
	P384Pub      hexBytes `json:"p384_pub"`
}

type vectorSealed struct {
	Aad   hexBytes `json:"aad"`
	Ct    hexBytes `json:"ct"`
	Nonce hexBytes `json:"nonce"`
	Plain hexBytes `json:"plain"`
}

type vectorReply struct {
	vectorSealed
	FrameType   string   `json:"frame_type"`
	RequestHash hexBytes `json:"request_hash"`
	RespondedBy hexBytes `json:"responded_by"`
}

type vectorFrame struct {
	vectorSealed
	Direction uint8  `json:"direction"`
	FrameType string `json:"frame_type"`
	Seq       uint64 `json:"seq"`
}

type vectorCall struct {
	Profile   string   `json:"profile"`
	FrameType string   `json:"frame_type"`
	Realm     hexBytes `json:"realm"`
	Procedure string   `json:"procedure"`
	Caller    hexBytes `json:"caller"`
	Target    hexBytes `json:"target"`
	RequestID hexBytes `json:"request_id"`
	Deadline  uint64   `json:"deadline"`
	KeyID     hexBytes `json:"key_id"`

	KemCt   hexBytes `json:"kem_ct"`
	MLKEMCt hexBytes `json:"mlkem_ct"`
	EphPub  hexBytes `json:"eph_pub"`
	EphPriv hexBytes `json:"eph_priv"`
	EncapsM hexBytes `json:"encaps_m"`
	SsMLKEM hexBytes `json:"ss_mlkem"`
	SsECDH  hexBytes `json:"ss_ecdh"`
	Ikm     hexBytes `json:"ikm"`
	Ss      hexBytes `json:"ss"`

	KReq hexBytes `json:"k_req"`
	KRep hexBytes `json:"k_rep"`
	KC2P hexBytes `json:"k_c2p"`
	KP2C hexBytes `json:"k_p2c"`

	Request vectorSealed  `json:"request"`
	Reply   *vectorReply  `json:"reply"`
	Frames  []vectorFrame `json:"frames"`
}

type vectorEvent struct {
	vectorSealed
	KG          hexBytes `json:"k_g"`
	PrkG        hexBytes `json:"prk_g"`
	KPub        hexBytes `json:"k_pub"`
	KeyID       hexBytes `json:"key_id"`
	Realm       hexBytes `json:"realm"`
	Topic       string   `json:"topic"`
	Publisher   hexBytes `json:"publisher"`
	Seq         uint64   `json:"seq"`
	PublishedAt uint64   `json:"published_at"`
}

type vectorRefusal struct {
	Profile      string   `json:"profile"`
	MLKEMSeed    hexBytes `json:"mlkem_seed"`
	MLKEMDk      hexBytes `json:"mlkem_dk"`
	P384Priv     hexBytes `json:"p384_priv"`
	P384Pub      hexBytes `json:"p384_pub"`
	KeyAsCarried hexBytes `json:"key_as_carried"`
	KemCt        hexBytes `json:"kem_ct"`
	Expect       string   `json:"expect"`
	Why          string   `json:"why"`
}

type vectorFile struct {
	Scheme     int                        `json:"scheme"`
	Recipients map[string]vectorRecipient `json:"recipients"`
	Calls      []vectorCall               `json:"calls"`
	Events     []vectorEvent              `json:"events"`
	Refusals   []vectorRefusal            `json:"refusals"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "e2e_seal_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Scheme != Scheme {
		t.Fatalf("vectors are scheme %d, this package seals scheme %d", v.Scheme, Scheme)
	}
	if len(v.Calls) == 0 || len(v.Events) == 0 || len(v.Refusals) == 0 {
		t.Fatalf("vectors hold %d calls, %d events and %d refusals", len(v.Calls), len(v.Events), len(v.Refusals))
	}
	return v
}

// recipientKey loads a vector's recipient private key from its ML-KEM seed
// and P-384 scalar, and checks the ML-KEM key it expands to is the vector's.
func recipientKey(t *testing.T, name string, r vectorRecipient) *PrivateKey {
	t.Helper()
	key, err := NewPrivateKey(profile.Profile(name), r.MLKEMSeed, r.P384Priv)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	equal(t, name+" mlkem_ek", key.PublicKey().MLKEM.Bytes(), r.MLKEMEk)
	if name == string(profile.PQHybrid) {
		equal(t, name+" p384_pub", key.PublicKey().P384.Bytes(), r.P384Pub)
	}
	return key
}

func equal(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %x\nwant %x", what, got, want)
	}
}

func id32(t *testing.T, b []byte) [32]byte {
	t.Helper()
	if len(b) != 32 {
		t.Fatalf("%d bytes where 32 are due", len(b))
	}
	return [32]byte(b)
}

func key32(t *testing.T, b []byte) [32]byte { return id32(t, b) }

func nonce12(t *testing.T, b []byte) [12]byte {
	t.Helper()
	if len(b) != NonceSize {
		t.Fatalf("%d-byte nonce", len(b))
	}
	return [12]byte(b)
}

// checkSealed seals the vector's plaintext and compares it to its ct, opens
// the ct back to the plaintext, and checks one flipped bit of the ct, the
// AAD or the nonce is refused.
func checkSealed(t *testing.T, what string, key [32]byte, s vectorSealed) {
	t.Helper()
	nonce := nonce12(t, s.Nonce)
	equal(t, what+" ct", Seal(key, nonce, s.Aad, s.Plain), s.Ct)
	plain, err := Open(key, nonce, s.Aad, s.Ct)
	if err != nil {
		t.Errorf("%s: open: %v", what, err)
	}
	equal(t, what+" opened", plain, s.Plain)

	flipped := func(b []byte, i int) []byte {
		c := bytes.Clone(b)
		c[i] ^= 1
		return c
	}
	for name, attempt := range map[string]func() ([]byte, error){
		"a flipped ct bit":    func() ([]byte, error) { return Open(key, nonce, s.Aad, flipped(s.Ct, 0)) },
		"a flipped tag bit":   func() ([]byte, error) { return Open(key, nonce, s.Aad, flipped(s.Ct, len(s.Ct)-1)) },
		"a flipped AAD bit":   func() ([]byte, error) { return Open(key, nonce, flipped(s.Aad, len(s.Aad)-1), s.Ct) },
		"a flipped nonce bit": func() ([]byte, error) { return Open(key, [12]byte(flipped(nonce[:], 11)), s.Aad, s.Ct) },
	} {
		if _, err := attempt(); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: open with %s: %v, want ErrRefused", what, name, err)
		}
	}
}

func TestVectorRecipientKeys(t *testing.T) {
	v := loadVectors(t)
	for _, name := range []string{string(profile.PQPure), string(profile.PQHybrid)} {
		r, ok := v.Recipients[name]
		if !ok {
			t.Fatalf("no %s recipient", name)
		}
		key := recipientKey(t, name, r)
		carried := key.PublicKey().Carried()
		equal(t, name+" key_as_carried", carried, r.KeyAsCarried)
		hash := KeyHash(carried)
		equal(t, name+" key_hash", hash[:], r.KeyHash)
		id := KeyID(carried)
		equal(t, name+" key_id", id[:], r.KeyID)
	}
}

func TestVectorCalls(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Calls {
		t.Run(c.Profile+"/"+c.FrameType, func(t *testing.T) {
			key := recipientKey(t, c.Profile, v.Recipients[c.Profile])
			carried := key.PublicKey().Carried()
			id := KeyID(carried)
			equal(t, "key_id", id[:], c.KeyID)

			// The recipient's side of the shared secret, and the values it
			// combines.
			equal(t, "kem_ct", c.KemCt, append(bytes.Clone(c.MLKEMCt), c.EphPub...))
			ssMLKEM, err := key.MLKEM.Decapsulate(c.MLKEMCt)
			if err != nil {
				t.Fatal(err)
			}
			equal(t, "ss_mlkem", ssMLKEM, c.SsMLKEM)
			keyHash := KeyHash(carried)
			if c.Profile == string(profile.PQHybrid) {
				ssECDH, err := ecdhSecret(key.P384, c.EphPub)
				if err != nil {
					t.Fatal(err)
				}
				equal(t, "ss_ecdh", ssECDH, c.SsECDH)
				equal(t, "ikm", hybridIkm(ssMLKEM, ssECDH, c.MLKEMCt, c.EphPub, keyHash), c.Ikm)
			} else {
				equal(t, "ikm", pureIkm(ssMLKEM, c.MLKEMCt, keyHash), c.Ikm)
			}
			ss, err := RecipientSecret(key, c.KemCt)
			if err != nil {
				t.Fatal(err)
			}
			equal(t, "ss", ss[:], c.Ss)

			parties := Parties{RequestID: [16]byte(c.RequestID), Caller: id32(t, c.Caller), Target: id32(t, c.Target)}
			kReq, kRep := CallKeys(ss, c.FrameType, parties)
			equal(t, "k_req", kReq[:], c.KReq)
			equal(t, "k_rep", kRep[:], c.KRep)

			request := Request{FrameType: c.FrameType, Realm: id32(t, c.Realm), Procedure: c.Procedure,
				Caller: parties.Caller, Target: parties.Target, RequestID: parties.RequestID, Deadline: c.Deadline}
			equal(t, "request aad", RequestAAD(request), c.Request.Aad)
			equal(t, "request nonce", c.Request.Nonce, make([]byte, NonceSize))
			checkSealed(t, "request", kReq, c.Request)

			if c.Reply != nil {
				aad := ReplyAAD(request, c.Reply.FrameType, [48]byte(c.Reply.RequestHash), id32(t, c.Reply.RespondedBy))
				equal(t, "reply aad", aad, c.Reply.Aad)
				checkSealed(t, "reply", kRep, c.Reply.vectorSealed)
			}

			if c.FrameType != FrameStreamOpen {
				if len(c.Frames) != 0 || c.KC2P != nil {
					t.Fatalf("a %s vector carries stream frames or keys", c.FrameType)
				}
				return
			}
			if c.Reply != nil || len(c.Frames) == 0 {
				t.Fatalf("a stream_open vector carries a reply, or no frames")
			}
			kC2P, kP2C := StreamKeys(ss, parties)
			equal(t, "k_c2p", kC2P[:], c.KC2P)
			equal(t, "k_p2c", kP2C[:], c.KP2C)
			directions := map[Direction]int{}
			for _, f := range c.Frames {
				direction := Direction(f.Direction)
				directions[direction]++
				equal(t, "stream frame aad", StreamAAD(f.FrameType, parties.RequestID, f.Seq, direction), f.Aad)
				streamKey := kP2C
				if direction == CallerToProvider {
					streamKey = kC2P
					nonce := StreamNonce(f.Seq)
					equal(t, "caller stream frame nonce", nonce[:], f.Nonce)
				}
				checkSealed(t, "stream frame", streamKey, f.vectorSealed)
			}
			if directions[CallerToProvider] == 0 || directions[ProviderToCaller] == 0 {
				t.Fatalf("stream frames in only one direction: %v", directions)
			}
		})
	}
}

func TestVectorEvents(t *testing.T) {
	v := loadVectors(t)
	for _, e := range v.Events {
		kG := key32(t, e.KG)
		prk := eventPRK(kG)
		equal(t, "prk_g", prk, e.PrkG)
		kPub := EventKey(kG, id32(t, e.Publisher))
		equal(t, "k_pub", kPub[:], e.KPub)
		equal(t, "event aad", EventAAD(id32(t, e.Realm), e.Topic, id32(t, e.Publisher), e.Seq, e.PublishedAt), e.Aad)
		checkSealed(t, "event", kPub, e.vectorSealed)
	}
}

// The sender's side, byte for byte: crypto/mlkem/mlkemtest's derandomized
// encapsulation with the vector's encaps_m, and the vector's ephemeral P-384
// scalar, reproduce kem_ct and ss.
func TestVectorSenderSide(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Calls {
		t.Run(c.Profile+"/"+c.FrameType, func(t *testing.T) {
			recipient := recipientKey(t, c.Profile, v.Recipients[c.Profile]).PublicKey()
			var ephemeral *ecdh.PrivateKey
			if c.Profile == string(profile.PQHybrid) {
				var err error
				if ephemeral, err = ecdh.P384().NewPrivateKey(c.EphPriv); err != nil {
					t.Fatal(err)
				}
				equal(t, "eph_pub", ephemeral.PublicKey().Bytes(), c.EphPub)
			}
			seeded := func(ek *mlkem.EncapsulationKey1024) ([]byte, []byte, error) {
				return mlkemtest.Encapsulate1024(ek, c.EncapsM)
			}
			ss, kemCt, err := senderSecret(recipient, seeded, ephemeral)
			if err != nil {
				t.Fatal(err)
			}
			equal(t, "kem_ct", kemCt, c.KemCt)
			equal(t, "ss", ss[:], c.Ss)
		})
	}
}

// Every refusal is refused. The zero-ECDH refusal is also checked to reach
// its zero:
// crypto/ecdh returns the 48 zero bytes without an error, so RecipientSecret's
// own check is what refuses it.
func TestVectorRefusals(t *testing.T) {
	v := loadVectors(t)
	for _, r := range v.Refusals {
		t.Run(r.Why, func(t *testing.T) {
			if r.Expect != "sealed_refused" {
				t.Fatalf("expect %q", r.Expect)
			}
			var p384 []byte
			if r.Profile == string(profile.PQHybrid) {
				p384 = r.P384Priv
			}
			key, err := NewPrivateKey(profile.Profile(r.Profile), r.MLKEMSeed, p384)
			if err != nil {
				t.Fatal(err)
			}
			equal(t, "key_as_carried", key.PublicKey().Carried(), r.KeyAsCarried)
			if key.P384 != nil {
				equal(t, "p384_pub", key.P384.PublicKey().Bytes(), r.P384Pub)
			}
			if key.P384 != nil && len(r.KemCt) == MLKEMCiphertextSize+P384PointSize {
				peer, err := ecdh.P384().NewPublicKey(r.KemCt[MLKEMCiphertextSize:])
				if err != nil {
					t.Fatalf("the ephemeral point is not on P-384: %v", err)
				}
				raw, err := key.P384.ECDH(peer)
				if err != nil || !bytes.Equal(raw, make([]byte, len(raw))) {
					t.Fatalf("crypto/ecdh gives %x, %v: this refusal no longer reaches the zero output it names", raw, err)
				}
			}
			if ss, err := RecipientSecret(key, r.KemCt); !errors.Is(err, ErrRefused) {
				t.Fatalf("recovered %x, %v: want ErrRefused", ss, err)
			}
		})
	}
}
