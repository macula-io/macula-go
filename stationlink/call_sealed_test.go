package stationlink

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
)

// A caller that seals (macula 13's E2E design §5.1, §8.3): a call sealed to
// the provider's KEM key takes a sealed answer, opened, or from the clear only
// a relay error, a refusal from the closed set, or sealed_refused naming the
// provider's key; anything else is refused, never taken as the clear answer to
// a clear call. The station here plays the provider, holding the key.

// sealedAnswerFunc builds the answer a station playing the provider gives one
// opened sealed request: the plaintext it opened, the reply key, and the
// request the answer's AAD names.
type sealedAnswerFunc func(s *testStation, r frame.VerifiedRequest, plain cbor.Value, kRep [32]byte, request seal.Request) cbor.Value

// sealedCheckFunc is what a sealed caller must make of the answer it got.
type sealedCheckFunc func(t *testing.T, got cbor.Value, err error)

// sealedAnswerer is the station's side of a sealed call: it opens the request
// with key and answers with what answer builds from it.
func sealedAnswerer(t *testing.T, s *testStation, key *seal.PrivateKey, answer sealedAnswerFunc) {
	t.Helper()
	s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
		if r.Sealed == nil {
			t.Errorf("the call came clear")
			return cbor.Value{}, false
		}
		ss, err := seal.RecipientSecret(key, r.Sealed.KemCt)
		if err != nil {
			t.Errorf("RecipientSecret: %v", err)
			return cbor.Value{}, false
		}
		kReq, kRep := seal.CallKeys(ss, seal.FrameCall, seal.Parties{RequestID: r.RequestID, Caller: r.Caller, Target: r.Target})
		request := sealRequestOf(r)
		plain, err := seal.Open(kReq, [seal.NonceSize]byte{}, seal.RequestAAD(request), r.Sealed.Ct)
		if err != nil {
			t.Errorf("the request does not open: %v", err)
			return cbor.Value{}, false
		}
		payload, err := cbor.Decode(plain)
		if err != nil {
			t.Errorf("the request's plaintext: %v", err)
			return cbor.Value{}, false
		}
		return answer(s, r, payload, kRep, request), true
	})
}

// sealedReplyWith is a sealed RESULT or ERROR the station signs, plain sealed
// under kRep.
func sealedReplyWith(t *testing.T, s *testStation, r frame.VerifiedRequest, frameType string, plain []byte, kRep [32]byte,
	request seal.Request) cbor.Value {
	t.Helper()
	return sealedReplyNaming(t, s, r, r.Sealed.KeyID, frameType, plain, kRep, request)
}

// sealedReplyNaming is sealedReplyWith naming keyID as the key it answers.
func sealedReplyNaming(t *testing.T, s *testStation, r frame.VerifiedRequest, keyID [seal.KeyIDSize]byte, frameType string,
	plain []byte, kRep [32]byte, request seal.Request) cbor.Value {
	t.Helper()
	nonce := seal.RandomNonce()
	sealed := frame.Sealed{KeyID: keyID, Nonce: nonce[:],
		Ct: seal.Seal(kRep, nonce, seal.ReplyAAD(request, frameType, r.RequestHash, s.nodeID), plain)}
	var reply cbor.Value
	var err error
	if frameType == "result" {
		reply, err = frame.SignSealedResult(r, sealed, nil, s.key)
	} else {
		reply, err = frame.SignSealedProviderError(r, sealed, nil, s.key)
	}
	if err != nil {
		t.Fatalf("sign the sealed %s: %v", frameType, err)
	}
	return reply
}

func TestASealedCallTakesOnlyWhatMayAnswerIt(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			runSealedCallCases(t, p)
		})
	}
	assertAnOversizedKEMKeyIsRefused(t)
}

// runSealedCallCases has a station for p answer one sealed call per case and
// checks the caller takes only what may answer it.
func runSealedCallCases(t *testing.T, p profile.Profile) {
	t.Helper()
	key := must[*seal.PrivateKey](t)(seal.GenerateKey(p))
	keyID := seal.KeyID(key.PublicKey().Carried())
	for _, c := range sealedCallCases(t, keyID) {
		t.Run(c.name, func(t *testing.T) {
			link, s := linkWithStation(t, p)
			sealedAnswerer(t, s, key, c.answer)
			call := stationCall("_dht.find_record", cbor.Text("secret"))
			call.SealTo = key.PublicKey().Carried()
			got, err := callWithin(t, link, call)
			c.check(t, got, err)
		})
	}
}

// sealedCallCase is one answer a station playing the provider may give a
// sealed call, and what the caller must make of it.
type sealedCallCase struct {
	name   string
	answer sealedAnswerFunc
	check  sealedCheckFunc
}

// sealedCallCases is every answer that may come back to a sealed call: the
// sealed result and error open, the one that does not open or names another
// key is refused, and from the clear only a relay error, an admission refusal
// or sealed_refused naming the provider's key is taken.
func sealedCallCases(t *testing.T, keyID [seal.KeyIDSize]byte) []sealedCallCase {
	t.Helper()
	named, noKey := hex.EncodeToString(keyID[:]), noKeyDetail
	return []sealedCallCase{
		{"a sealed result", sealedResultAnswer(t), wantSealedText("secret")},
		{"a sealed error", sealedErrorAnswer(t), wantProviderError("handler_error", "no such city")},
		{"a sealed result that does not open", sealedResultSealedWrongly(t), wantConfidentiality(ReasonReplyNotOpened)},
		// As macula's open_reply/4: a reply naming another key than the
		// request's does not open, though its ciphertext would.
		{"a sealed result naming another key", sealedResultNamingAnotherKey(t), wantConfidentiality(ReasonReplyNotOpened)},
		{"a clear result", clearResultAnswer(t), wantErr(ErrClearAnswerToSealed)},
		{"a clear handler error", clearErrorAnswer(t, "handler_error", nil), wantErr(ErrClearAnswerToSealed)},
		{"a clear admission refusal", clearErrorAnswer(t, "expired", nil), wantProviderCode("expired")},
		{"sealed_refused naming a key", clearErrorAnswer(t, codeSealedRefused, &named), wantSealedRefusedNamed(keyID)},
		{"sealed_refused holding none", clearErrorAnswer(t, codeSealedRefused, &noKey), wantSealedRefusedNone()},
	}
}

// sealedResultAnswer seals the request's plaintext back as the result.
func sealedResultAnswer(t *testing.T) sealedAnswerFunc {
	return func(s *testStation, r frame.VerifiedRequest, plain cbor.Value, kRep [32]byte, req seal.Request) cbor.Value {
		return sealedReplyWith(t, s, r, "result", cbor.Encode(plain), kRep, req)
	}
}

// sealedErrorAnswer seals a handler error naming the city it could not find.
func sealedErrorAnswer(t *testing.T) sealedAnswerFunc {
	return func(s *testStation, r frame.VerifiedRequest, _ cbor.Value, kRep [32]byte, req seal.Request) cbor.Value {
		return sealedReplyWith(t, s, r, "error", seal.ErrorPlain("handler_error", "no such city"), kRep, req)
	}
}

// sealedResultSealedWrongly seals the result under a reply key the caller does
// not derive.
func sealedResultSealedWrongly(t *testing.T) sealedAnswerFunc {
	return func(s *testStation, r frame.VerifiedRequest, plain cbor.Value, _ [32]byte, req seal.Request) cbor.Value {
		return sealedReplyWith(t, s, r, "result", cbor.Encode(plain), [32]byte{9}, req)
	}
}

// sealedResultNamingAnotherKey seals the result under the right key but names
// another key ID.
func sealedResultNamingAnotherKey(t *testing.T) sealedAnswerFunc {
	return func(s *testStation, r frame.VerifiedRequest, plain cbor.Value, kRep [32]byte, req seal.Request) cbor.Value {
		return sealedReplyNaming(t, s, r, [seal.KeyIDSize]byte{1}, "result", cbor.Encode(plain), kRep, req)
	}
}

// clearResultAnswer answers a sealed call with a result in the clear.
func clearResultAnswer(t *testing.T) sealedAnswerFunc {
	return func(s *testStation, r frame.VerifiedRequest, _ cbor.Value, _ [32]byte, _ seal.Request) cbor.Value {
		return must[cbor.Value](t)(frame.SignResult(r, cbor.Text("in the clear"), nil, s.key))
	}
}

// clearErrorAnswer answers a sealed call with a provider error in the clear,
// naming detail when the caller may see one.
func clearErrorAnswer(t *testing.T, code string, detail *string) sealedAnswerFunc {
	return func(s *testStation, r frame.VerifiedRequest, _ cbor.Value, _ [32]byte, _ seal.Request) cbor.Value {
		return must[cbor.Value](t)(frame.SignProviderError(r, code, detail, nil, s.key))
	}
}

// assertAnOversizedKEMKeyIsRefused checks a seal target longer than a KEM key
// is refused rather than sealed to.
func assertAnOversizedKEMKeyIsRefused(t *testing.T) {
	t.Helper()
	link, _ := linkWithStation(t, profile.PQPure)
	call := stationCall("_dht.find_record", cbor.Text("x"))
	call.SealTo = make([]byte, 100)
	_, err := callWithin(t, link, call)
	wantConfidentiality(ReasonNoKEMKey)(t, cbor.Value{}, err)
}

// wantSealedText checks the caller opened a sealed result to want.
func wantSealedText(want string) sealedCheckFunc {
	return func(t *testing.T, got cbor.Value, err error) {
		t.Helper()
		if text, _ := got.AsText(); err != nil || text != want {
			t.Errorf("%q, %v", text, err)
		}
	}
}

// wantProviderError checks err is a *ProviderError naming code and detail.
func wantProviderError(code, detail string) sealedCheckFunc {
	return func(t *testing.T, _ cbor.Value, err error) {
		t.Helper()
		var provided *ProviderError
		if !errors.As(err, &provided) || provided.Code != code || provided.Detail == nil || *provided.Detail != detail {
			t.Errorf("%v", err)
		}
	}
}

// wantProviderCode checks err is a *ProviderError with this code.
func wantProviderCode(code string) sealedCheckFunc {
	return func(t *testing.T, _ cbor.Value, err error) {
		t.Helper()
		var provided *ProviderError
		if !errors.As(err, &provided) || provided.Code != code {
			t.Errorf("%v", err)
		}
	}
}

// wantSealedRefusedNamed checks err is a *SealedRefusedError naming keyID.
func wantSealedRefusedNamed(keyID [seal.KeyIDSize]byte) sealedCheckFunc {
	return func(t *testing.T, _ cbor.Value, err error) {
		t.Helper()
		var refused *SealedRefusedError
		if !errors.As(err, &refused) || refused.Named == nil || *refused.Named != keyID {
			t.Errorf("%v", err)
		}
	}
}

// wantSealedRefusedNone checks err is a *SealedRefusedError naming no key.
func wantSealedRefusedNone() sealedCheckFunc {
	return func(t *testing.T, _ cbor.Value, err error) {
		t.Helper()
		var refused *SealedRefusedError
		if !errors.As(err, &refused) || refused.Named != nil {
			t.Errorf("%v", err)
		}
	}
}

func wantConfidentiality(reason string) func(*testing.T, cbor.Value, error) {
	return func(t *testing.T, _ cbor.Value, err error) {
		t.Helper()
		var refused *ConfidentialityError
		if !errors.As(err, &refused) || refused.Reason != reason {
			t.Errorf("%v, want confidentiality %s", err, reason)
		}
	}
}

func wantErr(want error) func(*testing.T, cbor.Value, error) {
	return func(t *testing.T, _ cbor.Value, err error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Errorf("%v, want %v", err, want)
		}
	}
}
