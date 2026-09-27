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

// sealedAnswerer is the station's side of a sealed call: it opens the request
// with key and answers with what answer builds from it.
func sealedAnswerer(t *testing.T, s *testStation, key *seal.PrivateKey,
	answer func(s *testStation, r frame.VerifiedRequest, plain cbor.Value, kRep [32]byte, request seal.Request) cbor.Value) {
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
			key := must[*seal.PrivateKey](t)(seal.GenerateKey(p))
			keyID := seal.KeyID(key.PublicKey().Carried())
			clearError := func(code string, detail *string) func(*testStation, frame.VerifiedRequest, cbor.Value, [32]byte, seal.Request) cbor.Value {
				return func(s *testStation, r frame.VerifiedRequest, _ cbor.Value, _ [32]byte, _ seal.Request) cbor.Value {
					return must[cbor.Value](t)(frame.SignProviderError(r, code, detail, nil, s.key))
				}
			}
			named := hex.EncodeToString(keyID[:])
			noKey := noKeyDetail
			for _, c := range []struct {
				name   string
				answer func(*testStation, frame.VerifiedRequest, cbor.Value, [32]byte, seal.Request) cbor.Value
				check  func(t *testing.T, got cbor.Value, err error)
			}{
				{"a sealed result", func(s *testStation, r frame.VerifiedRequest, plain cbor.Value, kRep [32]byte, req seal.Request) cbor.Value {
					return sealedReplyWith(t, s, r, "result", cbor.Encode(plain), kRep, req)
				}, func(t *testing.T, got cbor.Value, err error) {
					if text, _ := got.AsText(); err != nil || text != "secret" {
						t.Errorf("%q, %v", text, err)
					}
				}},
				{"a sealed error", func(s *testStation, r frame.VerifiedRequest, _ cbor.Value, kRep [32]byte, req seal.Request) cbor.Value {
					return sealedReplyWith(t, s, r, "error", seal.ErrorPlain("handler_error", "no such city"), kRep, req)
				}, func(t *testing.T, _ cbor.Value, err error) {
					var provided *ProviderError
					if !errors.As(err, &provided) || provided.Code != "handler_error" || provided.Detail == nil || *provided.Detail != "no such city" {
						t.Errorf("%v", err)
					}
				}},
				{"a sealed result that does not open", func(s *testStation, r frame.VerifiedRequest, plain cbor.Value, _ [32]byte, req seal.Request) cbor.Value {
					return sealedReplyWith(t, s, r, "result", cbor.Encode(plain), [32]byte{9}, req)
				}, wantConfidentiality(ReasonReplyNotOpened)},
				// As macula's open_reply/4: a reply naming another key than
				// the request's does not open, though its ciphertext would.
				{"a sealed result naming another key", func(s *testStation, r frame.VerifiedRequest, plain cbor.Value, kRep [32]byte, req seal.Request) cbor.Value {
					return sealedReplyNaming(t, s, r, [seal.KeyIDSize]byte{1}, "result", cbor.Encode(plain), kRep, req)
				}, wantConfidentiality(ReasonReplyNotOpened)},
				{"a clear result", func(s *testStation, r frame.VerifiedRequest, _ cbor.Value, _ [32]byte, _ seal.Request) cbor.Value {
					return must[cbor.Value](t)(frame.SignResult(r, cbor.Text("in the clear"), nil, s.key))
				}, wantErr(ErrClearAnswerToSealed)},
				{"a clear handler error", clearError("handler_error", nil), wantErr(ErrClearAnswerToSealed)},
				{"a clear admission refusal", clearError("expired", nil), func(t *testing.T, _ cbor.Value, err error) {
					var provided *ProviderError
					if !errors.As(err, &provided) || provided.Code != "expired" {
						t.Errorf("%v", err)
					}
				}},
				{"sealed_refused naming a key", clearError(codeSealedRefused, &named), func(t *testing.T, _ cbor.Value, err error) {
					var refused *SealedRefusedError
					if !errors.As(err, &refused) || refused.Named == nil || *refused.Named != keyID {
						t.Errorf("%v", err)
					}
				}},
				{"sealed_refused holding none", clearError(codeSealedRefused, &noKey), func(t *testing.T, _ cbor.Value, err error) {
					var refused *SealedRefusedError
					if !errors.As(err, &refused) || refused.Named != nil {
						t.Errorf("%v", err)
					}
				}},
			} {
				t.Run(c.name, func(t *testing.T) {
					link, s := linkWithStation(t, p)
					sealedAnswerer(t, s, key, c.answer)
					call := stationCall("_dht.find_record", cbor.Text("secret"))
					call.SealTo = key.PublicKey().Carried()
					got, err := callWithin(t, link, call)
					c.check(t, got, err)
				})
			}
		})
	}
	link, _ := linkWithStation(t, profile.PQPure)
	call := stationCall("_dht.find_record", cbor.Text("x"))
	call.SealTo = make([]byte, 100)
	_, err := callWithin(t, link, call)
	wantConfidentiality(ReasonNoKEMKey)(t, cbor.Value{}, err)
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
