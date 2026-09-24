package stationlink

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/record"
)

// Serving, as macula 12's provider does it. A procedure is served under an org
// namespace: the realm's org directory names the org's key, the org's procedure
// delegation names this node, both are found in the DHT, and the signed
// procedure_advertisement carries them to the station in an ADVERTISE, checked
// against the realm key before it goes out. The station routes CALLs for the
// procedure to this link; each is admitted once per (caller, request_id) and
// answered with a RESULT or ERROR signed by this node. UNADVERTISE carries a
// tombstone of the advertisement.
//
// Only open procedures are served. A gated procedure needs a post-quantum UCAN
// verifier, which macula-go does not have yet (macula-io/macula-go#2), and is
// refused by name rather than served open.

// The provider codes of a served procedure's ERRORs: a handler's own refusal,
// a handler that panicked, a procedure this link does not serve, a copy of a
// request still running, and a result the wire cannot carry.
const (
	codeHandlerError     = "handler_error"
	codeHandlerCrashed   = "temporary_relay_failure"
	codeUnknownProcedure = "unknown_next_peer"
	codeRequestCopy      = "request_copy"
	codePayloadTooLarge  = "payload_too_large"
	codeUnsendable       = "unknown_error"
)

// maxDetailBytes bounds an ERROR's detail, cut on a character boundary.
const maxDetailBytes = 256

var (
	// maxAdvertisementTTL is macula's default and longest advertisement
	// lifetime.
	maxAdvertisementTTL = 5 * time.Minute
	// refreshRetry is how soon a failed renewal is tried again, while the
	// advertisement it replaces still lives.
	refreshRetry = 10 * time.Second
)

var (
	// ErrNoOrg is a procedure without an org namespace, which nobody can
	// authorize a provider for.
	ErrNoOrg = errors.New("stationlink: a served procedure needs an org namespace")
	// ErrGatedUnsupported is a gated procedure: its UCAN check needs the
	// post-quantum token verifier macula-go does not have yet.
	ErrGatedUnsupported = errors.New("stationlink: gated procedures need a post-quantum UCAN verifier (macula-io/macula-go#2)")
	// ErrAlreadyServed is a procedure this link already serves in the realm.
	ErrAlreadyServed = errors.New("stationlink: the procedure is already served on this link")
	// ErrInvalidOffer is an offer without a handler or a realm key.
	ErrInvalidOffer = errors.New("stationlink: an offer needs a handler and the realm key")
	// ErrStopped is a served procedure withdrawn by Stop.
	ErrStopped = errors.New("stationlink: the procedure was withdrawn")
)

// Request is a CALL a served procedure answers: the caller, the key id its
// signature verified under, and what it asked for. The handler's context ends
// at the request's deadline.
type Request struct {
	Caller    [32]byte
	Realm     [32]byte
	Procedure string
	Payload   cbor.Value
	Token     []byte
	Proofs    [][]byte
	Deadline  time.Time
}

// Handler answers a Request with a result payload, or an error whose text the
// caller receives as a handler_error's detail.
type Handler func(ctx context.Context, r Request) (cbor.Value, error)

// Offer is a procedure to serve: its realm and name, its handler, and the realm
// key the org directory must be signed with, as the realm's members pin it.
// Gated is a procedure whose callers need a UCAN, refused for now.
type Offer struct {
	Realm     [32]byte
	Procedure string
	Handler   Handler
	RealmKey  []byte
	Gated     bool
}

type servedKey struct {
	realm     [32]byte
	procedure string
}

// Served is a procedure this link serves, until Stop or the link ends, or until
// its advertisement lapses because its authorization could not be found again.
type Served struct {
	link    *Link
	key     servedKey
	offer   Offer
	stop    chan struct{}
	done    chan struct{}
	endOnce sync.Once
	// maxTTL and retry are the advertisement lifetime and renewal retry in
	// force when Serve was called.
	maxTTL, retry time.Duration

	mu     sync.Mutex
	latest record.Record
	err    error
}

// Serve advertises o's procedure on the link and answers its CALLs until Stop.
// It resolves the org directory and this node's procedure delegation from the
// DHT, signs the advertisement with this node's identity key, naming the
// connected station as the serving station and living no longer than either
// record nor 5 minutes, and checks its authorization against o.RealmKey
// before sending it. The advertisement is renewed at half its lifetime.
func (l *Link) Serve(ctx context.Context, o Offer) (*Served, error) {
	if o.Handler == nil || len(o.RealmKey) == 0 {
		return nil, ErrInvalidOffer
	}
	if o.Gated {
		return nil, ErrGatedUnsupported
	}
	if _, hasOrg, err := record.ProcedureOrg(o.Procedure); err != nil || !hasOrg {
		return nil, errors.Join(ErrNoOrg, err)
	}
	maxTTL, retry := maxAdvertisementTTL, refreshRetry
	advertisement, wire, err := l.advertisement(ctx, o, maxTTL)
	if err != nil {
		return nil, err
	}
	s := &Served{link: l, key: servedKey{o.Realm, o.Procedure}, offer: o, latest: advertisement,
		stop: make(chan struct{}), done: make(chan struct{}), maxTTL: maxTTL, retry: retry}
	l.mu.Lock()
	if _, taken := l.served[s.key]; taken {
		l.mu.Unlock()
		return nil, ErrAlreadyServed
	}
	l.served[s.key] = s
	l.mu.Unlock()
	if err := l.sendControl(frame.AdvertiseFrame(wire)); err != nil {
		s.end(err)
		return nil, err
	}
	go s.renew()
	return s, nil
}

// advertisement is o's signed procedure_advertisement and its wire form, with
// the authorization resolved from the DHT and verified against o.RealmKey,
// living at most maxTTL.
func (l *Link) advertisement(ctx context.Context, o Offer, maxTTL time.Duration) (record.Record, []byte, error) {
	org, _, _ := record.ProcedureOrg(o.Procedure)
	directory, err := l.FindRecord(ctx, record.OrgDirectoryKey(o.Realm, org))
	if err != nil {
		return record.Record{}, nil, fmt.Errorf("stationlink: the org directory of %q: %w", org, err)
	}
	named, err := record.ReadOrgDirectory(directory.Record())
	if err != nil {
		return record.Record{}, nil, err
	}
	delegation, err := l.FindRecord(ctx, record.ProcedureDelegationKey(named.OrgKey, l.self))
	if err != nil {
		return record.Record{}, nil, fmt.Errorf("stationlink: the procedure delegation of %q to this node: %w", org, err)
	}
	directoryWire, err := record.Encode(directory.Record())
	if err != nil {
		return record.Record{}, nil, err
	}
	delegationWire, err := record.Encode(delegation.Record())
	if err != nil {
		return record.Record{}, nil, err
	}
	now := time.Now().UnixMilli()
	ttl := min(int64(maxTTL/time.Millisecond),
		int64(directory.Record().ExpiresAt)-now, int64(delegation.Record().ExpiresAt)-now)
	if ttl <= 0 {
		return record.Record{}, nil, record.ErrAuthorizationOutlived
	}
	unsigned, err := record.NewProcedureAdvertisement(l.self, o.Realm, o.Procedure, l.station.NodeID,
		record.ProcedureAdvertisementOptions{
			Authorization: record.Authorization{Form: record.DelegationAuthorization,
				OrgDirectory: directoryWire, ProcedureDelegation: delegationWire},
			TTLMs: uint64(ttl),
		})
	if err != nil {
		return record.Record{}, nil, err
	}
	signed, err := record.Sign(unsigned, l.key)
	if err != nil {
		return record.Record{}, nil, err
	}
	wire, err := record.Encode(signed)
	if err != nil {
		return record.Record{}, nil, err
	}
	verified, err := record.Verify(wire, l.profile, now)
	if err != nil {
		return record.Record{}, nil, err
	}
	if err := record.VerifyAuthorization(verified, record.Trust{Profile: l.profile, RealmKey: o.RealmKey}, now); err != nil {
		return record.Record{}, nil, err
	}
	return signed, wire, nil
}

// renew sends a fresh advertisement at half the current one's lifetime. A
// renewal that fails is tried again every retry while the current one
// lives; when it lapses unrenewed, the procedure is no longer served and Err
// says why.
func (s *Served) renew() {
	s.mu.Lock()
	current := s.latest
	s.mu.Unlock()
	wait := halfLife(current)
	var lastErr error
	for {
		select {
		case <-s.stop:
			return
		case <-s.link.done:
			s.end(s.link.Err())
			return
		case <-time.After(wait):
		}
		if time.Now().UnixMilli() >= int64(current.ExpiresAt) {
			s.end(fmt.Errorf("stationlink: the advertisement lapsed unrenewed: %w", lastErr))
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), DefaultCallTimeout)
		advertisement, wire, err := s.link.advertisement(ctx, s.offer, s.maxTTL)
		cancel()
		if err == nil {
			err = s.link.sendControl(frame.AdvertiseFrame(wire))
		}
		if err != nil {
			lastErr = err
			wait = min(s.retry, max(time.Until(time.UnixMilli(int64(current.ExpiresAt))), 0))
			continue
		}
		s.mu.Lock()
		s.latest = advertisement
		s.mu.Unlock()
		current, wait = advertisement, halfLife(advertisement)
	}
}

func halfLife(r record.Record) time.Duration {
	return time.Duration(r.ExpiresAt-r.CreatedAt) * time.Millisecond / 2
}

// Stop withdraws the advertisement with an UNADVERTISE carrying its tombstone,
// signed by this node, and stops answering the procedure's CALLs. Stopping a
// procedure no longer served does nothing.
func (s *Served) Stop() error {
	select {
	case <-s.done:
		return nil
	default:
	}
	s.end(ErrStopped)
	s.mu.Lock()
	latest := s.latest
	s.mu.Unlock()
	tombstone, err := record.NewTombstone(latest, record.ReasonShutdown, record.TombstoneOptions{})
	if err != nil {
		return err
	}
	signed, err := record.Sign(tombstone, s.link.key)
	if err != nil {
		return err
	}
	wire, err := record.Encode(signed)
	if err != nil {
		return err
	}
	return s.link.sendControl(frame.UnadvertiseFrame(wire))
}

// Done is closed when the procedure is no longer served.
func (s *Served) Done() <-chan struct{} { return s.done }

// Err is why the procedure is no longer served: ErrStopped after Stop, the
// link's error when it ended, or the renewal's failure; nil while served.
func (s *Served) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Served) end(err error) {
	s.endOnce.Do(func() {
		s.link.mu.Lock()
		if s.link.served[s.key] == s {
			delete(s.link.served, s.key)
		}
		s.link.mu.Unlock()
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		close(s.stop)
		close(s.done)
	})
}

// endServed ends every procedure the link serves with its error.
func (l *Link) endServed(err error) {
	l.mu.Lock()
	served := make([]*Served, 0, len(l.served))
	for _, s := range l.served {
		served = append(served, s)
	}
	l.mu.Unlock()
	for _, s := range served {
		s.end(err)
	}
}

// called answers a CALL the station routed to this link. A request that does
// not verify, or targets another node, gets no reply and is counted. One that
// verifies is judged by the admission, then answered by its handler, or by an
// ERROR naming why not.
func (l *Link) called(v cbor.Value) {
	request, err := frame.VerifyRequest(v, l.profile)
	if err != nil {
		l.count("unverified_call")
		return
	}
	if request.Target != l.self {
		l.count("call_for_another_node")
		return
	}
	verdict := l.admission.admit(request, time.Now().UnixMilli())
	switch {
	case verdict.refusal != "":
		l.sendReply(l.providerError(request, verdict.refusal, nil))
	case verdict.copy && verdict.stored == nil:
		l.sendReply(l.providerError(request, codeRequestCopy, nil))
	case verdict.copy:
		_ = l.writer.write(verdict.stored, MaxFrameBytes)
	default:
		go l.answer(request)
	}
}

// answer runs the request's handler and sends its signed reply, storing it for
// the request's copies.
func (l *Link) answer(request frame.VerifiedRequest) {
	l.mu.Lock()
	served := l.served[servedKey{request.Realm, request.Procedure}]
	l.mu.Unlock()
	var reply cbor.Value
	if served == nil {
		reply = l.providerError(request, codeUnknownProcedure, nil)
	} else {
		reply = l.handled(served.offer.Handler, request)
	}
	encoded := cbor.Encode(reply)
	l.admission.store(request, encoded)
	_ = l.writer.write(encoded, MaxFrameBytes)
}

// handled is the handler's answer to request as a signed reply: its result, its
// refusal as handler_error, a panic as temporary_relay_failure, or a result the
// wire cannot carry as payload_too_large or unknown_error.
func (l *Link) handled(handler Handler, request frame.VerifiedRequest) (reply cbor.Value) {
	defer func() {
		if recover() != nil {
			reply = l.providerError(request, codeHandlerCrashed, nil)
		}
	}()
	deadline := time.UnixMilli(int64(request.Deadline))
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	payload, err := handler(ctx, Request{Caller: request.Caller, Realm: request.Realm, Procedure: request.Procedure,
		Payload: request.Payload, Token: request.Token, Proofs: request.Proofs, Deadline: deadline})
	if err != nil {
		detail := boundedDetail(err.Error())
		return l.providerError(request, codeHandlerError, &detail)
	}
	signed, err := frame.SignResult(request, payload, nil, l.key)
	if err != nil {
		if len(cbor.Encode(payload)) > frame.MaxFrameBytes {
			return l.providerError(request, codePayloadTooLarge, nil)
		}
		return l.providerError(request, codeUnsendable, nil)
	}
	return signed
}

// providerError is this node's signed ERROR for request. The request verified
// with this node as its target, so signing it cannot fail on the key; a code
// or detail out of bounds is a bug in this package and panics.
func (l *Link) providerError(request frame.VerifiedRequest, code string, detail *string) cbor.Value {
	reply, err := frame.SignProviderError(request, code, detail, nil, l.key)
	if err != nil {
		panic(fmt.Sprintf("stationlink: a provider error that does not sign: %v", err))
	}
	return reply
}

func (l *Link) sendReply(reply cbor.Value) {
	_ = l.writer.write(cbor.Encode(reply), MaxFrameBytes)
}

// boundedDetail is text cut to maxDetailBytes on a character boundary, with
// invalid UTF-8 replaced.
func boundedDetail(text string) string {
	text = string([]rune(text)) // replaces invalid UTF-8 with U+FFFD
	if len(text) <= maxDetailBytes {
		return text
	}
	cut := maxDetailBytes
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}
