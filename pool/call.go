package pool

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/seal"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
)

var (
	// ErrNoProvider is a procedure with no advertisement the pinned realm key
	// authorizes, or none by the provider asked for.
	ErrNoProvider = errors.New("pool: no trusted provider advertises the procedure")
	// ErrNoStationEndpoint is a serving station with no endpoint record it
	// signed itself.
	ErrNoStationEndpoint = errors.New("pool: the serving station has no endpoint record of its own")
	// ErrConfidentialOff is a pool call or stream with ConfidentialOff. A
	// pool decides from the provider's verified advertisement, and only one
	// naming no key is called in the clear (macula 13's E2E design §8.1):
	// off is an explicit target's (stationlink.Call without SealTo), and is
	// refused here rather than ignored.
	ErrConfidentialOff = errors.New("pool: confidential off is an explicit target's; a pool call is preferred or required")
	// ErrDirectLinksFull is a serving station not yet linked while the pool
	// already holds MaxDirectLinks direct links.
	ErrDirectLinksFull = errors.New("pool: MaxDirectLinks direct links are held")
)

// Call is a call to a procedure: its realm and name, the provider to call
// (any trusted one when zero), the payload, how long to wait (the stationlink
// default when zero), and a UCAN and its proofs for a gated procedure.
type Call struct {
	Realm     [32]byte
	Procedure string
	Provider  [32]byte
	Payload   cbor.Value
	Timeout   time.Duration
	Token     []byte
	Proofs    [][]byte
	// Confidential is whether the call is sealed (macula 13, E2E design
	// §8.1), decided from the provider's verified advertisement only:
	// ConfidentialPreferred (zero) seals whenever it names a KEM key and
	// sends in the clear only to one that names none; ConfidentialRequired
	// never calls one that names none (no_kem_key). ConfidentialOff is
	// ErrConfidentialOff: a clear call is an explicit target's
	// (stationlink.Call). A sealed call never falls back to the clear.
	Confidential stationlink.Confidentiality
}

// Provider is a node serving a procedure, and the station it serves from.
type Provider struct {
	Node    [32]byte
	Station [32]byte
}

// candidate is a trusted advertisement: its provider, serving station and
// expiry.
type candidate struct {
	Provider
	expiresAt int64
	createdAt int64
	// kemKey is the KEM key the advertisement names, and kemKeyID its id;
	// nil when it names none.
	kemKey   []byte
	kemKeyID [seal.KeyIDSize]byte
}

type resolvedKey struct {
	realm     [32]byte
	procedure string
	provider  [32]byte
}

// Call calls a procedure at a provider that serves it, as macula 12 calls
// one: it resolves the procedure's advertisements from the DHT, keeps those
// the realm's pinned key authorizes (or, in a node's own namespace, those that
// node signed), and tries the freshest first,
// dialing the serving station the advertisement names, pinned by its node_id
// from its own station_endpoint record, and calling the provider there. It
// moves on to the next candidate only when a station cannot be reached within
// that candidate's share of the deadline, before anything is sent: once the
// CALL has gone out, under the whole deadline, its outcome is returned as it
// is, a timeout included, so one Call reaches a provider at most once
// (macula's call_work and failure_scope/1). A candidate that answered is
// remembered until its advertisement expires.
func (p *Pool) Call(ctx context.Context, c Call) (cbor.Value, error) {
	if c.Confidential == stationlink.ConfidentialOff {
		return cbor.Value{}, ErrConfidentialOff
	}
	realmKey, err := p.realmKeyFor(c.Realm, c.Procedure)
	if err != nil {
		return cbor.Value{}, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = stationlink.DefaultCallTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	key := resolvedKey{c.Realm, c.Procedure, c.Provider}
	candidates, err := p.candidates(ctx, key, realmKey)
	if err != nil {
		return cbor.Value{}, err
	}
	var errs []error
	for i, cand := range candidates {
		sealTo, link, err := p.reach(ctx, cand, c.Confidential, len(candidates)-i)
		if err == nil {
			result, err := p.callAt(ctx, link, cand, c, sealTo)
			return result, p.settled(key, cand, err)
		}
		if err := p.unreached(ctx, err, errs); err != nil {
			return cbor.Value{}, err
		}
		p.forget(key)
		errs = append(errs, fmt.Errorf("provider %x at station %x: %w", cand.Node[:4], cand.Station[:4], err))
	}
	return cbor.Value{}, errors.Join(append([]error{ErrNoProvider}, errs...)...)
}

// reach is the key a call to cand is sealed to under conf (nil for the
// clear), and a link to its serving station, reached within the candidate's
// share of ctx's deadline with left candidates to try. Nothing is sent.
func (p *Pool) reach(ctx context.Context, cand candidate, conf stationlink.Confidentiality, left int) ([]byte, *stationlink.Link, error) {
	sealTo, err := p.sealTo(cand, conf)
	if err != nil {
		return nil, nil, err
	}
	share, cancel := context.WithTimeout(ctx, candidateShare(ctx, left))
	defer cancel()
	link, err := p.linkTo(share, cand.Station)
	return sealTo, link, err
}

// unreached is the error that ends a call whose candidate was not reached,
// nil when the next candidate is worth trying: a confidentiality failure,
// which every candidate would meet alike (macula's request scope), the call's
// own deadline, or the pool closing under it.
func (p *Pool) unreached(ctx context.Context, err error, errs []error) error {
	switch {
	case answeredConfidentially(err):
		return err
	case ctx.Err() != nil:
		return errors.Join(append(errs, err)...)
	case p.isClosed():
		return errors.Join(ErrClosed, err)
	}
	return nil
}

// settled is the outcome of a call or stream sent to cand, final whatever it
// is: a CALL that went out is never sent again elsewhere. A candidate whose
// provider answered is remembered, one that did not is forgotten.
func (p *Pool) settled(key resolvedKey, cand candidate, err error) error {
	var provided *stationlink.ProviderError
	switch {
	case err == nil, errors.As(err, &provided):
		p.rememberCandidate(key, cand)
		return err
	case answeredConfidentially(err):
		return err
	case p.isClosed():
		// The provider did not fail: this pool closed under the call.
		return errors.Join(ErrClosed, err)
	}
	p.forget(key)
	return err
}

// Providers is every provider whose advertisement of procedure in realm the
// realm's pinned key authorizes, with the station each serves from, freshest
// first.
func (p *Pool) Providers(ctx context.Context, realm [32]byte, procedure string) ([]Provider, error) {
	realmKey, err := p.realmKeyFor(realm, procedure)
	if err != nil {
		return nil, err
	}
	candidates, err := p.resolve(ctx, resolvedKey{realm: realm, procedure: procedure}, realmKey)
	if err != nil {
		return nil, err
	}
	out := make([]Provider, len(candidates))
	for i, cand := range candidates {
		out[i] = cand.Provider
	}
	return out, nil
}

// candidates is the remembered candidate while it lives and its station is
// linked, else the procedure's trusted advertisements from the DHT.
func (p *Pool) candidates(ctx context.Context, key resolvedKey, realmKey []byte) ([]candidate, error) {
	p.mu.Lock()
	remembered, held := p.remember[key]
	p.mu.Unlock()
	if held && remembered.expiresAt > time.Now().UnixMilli() && p.linkedTo(remembered.Station) != nil {
		return []candidate{remembered}, nil
	}
	return p.resolve(ctx, key, realmKey)
}

// resolve finds the procedure's advertisements and keeps the ones the realm
// key authorizes, by key.provider when it is set, freshest first.
func (p *Pool) resolve(ctx context.Context, key resolvedKey, realmKey []byte) ([]candidate, error) {
	found, _, err := p.FindRecords(ctx, record.ProcedureKey(key.realm, key.procedure))
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	trust := record.Trust{Profile: p.key.Profile(), RealmKey: realmKey}
	var out []candidate
	for _, verified := range found {
		r := verified.Record()
		if r.Type != record.TypeProcedureAdvertisement {
			continue
		}
		ad, err := record.ReadProcedureAdvertisement(r)
		if err != nil || ad.RealmID != key.realm || ad.Procedure != key.procedure {
			continue
		}
		if key.provider != ([32]byte{}) && ad.AdvertiserNode != key.provider {
			continue
		}
		if record.VerifyAuthorization(verified, trust, now) != nil {
			continue
		}
		out = append(out, candidate{Provider: Provider{Node: ad.AdvertiserNode, Station: ad.ServingStation},
			expiresAt: int64(r.ExpiresAt), createdAt: int64(r.CreatedAt), kemKey: ad.KEMKey, kemKeyID: ad.KEMKeyID})
	}
	if len(out) == 0 {
		return nil, ErrNoProvider
	}
	slices.SortFunc(out, func(a, b candidate) int { return cmp.Compare(b.createdAt, a.createdAt) })
	return out, nil
}

// callAt calls the candidate's provider on link, to its serving station,
// sealed to sealTo (the clear when nil), under what is left of ctx's
// deadline. A sealed call the provider refuses sealed_refused is sealed
// again, once, under a new request, to the key a fresh lookup of its
// advertisement names, when that is the key the refusal named (macula 13,
// amendment A1).
func (p *Pool) callAt(ctx context.Context, link *stationlink.Link, cand candidate, c Call, sealTo []byte) (cbor.Value, error) {
	call := stationlink.Call{Realm: c.Realm, Procedure: c.Procedure, Target: cand.Node,
		Payload: c.Payload, Timeout: time.Until(deadlineOf(ctx)), Token: c.Token, Proofs: c.Proofs, SealTo: sealTo, Clear: sealTo == nil}
	result, err := link.Call(ctx, call)
	var refused *stationlink.SealedRefusedError
	if !errors.As(err, &refused) {
		return result, err
	}
	if call.SealTo, err = p.resealed(ctx, resolvedKey{c.Realm, c.Procedure, cand.Node}, cand.Node, refused.Named); err != nil {
		return cbor.Value{}, err
	}
	call.Timeout = time.Until(deadlineOf(ctx))
	return link.Call(ctx, call)
}

// sealTo is the key a call to cand is sealed to under conf, nil for a clear
// call: the key its advertisement names; none when it names none, unless conf
// requires one. A named key not of this pool's profile is no_kem_key.
func (p *Pool) sealTo(cand candidate, conf stationlink.Confidentiality) ([]byte, error) {
	switch {
	case cand.kemKey == nil && conf == stationlink.ConfidentialRequired:
		return nil, &stationlink.ConfidentialityError{Reason: stationlink.ReasonNoKEMKey}
	case cand.kemKey == nil:
		return nil, nil
	case len(cand.kemKey) != seal.CarriedSize(p.key.Profile()):
		return nil, &stationlink.ConfidentialityError{Reason: stationlink.ReasonNoKEMKey}
	}
	return cand.kemKey, nil
}

// resealed looks the provider's advertisement up once more, past what the
// pool remembers, and gives the key to seal to again (resealKey).
func (p *Pool) resealed(ctx context.Context, key resolvedKey, node [32]byte, named *[seal.KeyIDSize]byte) ([]byte, error) {
	p.forget(key)
	// A lookup that fails finds nothing, as macula's providers_ads/5 reads
	// it: resealKey then fails closed, no_kem_key, and the call ends.
	var fresh []candidate
	if realmKey, err := p.realmKeyFor(key.realm, key.procedure); err == nil {
		fresh, _ = p.resolve(ctx, key, realmKey)
	}
	return resealKey(node, named, fresh)
}

// resealKey is the key a call refused sealed_refused is sealed to again, from
// node's freshly resolved advertisements, as macula's resealed/7 picks it:
// when the refusal named a key, that key if any advertisement names it (the
// DHT may still serve the one before a rotation), else key_mismatch naming
// the first key one names, else no_kem_key; when the provider holds none, the
// first key one names, else no_kem_key. It never gives the clear.
func resealKey(node [32]byte, named *[seal.KeyIDSize]byte, fresh []candidate) ([]byte, error) {
	var first *candidate
	for i, c := range fresh {
		switch {
		case c.Node != node || c.kemKey == nil:
			continue
		case named != nil && c.kemKeyID == *named:
			return c.kemKey, nil
		case first == nil:
			first = &fresh[i]
		}
	}
	switch {
	case first == nil:
		return nil, &stationlink.ConfidentialityError{Reason: stationlink.ReasonNoKEMKey}
	case named != nil:
		found := first.kemKeyID
		return nil, &stationlink.ConfidentialityError{Reason: stationlink.ReasonKeyMismatch, Named: named, Found: &found}
	}
	return first.kemKey, nil
}

// answeredConfidentially reports whether err is a provider's answer, or a
// confidentiality failure, that ends a call rather than moving it to the next
// candidate: every one, as macula's failure_scope/1 scopes them to the
// request. The next candidate might be keyless, and a call sealed once is
// never sent in the clear.
func answeredConfidentially(err error) bool {
	var confidentiality *stationlink.ConfidentialityError
	var refused *stationlink.SealedRefusedError
	return errors.As(err, &confidentiality) || errors.As(err, &refused) || errors.Is(err, stationlink.ErrClearAnswerToSealed)
}

// candidateShare is one candidate's part of what is left of ctx's deadline
// with left candidates to try, at least a second, as macula shares it.
func candidateShare(ctx context.Context, left int) time.Duration {
	return max(time.Until(deadlineOf(ctx))/time.Duration(left), minCandidateShare)
}

const minCandidateShare = time.Second

func deadlineOf(ctx context.Context) time.Time {
	deadline, _ := ctx.Deadline()
	return deadline
}

// linkedTo is the link up now to station, or nil.
func (p *Pool) linkedTo(station [32]byte) *stationlink.Link {
	for _, link := range p.links() {
		if link.StationNodeID() == station {
			return link
		}
	}
	return nil
}

// linkTo is a link to station: one the pool holds, or a direct link it dials
// to the address in the station's own endpoint record, pinned by its node_id.
// A direct link that does not come up on its first dial is not kept.
func (p *Pool) linkTo(ctx context.Context, station [32]byte) (*stationlink.Link, error) {
	if link := p.linkedTo(station); link != nil {
		return link, nil
	}
	p.mu.Lock()
	var existing *member
	direct := 0
	for _, m := range p.members {
		if m.target.ExpectedNodeID == station {
			existing = m
		}
		if m.direct {
			direct++
		}
	}
	p.mu.Unlock()
	fresh := existing == nil
	if fresh {
		if direct >= p.opts.MaxDirectLinks {
			return nil, ErrDirectLinksFull
		}
		target, err := p.endpointOf(ctx, station)
		if err != nil {
			return nil, err
		}
		existing = p.startMember(target, true)
	}
	if link := existing.awaitUp(ctx, fresh); link != nil {
		return link, nil
	}
	if fresh {
		p.drop(existing)
	}
	return nil, fmt.Errorf("pool: station %x not reached: %w", station[:4], errors.Join(ctx.Err(), existing.lastErr()))
}

// endpointOf is where station is dialed, from the station_endpoint record the
// station signed itself.
func (p *Pool) endpointOf(ctx context.Context, station [32]byte) (transport.Target, error) {
	verified, err := p.FindRecord(ctx, record.StationEndpointKey(station))
	if err != nil {
		return transport.Target{}, fmt.Errorf("%w: %w", ErrNoStationEndpoint, err)
	}
	r := verified.Record()
	endpoint, err := record.ReadStationEndpoint(r)
	if err != nil || r.KeyID != station || endpoint.QUICPort == 0 || len(endpoint.HostAdvertised) == 0 {
		return transport.Target{}, ErrNoStationEndpoint
	}
	return transport.Target{Host: endpoint.HostAdvertised[0], Port: endpoint.QUICPort, Profile: p.key.Profile(),
		ExpectedNodeID: station}, nil
}

func (p *Pool) rememberCandidate(key resolvedKey, cand candidate) {
	p.mu.Lock()
	p.remember[key] = cand
	p.mu.Unlock()
}

func (p *Pool) forget(key resolvedKey) {
	p.mu.Lock()
	delete(p.remember, key)
	p.mu.Unlock()
}

// FindRecord asks the pool's links in turn for the record under key, until one
// answers.
func (p *Pool) FindRecord(ctx context.Context, key [32]byte) (record.Verified, error) {
	return firstAnswer(p, func(link *stationlink.Link) (record.Verified, error) { return link.FindRecord(ctx, key) })
}

// FindRecords asks the pool's links in turn for the records under key.
func (p *Pool) FindRecords(ctx context.Context, key [32]byte) ([]record.Verified, int, error) {
	type found struct {
		records []record.Verified
		dropped int
	}
	out, err := firstAnswer(p, func(link *stationlink.Link) (found, error) {
		records, dropped, err := link.FindRecords(ctx, key)
		return found{records, dropped}, err
	})
	return out.records, out.dropped, err
}

// FindRecordsByType asks the pool's links in turn for the records of type t.
func (p *Pool) FindRecordsByType(ctx context.Context, t record.Type) ([]record.Verified, int, error) {
	type found struct {
		records []record.Verified
		dropped int
	}
	out, err := firstAnswer(p, func(link *stationlink.Link) (found, error) {
		records, dropped, err := link.FindRecordsByType(ctx, t)
		return found{records, dropped}, err
	})
	return out.records, out.dropped, err
}

// PutRecord puts a signed record through the pool's links in turn, until one
// station takes it.
func (p *Pool) PutRecord(ctx context.Context, wire []byte) error {
	_, err := firstAnswer(p, func(link *stationlink.Link) (struct{}, error) {
		return struct{}{}, link.PutRecord(ctx, wire)
	})
	return err
}

// firstAnswer runs ask on the pool's links in selection order and returns the
// first answer, moving on only when a link could not be asked: a station's
// own answer, not_found included, is final.
func firstAnswer[T any](p *Pool, ask func(*stationlink.Link) (T, error)) (T, error) {
	var zero T
	links := p.links()
	if len(links) == 0 {
		return zero, ErrNoLink
	}
	var errs []error
	for _, link := range links {
		out, err := ask(link)
		if err == nil || !unreachable(err) {
			return out, err
		}
		errs = append(errs, err)
	}
	return zero, errors.Join(errs...)
}

// unreachable is a failure to reach the station at all, as opposed to its
// answer.
func unreachable(err error) bool {
	return errors.Is(err, stationlink.ErrCallTimeout) || errors.Is(err, stationlink.ErrClosed) ||
		errors.Is(err, stationlink.ErrLivenessLost)
}

// StreamCall is a streaming session to open on an org procedure: its realm and
// name, the provider (any trusted one when zero), the mode, the open's payload,
// its deadline (the stationlink default when zero), and a UCAN and its proofs
// for a gated procedure.
type StreamCall struct {
	Realm     [32]byte
	Procedure string
	Provider  [32]byte
	Mode      frame.StreamMode
	Payload   cbor.Value
	Deadline  time.Duration
	Token     []byte
	Proofs    [][]byte
	// Confidential is whether the stream is sealed, as Call.Confidential
	// (ConfidentialOff is ErrConfidentialOff).
	Confidential stationlink.Confidentiality
}

// OpenStream opens a streaming session at a provider of the procedure, reached
// as Call reaches one: its trusted advertisements from the DHT, freshest
// first, its serving station dialed pinned, the next candidate only when a
// station cannot be reached; the link's own outcome is final. The stream is
// open once its STREAM_OPEN is sent; a provider's or station's refusal
// arrives on its first Recv.
func (p *Pool) OpenStream(ctx context.Context, c StreamCall) (*stationlink.Stream, error) {
	if c.Confidential == stationlink.ConfidentialOff {
		return nil, ErrConfidentialOff
	}
	realmKey, err := p.realmKeyFor(c.Realm, c.Procedure)
	if err != nil {
		return nil, err
	}
	key := resolvedKey{c.Realm, c.Procedure, c.Provider}
	candidates, err := p.candidates(ctx, key, realmKey)
	if err != nil {
		return nil, err
	}
	var errs []error
	for i, cand := range candidates {
		sealTo, link, err := p.reach(ctx, cand, c.Confidential, len(candidates)-i)
		if err == nil {
			stream, err := p.openAt(ctx, link, cand, c, sealTo)
			return stream, p.settled(key, cand, err)
		}
		if err := p.unreached(ctx, err, errs); err != nil {
			return nil, err
		}
		p.forget(key)
		errs = append(errs, fmt.Errorf("provider %x at station %x: %w", cand.Node[:4], cand.Station[:4], err))
	}
	return nil, errors.Join(append([]error{ErrNoProvider}, errs...)...)
}

// openAt opens the stream at the candidate's provider on link, sealed to
// sealTo (the clear when nil).
func (p *Pool) openAt(ctx context.Context, link *stationlink.Link, cand candidate, c StreamCall, sealTo []byte) (*stationlink.Stream, error) {
	call := stationlink.StreamCall{Realm: c.Realm, Procedure: c.Procedure, Target: cand.Node,
		Mode: c.Mode, Payload: c.Payload, Deadline: c.Deadline, Token: c.Token, Proofs: c.Proofs, SealTo: sealTo, Clear: sealTo == nil}
	if sealTo != nil {
		// Refused sealed_refused before it has sent anything, the stream
		// reseals once to the key a fresh lookup confirms (amendment A1).
		key := resolvedKey{c.Realm, c.Procedure, cand.Node}
		call.Reseal = func(named *[seal.KeyIDSize]byte) ([]byte, error) {
			ctx, cancel := context.WithTimeout(context.Background(), stationlink.DefaultCallTimeout)
			defer cancel()
			return p.resealed(ctx, key, cand.Node, named)
		}
	}
	return link.OpenStream(ctx, call)
}
