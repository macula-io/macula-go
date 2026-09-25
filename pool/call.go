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
// moves on to the next candidate when a station cannot be reached or reports
// it cannot relay the call, and returns a provider's own answer or error as
// it is. A candidate that answered is remembered until its advertisement
// expires.
func (p *Pool) Call(ctx context.Context, c Call) (cbor.Value, error) {
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
		share, cancelShare := context.WithTimeout(ctx, candidateShare(ctx, len(candidates)-i))
		result, err := p.callAt(share, cand, c)
		cancelShare()
		var provided *stationlink.ProviderError
		switch {
		case err == nil, errors.As(err, &provided):
			p.rememberCandidate(key, cand)
			return result, err
		case ctx.Err() != nil:
			return cbor.Value{}, errors.Join(append(errs, err)...)
		}
		p.forget(key)
		errs = append(errs, fmt.Errorf("provider %x at station %x: %w", cand.Node[:4], cand.Station[:4], err))
	}
	return cbor.Value{}, errors.Join(append([]error{ErrNoProvider}, errs...)...)
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
			expiresAt: int64(r.ExpiresAt), createdAt: int64(r.CreatedAt)})
	}
	if len(out) == 0 {
		return nil, ErrNoProvider
	}
	slices.SortFunc(out, func(a, b candidate) int { return cmp.Compare(b.createdAt, a.createdAt) })
	return out, nil
}

// callAt calls the candidate's provider at its serving station.
func (p *Pool) callAt(ctx context.Context, cand candidate, c Call) (cbor.Value, error) {
	link, err := p.linkTo(ctx, cand.Station)
	if err != nil {
		return cbor.Value{}, err
	}
	return link.Call(ctx, stationlink.Call{Realm: c.Realm, Procedure: c.Procedure, Target: cand.Node,
		Payload: c.Payload, Timeout: time.Until(deadlineOf(ctx)), Token: c.Token, Proofs: c.Proofs})
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
}

// OpenStream opens a streaming session at a provider of the procedure, reached
// as Call reaches one: its trusted advertisements from the DHT, freshest
// first, its serving station dialed pinned, the next candidate when a station
// cannot be reached. The stream is open once its STREAM_OPEN is sent; a
// provider's or station's refusal arrives on its first Recv.
func (p *Pool) OpenStream(ctx context.Context, c StreamCall) (*stationlink.Stream, error) {
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
		share, cancel := context.WithTimeout(ctx, candidateShare(ctx, len(candidates)-i))
		stream, err := p.openAt(share, cand, c)
		cancel()
		if err == nil {
			p.rememberCandidate(key, cand)
			return stream, nil
		}
		if ctx.Err() != nil {
			return nil, errors.Join(append(errs, err)...)
		}
		p.forget(key)
		errs = append(errs, fmt.Errorf("provider %x at station %x: %w", cand.Node[:4], cand.Station[:4], err))
	}
	return nil, errors.Join(append([]error{ErrNoProvider}, errs...)...)
}

func (p *Pool) openAt(ctx context.Context, cand candidate, c StreamCall) (*stationlink.Stream, error) {
	link, err := p.linkTo(ctx, cand.Station)
	if err != nil {
		return nil, err
	}
	return link.OpenStream(ctx, stationlink.StreamCall{Realm: c.Realm, Procedure: c.Procedure, Target: cand.Node,
		Mode: c.Mode, Payload: c.Payload, Deadline: c.Deadline, Token: c.Token, Proofs: c.Proofs})
}
