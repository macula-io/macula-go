package pool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/group"
	"github.com/macula-io/macula-go/internal/redact"
	"github.com/macula-io/macula-go/stationlink"
)

// Group names the sealed group a publish or subscribe is under (macula 13.2,
// DESIGN_E2E_SEALED_PUBSUB.md §7): its prefix, which the topic must be under
// and whose second segment is its org; the org's grant, a UCAN carrying
// can "group_keys", presented on every key pull; and the distributor's node
// id when it must be that node.
type Group struct {
	Prefix      string
	UCAN        []byte
	Distributor *[32]byte
}

// String writes the Group without its credential: the grant and proofs
// show by size only.
func (g Group) String() string { return redact.Struct(g, "UCAN") }

// Format writes it as String does, whatever the verb, so %+v and %#v never
// print the credential either.
func (g Group) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, g.String()) }

// LogValue writes it as String does, so slog's JSON handler, which never
// asks fmt, does not print the credential either.
func (g Group) LogValue() slog.Value { return slog.StringValue(g.String()) }

// GroupHeldError is a publish in the clear under a prefix whose group this
// node holds: it names the prefix, and is refused rather than sent in the
// clear or silently sealed.
type GroupHeldError struct{ Prefix string }

func (e *GroupHeldError) Error() string {
	return fmt.Sprintf("pool: %q is a sealed group this node holds; publish under it with its Group", e.Prefix)
}

// groups is the pool's keyring, made with the pool: one per node identity,
// pulling over the pool's own sealed calls.
func (p *Pool) groups() *group.Keyring {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.keyring == nil {
		p.keyring = group.NewKeyring(group.Options{Pull: p.pullGroupKey})
		if p.closed {
			// A pool that has closed holds nothing: the keyring answers
			// every join ErrNotJoined and schedules no re-pull.
			p.keyring.Close()
		}
	}
	return p.keyring
}

// pullGroupKey is one key pull: a call sealed to the distributor's KEM key,
// never in the clear.
func (p *Pool) pullGroupKey(ctx context.Context, pl group.Pull) (cbor.Value, [32]byte, error) {
	result, report, err := p.CallReport(ctx, Call{Realm: pl.Realm, Procedure: pl.Procedure, Provider: pl.Provider,
		Payload: pl.Payload, Token: pl.Token, Confidential: stationlink.ConfidentialRequired})
	// Only no advertisement at all is "not advertised": candidates that
	// could not be reached come joined with their errors, and keep the
	// group's distributor, as macula keeps it on anything but
	// provider_not_advertised.
	if err == ErrNoProvider {
		err = errors.Join(group.ErrNotAdvertised, err)
	}
	return result, report.Provider, err
}

// checkedGroup checks a group against its topic before anything is sent.
func checkedGroup(topic string, g Group) error {
	if _, err := group.OrgOf(g.Prefix); err != nil {
		return err
	}
	if !group.Under(topic, g.Prefix) {
		return fmt.Errorf("%w: topic %q is not under %q", group.ErrInvalidGroup, topic, g.Prefix)
	}
	return nil
}

// PublishGroup publishes pub sealed under g's current epoch: joining the
// group first when it is not held, then sealing with the publisher's own
// subkey of the epoch key, a fresh random nonce, and the event AAD. A
// publisher whose epochs have all stopped publishing pulls at once, and the
// publish fails closed with that pull's error (a *group.Error).
func (p *Pool) PublishGroup(ctx context.Context, pub stationlink.Publication, g Group) error {
	if err := checkedGroup(pub.Topic, g); err != nil {
		return err
	}
	keyring := p.groups()
	if _, err := keyring.Join(ctx, pub.Realm, g.Prefix, group.JoinOptions{UCAN: g.UCAN, Distributor: g.Distributor}); err != nil {
		return err
	}
	epoch, err := keyring.PublishEpoch(ctx, pub.Realm, g.Prefix)
	if err != nil {
		return err
	}
	pub.Seal = func(f stationlink.SealFields) (frame.Sealed, error) {
		return group.SealEvent(epoch, group.Fields{Realm: f.Realm, Topic: f.Topic, Publisher: f.Publisher, Seq: f.Seq,
			PublishedAt: f.PublishedAt}, f.Payload)
	}
	return p.publish(pub)
}

// SubscribeGroup subscribes to topic in realm under g: it joins the group
// first, failing with the join's refusal, and then delivers each sealed
// event opened, or once with Unopened set and no payload when it cannot be
// opened. Under a Required group a clear event is refused and counted;
// under any other group it is delivered with Sealed nil, and any realm member
// can publish one, so check Sealed before taking an event as the group's.
func (p *Pool) SubscribeGroup(ctx context.Context, realm [32]byte, topic string, g Group) (*Subscription, error) {
	if err := checkedGroup(topic, g); err != nil {
		return nil, err
	}
	if _, err := p.groups().Join(ctx, realm, g.Prefix, group.JoinOptions{UCAN: g.UCAN, Distributor: g.Distributor}); err != nil {
		return nil, err
	}
	return p.subscribe(realm, topic, g.Prefix)
}

// opened is a received event as its subscription delivers it, or false when
// it is refused: a sealed event opened under its group, or marked unopened;
// a clear event refused under a Required group the node holds.
func (s *Subscription) opened(ctx context.Context, e stationlink.Event) (stationlink.Event, bool) {
	keyring := s.pool.heldGroups()
	if e.Sealed == nil {
		if keyring != nil {
			if _, policy, held := keyring.Policy(e.Realm, e.Topic); held && policy == group.PolicyRequired {
				return e, false
			}
		}
		return e, true
	}
	if s.group == "" || keyring == nil {
		e.Unopened = string(group.ReasonNoGroup)
		return e, true
	}
	if !e.Sealed.KnownScheme() {
		e.Unopened = string(group.ReasonTagInvalid)
		return e, true
	}
	epoch, err := keyring.OpenEpoch(ctx, e.Realm, s.group, e.Sealed.KeyID, e.Publisher)
	if err != nil {
		reason, named := group.ReasonOf(err)
		if !named {
			reason = group.ReasonNoGroup
		}
		e.Unopened = string(reason)
		return e, true
	}
	payload, err := group.OpenEvent(epoch, group.Fields{Realm: e.Realm, Topic: e.Topic, Publisher: e.Publisher,
		Seq: e.Seq, PublishedAt: e.PublishedAt}, *e.Sealed)
	if err != nil {
		e.Unopened = string(group.ReasonTagInvalid)
		return e, true
	}
	e.Payload = payload
	return e, true
}

// heldGroups is the pool's keyring, nil while no group was ever joined.
func (p *Pool) heldGroups() *group.Keyring {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keyring
}
