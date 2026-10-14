// Package group is the member side of sealed groups (macula 13.2,
// docs/design/DESIGN_E2E_SEALED_PUBSUB.md): a group is a topic prefix whose
// events are sealed under the group's current epoch key, which the org's
// distributor hands out over a sealed call, `<org>/group_keys_v1`, to members
// holding the org's grant. This package is the Go counterpart of macula's
// macula_group_epoch, macula_group_event and macula_group_keyring: epochs and
// their times, sealing and opening an event, the pull's payloads, and the
// Keyring a node holds its groups' epochs in. Epoch keys are held in memory
// only.
package group

import (
	"errors"
	"strings"
)

// The protocol's times, in milliseconds: an event lives at most 60 minutes
// of ttl plus 5 of tolerance, so an epoch is accepted that long past its
// publishing, and a verifier allows 5 minutes of clock skew.
const (
	DefaultRotateAfterMs = 15 * 60_000
	eventLifeMs          = 65 * 60_000
	toleranceMs          = 5 * 60_000
)

// IDSize is an epoch id, and KeySize an epoch key.
const (
	IDSize  = 8
	KeySize = 32
)

// Epoch is a group key for a stretch of time: its random id, which names it
// on every sealed event, its random key, independent of every other epoch's,
// and its times in Unix milliseconds. An event is sealed under it from
// IssuedAt until PublishUntil, and opened under it until AcceptUntil.
type Epoch struct {
	ID           [IDSize]byte
	Key          [KeySize]byte
	IssuedAt     int64
	PublishUntil int64
	AcceptUntil  int64
}

// rotation is how long the epoch publishes.
func (e Epoch) rotation() int64 { return e.PublishUntil - e.IssuedAt }

// aheadWindow is the epoch's ahead window, [from, to): the last third of its
// publishing stretch, when a pull is also handed the next epoch and every
// holder re-pulls.
func (e Epoch) aheadWindow() (from, to int64) {
	return e.PublishUntil - e.rotation()/3, e.PublishUntil
}

// repullAt is the instant a holder re-pulls: fraction (in [0, 1), drawn
// uniformly by the caller) of the way through the ahead window.
func (e Epoch) repullAt(fraction float64) int64 {
	from, to := e.aheadWindow()
	return from + int64(float64(to-from)*fraction)
}

// acceptable reports whether an event under the epoch is accepted at now:
// until its AcceptUntil, with the 5-minute clock tolerance.
func (e Epoch) acceptable(now int64) bool { return now <= e.AcceptUntil+toleranceMs }

// forPublish is the epoch a publisher seals under at now: the newest held
// epoch that has been issued and has not stopped publishing.
func forPublish(held []Epoch, now int64) (Epoch, bool) {
	var best Epoch
	found := false
	for _, e := range held {
		if e.IssuedAt <= now && now < e.PublishUntil && (!found || e.IssuedAt >= best.IssuedAt) {
			best, found = e, true
		}
	}
	return best, found
}

// live is the held epochs still of use at now.
func live(held []Epoch, now int64) []Epoch {
	kept := make([]Epoch, 0, len(held))
	for _, e := range held {
		if e.acceptable(now) {
			kept = append(kept, e)
		}
	}
	return kept
}

// ErrInvalidGroup is a prefix that cannot be a group: fewer than two
// segments, or an empty one.
var ErrInvalidGroup = errors.New("group: not a group prefix (realm/org/..., no empty segment)")

// OrgOf is a group prefix's org, its second segment: `io.macula/acme/chat` is
// owned by `acme`, and `_realm` there names a realm-wide group.
func OrgOf(prefix string) (string, error) {
	segments := strings.Split(prefix, "/")
	if len(segments) < 2 {
		return "", ErrInvalidGroup
	}
	for _, s := range segments {
		if s == "" {
			return "", ErrInvalidGroup
		}
	}
	return segments[1], nil
}

// Under reports whether topic is under prefix: equal to it, or the prefix
// followed by `/`, so `.../acme/chat` covers `.../acme/chat/room/said_v1` and
// not `.../acme/chatter`.
func Under(topic, prefix string) bool {
	return topic == prefix || strings.HasPrefix(topic, prefix+"/")
}
