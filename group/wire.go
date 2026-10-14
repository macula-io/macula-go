package group

import (
	"errors"

	"github.com/macula-io/macula-go/cbor"
)

// Policy is a group's policy as its distributor answers it: Required refuses
// clear events under the prefix, Preferred seals and accepts clear ones, Off
// accepts clear events too. Once a node has seen Preferred or Required for a
// prefix it never accepts Off for it.
type Policy string

const (
	PolicyRequired  Policy = "required"
	PolicyPreferred Policy = "preferred"
	PolicyOff       Policy = "off"
)

// Procedure is the distributor's procedure for org's groups.
func Procedure(org string) string { return org + "/group_keys_v1" }

// CurrentRequest is the pull of a group's current epoch, the CALL payload
// `{prefix, epoch: "current"}`.
func CurrentRequest(prefix string) cbor.Value {
	return request(prefix, cbor.Text("current"))
}

// ByIDRequest is the pull of a group's epoch by id, the CALL payload
// `{prefix, epoch: <8 bytes>}`.
func ByIDRequest(prefix string, id [IDSize]byte) cbor.Value {
	return request(prefix, cbor.Bytes(id[:]))
}

func request(prefix string, epoch cbor.Value) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("prefix"), Val: cbor.Text(prefix)},
		{Key: cbor.Text("epoch"), Val: epoch},
	})
}

// Reply is a distributor's answer to a pull: the policy and the epochs it
// handed out (the asked one, and the next inside the ahead window).
type Reply struct {
	Prefix string
	Policy Policy
	Epochs []Epoch
}

// ErrMalformedReply is a reply that is not the protocol's: the asked prefix
// not echoed, no policy of the three, no epoch, or an epoch whose id, key or
// times are not the protocol's. Nothing of it is held.
var ErrMalformedReply = errors.New("group: the distributor's reply is not group_keys_v1's")

// ParseReply reads a distributor's RESULT for a pull of prefix, as
// macula_group_keyring reads one.
func ParseReply(prefix string, v cbor.Value) (Reply, error) {
	echoed, ok := text(v, "prefix")
	if !ok || echoed != prefix {
		return Reply{}, ErrMalformedReply
	}
	policyText, _ := text(v, "policy")
	policy := Policy(policyText)
	if policy != PolicyRequired && policy != PolicyPreferred && policy != PolicyOff {
		return Reply{}, ErrMalformedReply
	}
	list, _ := v.Get("epochs")
	items, ok := list.AsList()
	if !ok || len(items) == 0 {
		return Reply{}, ErrMalformedReply
	}
	epochs := make([]Epoch, 0, len(items))
	for _, item := range items {
		e, ok := epochOf(item)
		if !ok {
			return Reply{}, ErrMalformedReply
		}
		epochs = append(epochs, e)
	}
	return Reply{Prefix: prefix, Policy: policy, Epochs: epochs}, nil
}

// ReplyValue is the RESULT payload for r, as a distributor answers: what
// the vectors pin, byte for byte.
func ReplyValue(r Reply) cbor.Value {
	epochs := make([]cbor.Value, 0, len(r.Epochs))
	for _, e := range r.Epochs {
		epochs = append(epochs, cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("id"), Val: cbor.Bytes(e.ID[:])},
			{Key: cbor.Text("key"), Val: cbor.Bytes(e.Key[:])},
			{Key: cbor.Text("issued_at"), Val: cbor.Int(e.IssuedAt)},
			{Key: cbor.Text("publish_until"), Val: cbor.Int(e.PublishUntil)},
			{Key: cbor.Text("accept_until"), Val: cbor.Int(e.AcceptUntil)},
		}))
	}
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("prefix"), Val: cbor.Text(r.Prefix)},
		{Key: cbor.Text("policy"), Val: cbor.Text(string(r.Policy))},
		{Key: cbor.Text("epochs"), Val: cbor.List(epochs)},
	})
}

// epochOf reads one epoch: an 8-byte id, a 32-byte key, and times where it
// is issued before it stops publishing and is accepted exactly the life of
// an event past that.
func epochOf(v cbor.Value) (Epoch, bool) {
	id, okID := fixed(v, "id", IDSize)
	key, okKey := fixed(v, "key", KeySize)
	issued, okI := integer(v, "issued_at")
	publish, okP := integer(v, "publish_until")
	accept, okA := integer(v, "accept_until")
	if !okID || !okKey || !okI || !okP || !okA || issued >= publish || accept != publish+eventLifeMs {
		return Epoch{}, false
	}
	e := Epoch{IssuedAt: issued, PublishUntil: publish, AcceptUntil: accept}
	copy(e.ID[:], id)
	copy(e.Key[:], key)
	return e, true
}

func text(v cbor.Value, name string) (string, bool) {
	field, _ := v.Get(name)
	return field.AsText()
}

func integer(v cbor.Value, name string) (int64, bool) {
	field, has := v.Get(name)
	if !has || field.Kind() != cbor.KindUInt {
		return 0, false
	}
	return field.AsInt64()
}

func fixed(v cbor.Value, name string, size int) ([]byte, bool) {
	field, _ := v.Get(name)
	b, ok := field.AsBytes()
	return b, ok && len(b) == size
}
