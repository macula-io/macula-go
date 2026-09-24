// Command goneighbour writes the control frames a client link sends, built and
// neighbour-signed by macula-go (unsigned in pq_pure), for macula's
// macula_frame to verify. See scripts/interop/erlang_neighbour.escript.
//
//	go run ./scripts/interop/goneighbour <go_neighbour.json>
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

type sent struct {
	FrameType string `json:"frame_type"`
	Seq       uint64 `json:"seq"`
	Bytes     string `json:"bytes"`
}

type entry struct {
	Profile    string `json:"profile"`
	PeerKey    string `json:"peer_key"`
	Connection string `json:"connection"`
	Frames     []sent `json:"frames"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: goneighbour <go_neighbour.json>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "goneighbour:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	var entries []entry
	for _, p := range []profile.Profile{profile.PQHybrid, profile.PQPure} {
		e, err := framesFor(p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		entries = append(entries, e)
	}
	encoded, err := json.MarshalIndent(map[string]any{"entries": entries}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("goneighbour: wrote control frames for %d profiles\n", len(entries))
	return os.WriteFile(out, encoded, 0o644)
}

func framesFor(p profile.Profile) (entry, error) {
	key, err := identity.GenerateKey(identity.PurposeIdentity, p)
	if err != nil {
		return entry{}, err
	}
	var connection [48]byte
	if _, err := rand.Read(connection[:]); err != nil {
		return entry{}, err
	}
	realm, subscriber := [32]byte{3}, [32]byte{1}
	topic := []byte("io.macula/mcl-news/news/wire/news_item_reported_v1")
	subscribe, err := frame.SubscribeFrame(topic, realm, subscriber)
	if err != nil {
		return entry{}, err
	}
	unsubscribe, err := frame.UnsubscribeFrame(topic, realm, subscriber)
	if err != nil {
		return entry{}, err
	}
	goodbye, err := frame.GoodbyeFrame("normal", []byte("closing"))
	if err != nil {
		return entry{}, err
	}
	built := []struct {
		name  string
		frame cbor.Value
	}{
		{"advertise", frame.AdvertiseFrame([]byte("a signed procedure_advertisement record"))},
		{"unadvertise", frame.UnadvertiseFrame([]byte("a signed withdrawal record"))},
		{"subscribe", subscribe},
		{"unsubscribe", unsubscribe},
		{"goodbye", goodbye},
	}
	e := entry{Profile: string(p), PeerKey: hex.EncodeToString(key.PublicKey()), Connection: hex.EncodeToString(connection[:])}
	for seq, b := range built {
		signed, err := frame.SignNeighbour(b.frame, key, frame.NeighbourLink{Connection: connection, Seq: uint64(seq)})
		if err != nil {
			return entry{}, fmt.Errorf("sign %s: %w", b.name, err)
		}
		wire, err := frame.Encode(signed)
		if err != nil {
			return entry{}, fmt.Errorf("encode %s: %w", b.name, err)
		}
		e.Frames = append(e.Frames, sent{FrameType: b.name, Seq: uint64(seq), Bytes: hex.EncodeToString(wire)})
	}
	return e, nil
}
