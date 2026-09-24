// Package meshflags is the command line every example joins the mesh with: the
// station to link to, pinned by its node_id, the realm and its key, and the
// node's identity key file, created on first use.
package meshflags

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
)

// Flags are the parsed flags.
type Flags struct {
	seed, station, realm, realmKeyFile, keyFile, profile *string
}

// Register adds the mesh flags to the default flag set.
func Register() Flags {
	return Flags{
		seed:         flag.String("seed", "", "station host:port, e.g. [2a01:4f8::1]:4433"),
		station:      flag.String("station", "", "the station's node_id, 64 hex"),
		realm:        flag.String("realm", "", "the realm id, 64 hex"),
		realmKeyFile: flag.String("realm-key", "", "file holding the realm key as carried, in hex, as the realm publishes it"),
		keyFile:      flag.String("key", "node.key", "this node's identity key file, created when absent"),
		profile:      flag.String("profile", "pq_hybrid", "crypto profile: pq_pure or pq_hybrid"),
	}
}

// Realm is the realm id.
func (f Flags) Realm() ([32]byte, error) {
	return hex32("-realm", *f.realm)
}

// Connect loads or creates the node key and connects a pool to the seed,
// pinning the realm's key.
func (f Flags) Connect(ctx context.Context) (*pool.Pool, error) {
	p, err := profile.Parse(*f.profile)
	if err != nil {
		return nil, err
	}
	host, portText, err := net.SplitHostPort(*f.seed)
	if err != nil {
		return nil, fmt.Errorf("-seed: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("-seed port: %w", err)
	}
	station, err := hex32("-station", *f.station)
	if err != nil {
		return nil, err
	}
	realm, err := f.Realm()
	if err != nil {
		return nil, err
	}
	text, err := os.ReadFile(*f.realmKeyFile)
	if err != nil {
		return nil, fmt.Errorf("-realm-key: %w", err)
	}
	realmKey, err := hex.DecodeString(strings.TrimSpace(string(text)))
	if err != nil {
		return nil, fmt.Errorf("-realm-key: %w", err)
	}
	key, err := nodeKey(*f.keyFile, p)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return pool.Connect(ctx, []pool.Seed{{Host: host, Port: uint16(port), NodeID: station}},
		pool.Opts{IdentityKey: key, RealmTrust: map[[32]byte][]byte{realm: realmKey}})
}

// nodeKey loads the identity key at path, or creates one there: a new key
// solves the admission puzzle, which takes a few seconds.
func nodeKey(path string, p profile.Profile) (*identity.NodeKey, error) {
	key, err := identity.LoadKey(path, identity.PurposeIdentity, p)
	if !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}
	fmt.Fprintf(os.Stderr, "creating the node key %s (solving the admission puzzle)\n", path)
	key, err = identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return nil, err
	}
	return key, key.Save(path)
}

func hex32(name, text string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		return out, fmt.Errorf("%s must be 64 hex", name)
	}
	copy(out[:], raw)
	return out, nil
}
