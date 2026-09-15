// Command goartifacts writes signatures, node_ids, key ids, bindings and status
// statements made by macula-go, for macula's Erlang modules to check. See
// scripts/interop/run.sh.
//
//	go run ./scripts/interop/goartifacts <out dir>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

const (
	hourMs = int64(60 * 60 * 1000)
	dayMs  = 24 * hourMs
)

var leaf = []byte("a leaf certificate, as its listener presents it")

// keyArtifact is a node key's carried form with a signature it made, its
// node_id when it is an identity key, and its key id.
type keyArtifact struct {
	Profile   string `json:"profile"`
	Purpose   string `json:"purpose"`
	Key       string `json:"key"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
	NodeID    string `json:"node_id,omitempty"`
	KeyID     string `json:"key_id"`
}

type signedTBS struct {
	TBS       string `json:"tbs"`
	Signature string `json:"signature"`
}

// bindingArtifact is one profile's TLS and CONNECT bindings and status
// statements, made at NowMs.
type bindingArtifact struct {
	Profile        string    `json:"profile"`
	NowMs          int64     `json:"now_ms"`
	IdentityKey    string    `json:"identity_key"`
	NodeID         string    `json:"node_id"`
	Leaf           string    `json:"leaf"`
	TLSBinding     signedTBS `json:"tls_binding"`
	TLSStatus      signedTBS `json:"tls_status"`
	ConnectKey     string    `json:"connect_key"`
	ConnectBinding signedTBS `json:"connect_binding"`
	ConnectStatus  signedTBS `json:"connect_status"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: goartifacts <out dir>")
		os.Exit(2)
	}
	var keys []keyArtifact
	var bindings []bindingArtifact
	now := time.Now().UnixMilli()
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		for _, purpose := range []identity.Purpose{identity.PurposeIdentity, identity.PurposeConnect} {
			a, err := keyMade(p, purpose)
			exitOn(err, p)
			keys = append(keys, a)
		}
		b, err := bindingsMade(p, now)
		exitOn(err, p)
		bindings = append(bindings, b)
	}
	exitOn(writeJSON(filepath.Join(os.Args[1], "go_identity_artifacts.json"), keys), "identity artifacts")
	exitOn(writeJSON(filepath.Join(os.Args[1], "go_binding_artifacts.json"), bindings), "binding artifacts")
	fmt.Printf("goartifacts: wrote %d key artifacts and %d binding artifacts\n", len(keys), len(bindings))
}

func exitOn(err error, context any) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "goartifacts: %v: %v\n", context, err)
		os.Exit(1)
	}
}

func writeJSON(path string, v any) error {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}

func keyMade(p profile.Profile, purpose identity.Purpose) (keyArtifact, error) {
	key, err := identity.GenerateKey(purpose, p)
	if err != nil {
		return keyArtifact{}, err
	}
	message := []byte(fmt.Sprintf("made by macula-go for a %s %s key", p, purpose))
	signature, err := key.Sign(message)
	if err != nil {
		return keyArtifact{}, err
	}
	keyID := key.KeyID()
	a := keyArtifact{
		Profile:   string(p),
		Purpose:   string(purpose),
		Key:       hex.EncodeToString(key.PublicKey()),
		Message:   hex.EncodeToString(message),
		Signature: hex.EncodeToString(signature),
		KeyID:     hex.EncodeToString(keyID[:]),
	}
	if nodeID, err := key.NodeID(); err == nil {
		a.NodeID = hex.EncodeToString(nodeID[:])
	}
	return a, nil
}

func bindingsMade(p profile.Profile, now int64) (bindingArtifact, error) {
	identityKey, err := identity.GenerateKey(identity.PurposeIdentity, p)
	if err != nil {
		return bindingArtifact{}, err
	}
	connectKey, err := identity.GenerateKey(identity.PurposeConnect, p)
	if err != nil {
		return bindingArtifact{}, err
	}
	tlsBinding, err := identity.TLSBinding(identityKey, leaf, now, now+7*dayMs)
	if err != nil {
		return bindingArtifact{}, err
	}
	tlsStatus, err := identity.StatusStatement(identityKey, tlsBinding, now, now+hourMs)
	if err != nil {
		return bindingArtifact{}, err
	}
	connectBinding, err := identity.ConnectBinding(identityKey, connectKey.PublicKey(), now, now+7*dayMs)
	if err != nil {
		return bindingArtifact{}, err
	}
	connectStatus, err := identity.StatusStatement(identityKey, connectBinding, now, now+hourMs)
	if err != nil {
		return bindingArtifact{}, err
	}
	nodeID, err := identityKey.NodeID()
	if err != nil {
		return bindingArtifact{}, err
	}
	return bindingArtifact{
		Profile:        string(p),
		NowMs:          now,
		IdentityKey:    hex.EncodeToString(identityKey.PublicKey()),
		NodeID:         hex.EncodeToString(nodeID[:]),
		Leaf:           hex.EncodeToString(leaf),
		TLSBinding:     signedAsJSON(tlsBinding),
		TLSStatus:      signedAsJSON(tlsStatus),
		ConnectKey:     hex.EncodeToString(connectKey.PublicKey()),
		ConnectBinding: signedAsJSON(connectBinding),
		ConnectStatus:  signedAsJSON(connectStatus),
	}, nil
}

func signedAsJSON(s identity.SignedTBS) signedTBS {
	return signedTBS{TBS: hex.EncodeToString(s.TBS), Signature: hex.EncodeToString(s.Signature)}
}
