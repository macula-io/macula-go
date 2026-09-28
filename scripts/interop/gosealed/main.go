// Command gosealed is macula-go's side of sealed calls and streams across
// macula 13 and macula-go (E2E seal scheme 1), for
// scripts/interop/erlang_sealed.escript, through one station.
//
//	gosealed -station host:port@<node_id hex> -profile pq_hybrid -realm <hex> -hold 60s serve
//	gosealed -station host:port@<node_id hex> -profile pq_hybrid -realm <hex> -provider <node_id hex> call
//
// serve connects a pool with KEMAdvertise, serves ~<self>/vault (a call) and
// ~<self>/watch (a server stream), both ConfidentialRequired, prints
// "node <hex>" and holds. call calls ~<provider>/vault and opens
// ~<provider>/watch sealed to the key the provider's advertisement names, then
// checks the pool refuses ConfidentialOff, and calls vault in the clear from a
// station link to it as an explicit target, which a required provider refuses
// sealed_required. It prints each outcome and exits 1 on any other.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
)

func main() {
	station := flag.String("station", "", "host:port@<node_id hex>")
	profileName := flag.String("profile", "pq_hybrid", "crypto profile")
	realmHex := flag.String("realm", "", "realm id, hex")
	hold := flag.Duration("hold", time.Minute, "how long serve holds")
	provider := flag.String("provider", "", "call: the provider's node_id, hex")
	flag.Parse()
	if err := run(flag.Arg(0), *station, *profileName, *realmHex, *hold, *provider); err != nil {
		fmt.Fprintln(os.Stderr, "gosealed:", err)
		os.Exit(1)
	}
}

func run(mode, station, profileName, realmHex string, hold time.Duration, provider string) error {
	p, err := profile.Parse(profileName)
	if err != nil {
		return err
	}
	seed, err := parseSeed(station)
	if err != nil {
		return err
	}
	realm, err := id32(realmHex)
	if err != nil {
		return err
	}
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), hold+2*time.Minute)
	defer cancel()
	node, err := pool.Connect(ctx, []pool.Seed{seed}, pool.Opts{IdentityKey: key, KEMAdvertise: mode == "serve"})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer node.Close()
	self := node.NodeID()
	fmt.Printf("node %s\n", hex.EncodeToString(self[:]))
	switch mode {
	case "serve":
		return serve(ctx, node, realm, hold)
	case "call":
		target, err := id32(provider)
		if err != nil {
			return err
		}
		return call(ctx, node, seed, p, realm, target)
	}
	return fmt.Errorf("mode %q is serve or call", mode)
}

func own(node [32]byte, name string) string { return "~" + hex.EncodeToString(node[:]) + "/" + name }

func serve(ctx context.Context, node *pool.Pool, realm [32]byte, hold time.Duration) error {
	self := node.NodeID()
	if _, err := node.Serve(ctx, pool.Offer{Realm: realm, Procedure: own(self, "vault"), Confidential: stationlink.ConfidentialRequired,
		Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
			if !r.Sealed {
				return cbor.Value{}, errors.New("a clear request reached the handler")
			}
			return cbor.Text("kept by go"), nil
		}}); err != nil {
		return fmt.Errorf("serve vault: %w", err)
	}
	if _, err := node.Serve(ctx, pool.Offer{Realm: realm, Procedure: own(self, "watch"), Confidential: stationlink.ConfidentialRequired,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			if err := s.Send([]byte("chunk from go")); err != nil {
				return err
			}
			return s.Reply(cbor.Text("streamed by go"))
		}}}); err != nil {
		return fmt.Errorf("serve watch: %w", err)
	}
	fmt.Println("serving")
	select {
	case <-time.After(hold):
	case <-ctx.Done():
	}
	return nil
}

func call(ctx context.Context, node *pool.Pool, seed pool.Seed, p profile.Profile, realm, provider [32]byte) error {
	vault, watch := own(provider, "vault"), own(provider, "watch")
	var result cbor.Value
	var err error
	for range 150 {
		if result, err = node.Call(ctx, pool.Call{Realm: realm, Procedure: vault, Payload: cbor.Map(nil)}); !errors.Is(err, pool.ErrNoProvider) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	text, _ := result.AsText()
	fmt.Printf("sealed call: %q, %v\n", text, err)
	if err != nil || text != "kept by erlang" {
		return errors.New("the sealed call")
	}
	stream, err := node.OpenStream(ctx, pool.StreamCall{Realm: realm, Procedure: watch, Mode: frame.ServerStream, Payload: cbor.Map(nil)})
	if err != nil {
		return fmt.Errorf("the sealed stream: %w", err)
	}
	chunk, err := stream.Recv(ctx)
	body, _ := chunk.Body.AsBytes()
	reply, rerr := stream.Recv(ctx)
	replied, _ := reply.Payload.AsText()
	fmt.Printf("sealed stream: chunk %q (%v), reply %q (%v)\n", body, err, replied, rerr)
	if err != nil || rerr != nil || string(body) != "chunk from erlang" || replied != "streamed by erlang" {
		return errors.New("the sealed stream")
	}
	if os.Getenv("MACULA_SEAL_REPORT") == "1" {
		if err := reports(ctx, node, stream, realm, provider, vault); err != nil {
			return err
		}
	}
	// Off at the pool is refused, never ignored: a clear call is an explicit
	// target's, on a station link without SealTo.
	if _, err := node.Call(ctx, pool.Call{Realm: realm, Procedure: vault, Payload: cbor.Map(nil),
		Confidential: stationlink.ConfidentialOff}); !errors.Is(err, pool.ErrConfidentialOff) {
		return fmt.Errorf("off at the pool: %v, want ErrConfidentialOff", err)
	}
	link, err := explicitLink(ctx, seed, p)
	if err != nil {
		return err
	}
	defer link.Close("done")
	_, err = link.Call(ctx, stationlink.Call{Realm: realm, Procedure: vault, Target: provider, Payload: cbor.Map(nil),
		Timeout: 10 * time.Second, Clear: true})
	fmt.Printf("clear call: %v\n", err)
	var refused *stationlink.ProviderError
	if !errors.As(err, &refused) || refused.Code != "sealed_required" {
		return errors.New("the clear call was not refused sealed_required")
	}
	return nil
}

// reports checks the seal reports (macula's DESIGN_E2E_SEAL_REPORT) of a
// sealed call to the provider and of the stream already read: both sealed 1,
// addressed to the provider, and naming the same key, the provider's.
func reports(ctx context.Context, node *pool.Pool, stream *stationlink.Stream, realm, provider [32]byte, vault string) error {
	_, called, err := node.CallReport(ctx, pool.Call{Realm: realm, Procedure: vault, Payload: cbor.Map(nil)})
	fmt.Printf("call report: sealed %d, provider %x, key %x, %v\n", called.Sealed, called.Provider[:4], called.SealKeyID, err)
	streamed, serr := stream.Report()
	fmt.Printf("stream report: sealed %d, provider %x, key %x, %v\n", streamed.Sealed, streamed.Provider[:4], streamed.SealKeyID, serr)
	switch {
	case err != nil, serr != nil:
		return errors.New("a seal report failed")
	case called.Sealed != 1 || called.Provider != provider || called.SealKeyID == ([8]byte{}):
		return errors.New("the call's seal report")
	case streamed != called:
		return errors.New("the stream's seal report differs from the call's")
	}
	return nil
}

// explicitLink is a station link of a fresh identity, for a call to an
// explicit target.
func explicitLink(ctx context.Context, seed pool.Seed, p profile.Profile) (*stationlink.Link, error) {
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return nil, err
	}
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		return nil, err
	}
	go issuer.Run(ctx, nil)
	return stationlink.Dial(ctx, stationlink.Config{Target: transport.Target{Host: seed.Host, Port: seed.Port, Profile: p,
		ExpectedNodeID: seed.NodeID}, IdentityKey: key, Issuer: issuer})
}

func id32(text string) ([32]byte, error) {
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("%q is not 64 hex characters", text)
	}
	return [32]byte(b), nil
}

func parseSeed(text string) (pool.Seed, error) {
	address, node, ok := strings.Cut(text, "@")
	host, portText, found := strings.Cut(address, ":")
	raw, err := hex.DecodeString(node)
	port, perr := strconv.ParseUint(portText, 10, 16)
	if !ok || !found || err != nil || len(raw) != 32 || perr != nil {
		return pool.Seed{}, fmt.Errorf("-station is host:port@<node_id hex>, not %q", text)
	}
	return pool.Seed{Host: host, Port: uint16(port), NodeID: [32]byte(raw)}, nil
}
