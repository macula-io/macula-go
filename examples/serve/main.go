// Command serve serves an org procedure on the macula 12 mesh until
// interrupted. The realm must have admitted the org and the org delegated its
// procedures to this node: the pool finds that authorization in the DHT and
// refuses to advertise without it.
//
//	go run ./examples/serve -seed '[2a01:4f8::1]:4433' -station <64 hex> \
//	    -realm <64 hex> -realm-key realm.key.hex -procedure acme/echo
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/examples/internal/meshflags"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

func main() {
	mesh := meshflags.Register()
	procedure := flag.String("procedure", "", "the org procedure to serve, org/name")
	flag.Parse()
	if err := run(mesh, *procedure); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		os.Exit(1)
	}
}

// echo answers with the caller's payload, and says who called.
func echo(_ context.Context, r stationlink.Request) (cbor.Value, error) {
	fmt.Printf("call from %x\n", r.Caller[:8])
	return r.Payload, nil
}

func run(mesh meshflags.Flags, procedure string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	p, err := mesh.Connect(ctx)
	if err != nil {
		return err
	}
	defer p.Close()
	realm, err := mesh.Realm()
	if err != nil {
		return err
	}
	served, err := p.Serve(ctx, pool.Offer{Realm: realm, Procedure: procedure, Handler: echo})
	if err != nil {
		return err
	}
	fmt.Printf("serving %s as node %x; interrupt to stop\n", procedure, p.NodeID())
	<-ctx.Done()
	return served.Stop()
}
