// Command call calls a procedure on the macula 12 mesh, by direct dial: the
// pool resolves the procedure's advertisements from the DHT, trusts only those
// the realm's key authorizes, dials the station a provider serves from, and
// calls it there.
//
//	go run ./examples/call -seed '[2a01:4f8::1]:4433' -station <64 hex> \
//	    -realm <64 hex> -realm-key realm.key.hex -procedure mcl-echo/echo -text hello
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/examples/internal/meshflags"
	"github.com/macula-io/macula-go/pool"
)

func main() {
	mesh := meshflags.Register()
	procedure := flag.String("procedure", "mcl-echo/echo", "the org procedure to call")
	text := flag.String("text", "hello", "the text payload")
	flag.Parse()
	if err := run(mesh, *procedure, *text); err != nil {
		fmt.Fprintln(os.Stderr, "call:", err)
		os.Exit(1)
	}
}

func run(mesh meshflags.Flags, procedure, text string) error {
	ctx := context.Background()
	p, err := mesh.Connect(ctx)
	if err != nil {
		return err
	}
	defer p.Close()
	realm, err := mesh.Realm()
	if err != nil {
		return err
	}
	providers, err := p.Providers(ctx, realm, procedure)
	if err != nil {
		return err
	}
	for _, provider := range providers {
		fmt.Printf("provider %x at station %x\n", provider.Node[:8], provider.Station[:8])
	}
	started := time.Now()
	result, err := p.Call(ctx, pool.Call{Realm: realm, Procedure: procedure, Payload: cbor.Text(text)})
	if err != nil {
		return err
	}
	answer, isText := result.AsText()
	if !isText {
		answer = fmt.Sprintf("%v", result)
	}
	fmt.Printf("%s answered %q in %s\n", procedure, answer, time.Since(started).Round(time.Millisecond))
	return nil
}
