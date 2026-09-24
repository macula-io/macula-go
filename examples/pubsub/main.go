// Command pubsub subscribes to a topic on the macula 12 mesh and publishes one
// message on it, then prints what it hears until interrupted. Topics name the
// kind of fact, never an entity: put ids in the payload.
//
//	go run ./examples/pubsub -seed '[2a01:4f8::1]:4433' -station <64 hex> \
//	    -realm <64 hex> -realm-key realm.key.hex -topic acme/demo/greeting_sent_v1
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/examples/internal/meshflags"
	"github.com/macula-io/macula-go/stationlink"
)

func main() {
	mesh := meshflags.Register()
	topic := flag.String("topic", "", "the topic")
	flag.Parse()
	if err := run(mesh, *topic); err != nil {
		fmt.Fprintln(os.Stderr, "pubsub:", err)
		os.Exit(1)
	}
}

func run(mesh meshflags.Flags, topic string) error {
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
	sub, err := p.Subscribe(realm, topic)
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()
	time.Sleep(200 * time.Millisecond)
	greeting := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("text"), Val: cbor.Text("hello")}})
	if err := p.Publish(stationlink.Publication{Realm: realm, Topic: topic, Payload: greeting}); err != nil {
		return err
	}
	for {
		select {
		case event, open := <-sub.Events():
			if !open {
				return nil
			}
			text, _ := event.Payload.Get("text")
			greeting, _ := text.AsText()
			fmt.Printf("heard %q from %x (seq %d, via %s)\n", greeting, event.Publisher[:8], event.Seq, event.DeliveredVia)
		case <-ctx.Done():
			return nil
		}
	}
}
