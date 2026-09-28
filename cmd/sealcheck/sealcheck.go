package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"slices"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
)

// config is one measurement: the seeds and realm a caller outside the fleet is
// given, the sealed procedure (unary) and its stream, the plain procedure for
// the clear leg, the provider to pin (nil for any), how many calls, and which
// legs run.
type config struct {
	Seeds           []pool.Seed
	Profile         profile.Profile
	Realm           [32]byte
	RealmKey        []byte
	Sealed          string
	StreamProcedure string
	Clear           string
	Provider        *[32]byte
	N               int
	Call, Stream    bool
	Timeout         time.Duration
}

// advertised is what the sealed provider's own advertisement says: the key it
// names and the station it serves from.
type advertised struct {
	kemKeyID [8]byte
	station  [32]byte
}

// measure makes the sealed calls and the sealed stream, and the same calls in
// the clear, and writes a log that is the measurement: each call's report, key,
// serving station and latency, then the sealed-vs-clear overhead. It returns an
// error, and the log ends "overall: FAIL", unless every sealed report is sealed
// to the key the provider's own advertisement names.
func measure(ctx context.Context, cfg config, out io.Writer) error {
	failures := run(ctx, cfg, out)
	for _, f := range failures {
		fmt.Fprintf(out, "failure: %v\n", f)
	}
	if len(failures) > 0 {
		fmt.Fprintln(out, "overall: FAIL")
		return errors.Join(failures...)
	}
	fmt.Fprintln(out, "overall: PASS")
	return nil
}

func run(ctx context.Context, cfg config, out io.Writer) []error {
	header(cfg, out)
	key, err := identity.GenerateIdentityKeyContext(ctx, cfg.Profile, identity.PuzzleDifficulty)
	if err != nil {
		return []error{fmt.Errorf("an identity: %w", err)}
	}
	connect, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	p, err := pool.Connect(connect, cfg.Seeds, pool.Opts{IdentityKey: key, RealmTrust: map[[32]byte][]byte{cfg.Realm: cfg.RealmKey}})
	if err != nil {
		return []error{fmt.Errorf("connect: %w", err)}
	}
	defer p.Close()
	var failures []error
	var sealedMs, clearMs []float64
	if cfg.Call {
		ads, err := advertisements(ctx, p, cfg, cfg.Sealed)
		if err != nil {
			return []error{err}
		}
		for i := 1; i <= cfg.N; i++ {
			ms, err := sealedCall(ctx, p, cfg, ads, i, out)
			if err != nil {
				failures = append(failures, err)
				continue
			}
			sealedMs = append(sealedMs, ms)
			if cfg.Clear != "" {
				ms, err := clearCall(ctx, p, cfg, i, out)
				if err != nil {
					failures = append(failures, err)
					continue
				}
				clearMs = append(clearMs, ms)
			}
		}
	}
	if cfg.Stream {
		ads, err := advertisements(ctx, p, cfg, cfg.StreamProcedure)
		if err == nil {
			err = sealedStream(ctx, p, cfg, ads, out)
		}
		if err != nil {
			failures = append(failures, err)
		}
	}
	summary(out, sealedMs, clearMs)
	return failures
}

// header records what was measured, with what, and when.
func header(cfg config, out io.Writer) {
	fmt.Fprintln(out, "# sealcheck: sealed calls and streams from outside the fleet, with the caller's seal report")
	fmt.Fprintf(out, "date_utc: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(out, "macula_go: %s\n", buildVersion())
	fmt.Fprintf(out, "profile: %s\nrealm: %x\n", cfg.Profile, cfg.Realm)
	for _, s := range cfg.Seeds {
		fmt.Fprintf(out, "seed: %s:%d@%x\n", s.Host, s.Port, s.NodeID)
	}
	fmt.Fprintf(out, "sealed: %s  stream: %s  clear: %s  n: %d\n", cfg.Sealed, cfg.StreamProcedure, cfg.Clear, cfg.N)
	if cfg.Provider != nil {
		fmt.Fprintf(out, "provider: %x\n", *cfg.Provider)
	}
}

// buildVersion is this binary's macula-go module version and VCS revision.
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	version, revision, modified := info.Main.Version, "", ""
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value
		}
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/macula-io/macula-go" {
			version = dep.Version
		}
	}
	return fmt.Sprintf("%s revision=%s modified=%s", version, revision, modified)
}

// advertisements are the trusted providers of procedure, as their own signed
// advertisements name them, waited for until the timeout.
func advertisements(ctx context.Context, p *pool.Pool, cfg config, procedure string) (map[[32]byte]advertised, error) {
	deadline := time.Now().Add(cfg.Timeout)
	for {
		ads, err := advertisementsNow(ctx, p, cfg, procedure)
		if err == nil && len(ads) > 0 {
			return ads, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s: no provider advertises it (%v)", procedure, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func advertisementsNow(ctx context.Context, p *pool.Pool, cfg config, procedure string) (map[[32]byte]advertised, error) {
	providers, err := p.Providers(ctx, cfg.Realm, procedure)
	if err != nil {
		return nil, err
	}
	trusted := map[[32]byte]bool{}
	for _, pr := range providers {
		trusted[pr.Node] = true
	}
	found, _, err := p.FindRecords(ctx, record.ProcedureKey(cfg.Realm, procedure))
	if err != nil {
		return nil, err
	}
	out := map[[32]byte]advertised{}
	for _, v := range found {
		ad, err := record.ReadProcedureAdvertisement(v.Record())
		if err != nil || !trusted[ad.AdvertiserNode] || (cfg.Provider != nil && ad.AdvertiserNode != *cfg.Provider) {
			continue
		}
		out[ad.AdvertiserNode] = advertised{kemKeyID: ad.KEMKeyID, station: ad.ServingStation}
	}
	return out, nil
}

// checked is a report as the measurement requires it: sealed, to a provider
// that advertises the procedure, under the key that advertisement names.
func checked(what string, report stationlink.Report, ads map[[32]byte]advertised) error {
	ad, ok := ads[report.Provider]
	switch {
	case report.Sealed != 1:
		return fmt.Errorf("%s: the report says sealed=%d", what, report.Sealed)
	case !ok:
		return fmt.Errorf("%s: the report names provider %x, which advertises no such procedure here", what, report.Provider[:4])
	case ad.kemKeyID == [8]byte{}:
		return fmt.Errorf("%s: provider %x advertises no key", what, report.Provider[:4])
	case report.SealKeyID != ad.kemKeyID:
		return fmt.Errorf("%s: sealed to %x, the advertisement names %x", what, report.SealKeyID, ad.kemKeyID)
	}
	return nil
}

func sealedCall(ctx context.Context, p *pool.Pool, cfg config, ads map[[32]byte]advertised, i int, out io.Writer) (float64, error) {
	c := pool.Call{Realm: cfg.Realm, Procedure: cfg.Sealed, Payload: cbor.Text(fmt.Sprintf("sealcheck %d", i)),
		Timeout: cfg.Timeout, Confidential: stationlink.ConfidentialRequired}
	if cfg.Provider != nil {
		c.Provider = *cfg.Provider
	}
	started := time.Now()
	_, report, err := p.CallReport(ctx, c)
	ms := millis(time.Since(started))
	if err != nil {
		fmt.Fprintf(out, "call %d sealed=- error=%q ms=%.1f\n", i, err, ms)
		return 0, fmt.Errorf("call %d: %w", i, err)
	}
	fmt.Fprintf(out, "call %d sealed=%d provider=%x key=%x station=%x ms=%.1f\n", i, report.Sealed, report.Provider,
		report.SealKeyID, ads[report.Provider].station, ms)
	return ms, checked(fmt.Sprintf("call %d", i), report, ads)
}

func clearCall(ctx context.Context, p *pool.Pool, cfg config, i int, out io.Writer) (float64, error) {
	started := time.Now()
	_, report, err := p.CallReport(ctx, pool.Call{Realm: cfg.Realm, Procedure: cfg.Clear,
		Payload: cbor.Text(fmt.Sprintf("sealcheck %d", i)), Timeout: cfg.Timeout})
	ms := millis(time.Since(started))
	if err != nil {
		fmt.Fprintf(out, "clear %d error=%q ms=%.1f\n", i, err, ms)
		return 0, fmt.Errorf("clear call %d: %w", i, err)
	}
	fmt.Fprintf(out, "clear %d sealed=%d provider=%x ms=%.1f\n", i, report.Sealed, report.Provider, ms)
	return ms, nil
}

// sealedStream opens the sealed stream, reads to its first chunk or reply,
// which settles its report, and checks the report as a call's.
func sealedStream(ctx context.Context, p *pool.Pool, cfg config, ads map[[32]byte]advertised, out io.Writer) error {
	c := pool.StreamCall{Realm: cfg.Realm, Procedure: cfg.StreamProcedure, Mode: frame.ServerStream,
		Payload: cbor.Text("sealcheck stream"), Confidential: stationlink.ConfidentialRequired}
	if cfg.Provider != nil {
		c.Provider = *cfg.Provider
	}
	started := time.Now()
	stream, err := p.OpenStream(ctx, c)
	if err != nil {
		fmt.Fprintf(out, "stream sealed=- error=%q\n", err)
		return fmt.Errorf("stream: %w", err)
	}
	defer stream.Close()
	recv, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	for {
		event, err := stream.Recv(recv)
		if err != nil {
			fmt.Fprintf(out, "stream sealed=- error=%q\n", err)
			return fmt.Errorf("stream: %w", err)
		}
		if event.Kind == stationlink.StreamData || event.Kind == stationlink.StreamReply {
			break
		}
	}
	ms := millis(time.Since(started))
	report, err := stream.Report()
	if err != nil {
		fmt.Fprintf(out, "stream sealed=- error=%q ms=%.1f\n", err, ms)
		return fmt.Errorf("stream: %w", err)
	}
	fmt.Fprintf(out, "stream sealed=%d provider=%x key=%x station=%x ms_to_first=%.1f\n", report.Sealed, report.Provider,
		report.SealKeyID, ads[report.Provider].station, ms)
	return checked("stream", report, ads)
}

// summary is the sealed and clear latencies and their difference.
func summary(out io.Writer, sealed, clear []float64) {
	s, c := stats(sealed), stats(clear)
	fmt.Fprintf(out, "sealed_ms: n=%d p50=%.1f p95=%.1f mean=%.1f\n", len(sealed), s.p50, s.p95, s.mean)
	fmt.Fprintf(out, "clear_ms:  n=%d p50=%.1f p95=%.1f mean=%.1f\n", len(clear), c.p50, c.p95, c.mean)
	if len(sealed) > 0 && len(clear) > 0 {
		fmt.Fprintf(out, "overhead: p50=%+.1f ms mean=%+.1f ms\n", s.p50-c.p50, s.mean-c.mean)
	}
}

type latency struct{ p50, p95, mean float64 }

func stats(ms []float64) latency {
	if len(ms) == 0 {
		return latency{}
	}
	sorted := slices.Clone(ms)
	slices.Sort(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	return latency{p50: sorted[len(sorted)/2], p95: sorted[min(len(sorted)-1, len(sorted)*95/100)], mean: sum / float64(len(sorted))}
}

func millis(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// hexID reads a 32-byte id given as hex.
func hexID(what, text string) ([32]byte, error) {
	var id [32]byte
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != len(id) {
		return id, fmt.Errorf("%s is 64 hex digits, not %q", what, text)
	}
	copy(id[:], b)
	return id, nil
}
