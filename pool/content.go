package pool

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
)

// Node-served content, as macula 12.6.0 has it (D27; macula's
// docs/guides/content/CONTENT_PROTOCOL.md). A station keeps no content: the
// node that shares content keeps it, serves it on a server_stream procedure of
// its own, ~<node_id>/content_v1, and announces it in the DHT under the
// content id's key, naming the realm, the station it is reachable through and
// that procedure. A fetcher finds the announcements, dials each sharer's
// station from the station's own endpoint record, and asks for the root and
// then each chunk, one stream each; everything it receives is checked against
// the content id it asked for, so it trusts no realm key and no sharer.

// ContentProcedureName is the content procedure's name in a sharer's own
// namespace.
const ContentProcedureName = "content_v1"

const (
	// contentAnnouncementTTL is how long an announcement is signed for; it is
	// renewed at half that.
	contentAnnouncementTTL = time.Hour
	// maxBlockBytes bounds one DATA body: one chunk.
	maxBlockBytes = manifest.DefaultChunkSize
)

// The defaults of ContentOptions, as macula_content_fetch's.
const (
	DefaultMaxContentBytes = 256 << 20
	DefaultMaxChunks       = 16_384
	DefaultParallel        = 4
	DefaultChunkTimeout    = 15 * time.Second
)

var (
	// ErrNotShared is content no sharer announces in the realm, or a sharer
	// that answers it does not hold it.
	ErrNotShared = errors.New("pool: the content is not shared")
	// ErrContentUnavailable is content every announcing sharer failed to give;
	// it is joined with each sharer's failure.
	ErrContentUnavailable = errors.New("pool: no sharer gave the content")
	// ErrContentMismatch is a block, manifest or whole that does not match the
	// content id it was asked for by.
	ErrContentMismatch = errors.New("pool: the content does not match its content id")
	// ErrContentTooLarge is content over the fetch's bounds.
	ErrContentTooLarge = errors.New("pool: the content is over the bounds asked for")
	// ErrContentReply is a DATA body a sharer never answers with.
	ErrContentReply = errors.New("pool: a sharer answered with something that is not content")
)

// ContentOptions bound a fetch; a zero field takes its default.
type ContentOptions struct {
	MaxBytes     uint64
	MaxChunks    int
	Parallel     int
	ChunkTimeout time.Duration
}

func (o ContentOptions) withDefaults() ContentOptions {
	if o.MaxBytes == 0 {
		o.MaxBytes = DefaultMaxContentBytes
	}
	if o.MaxChunks <= 0 {
		o.MaxChunks = DefaultMaxChunks
	}
	if o.Parallel <= 0 {
		o.Parallel = DefaultParallel
	}
	if o.ChunkTimeout <= 0 {
		o.ChunkTimeout = DefaultChunkTimeout
	}
	return o
}

// ---- the sharer ------------------------------------------------------------

// contentSharer is what a pool shares: per realm, the content it keeps (roots
// and chunks, by content id), the served content procedure, and each root's
// latest signed announcement.
type contentSharer struct {
	mu     sync.Mutex
	realms map[[32]byte]*sharedRealm
}

type sharedRealm struct {
	served        *Served
	roots         map[manifest.Mcid]sharedRoot
	chunks        map[manifest.Mcid][]byte
	announcements map[manifest.Mcid]*announced
}

type sharedRoot struct {
	block    []byte
	manifest *manifest.Manifest
}

type announced struct {
	latest record.Record
	stop   chan struct{}
}

// ShareContent keeps data, serves it on this node's content procedure in realm
// and announces it, renewing the announcement until UnshareContent or Close.
// Data of at most one chunk is one raw block; larger data is a manifest over
// 256 KiB chunks, named name. It returns the content id.
func (p *Pool) ShareContent(ctx context.Context, realm [32]byte, data []byte, name string) (manifest.Mcid, error) {
	var root sharedRoot
	var mcid manifest.Mcid
	chunks := map[manifest.Mcid][]byte{}
	if len(data) <= maxBlockBytes {
		mcid, root.block = manifest.BlockMcid(data), append([]byte(nil), data...)
	} else {
		m, parts := manifest.Create(data, manifest.CreateOptions{Name: name, ChunkSize: manifest.DefaultChunkSize})
		for i, part := range parts {
			chunkMcid, _ := manifest.ChunkMcid(m, i)
			chunks[chunkMcid] = part
		}
		mcid, root.manifest = m.Mcid, &m
	}
	shared, err := p.sharedRealm(ctx, realm)
	if err != nil {
		return manifest.Mcid{}, err
	}
	p.sharer.mu.Lock()
	shared.roots[mcid] = root
	for c, part := range chunks {
		shared.chunks[c] = part
	}
	_, already := shared.announcements[mcid]
	p.sharer.mu.Unlock()
	if already {
		return mcid, nil
	}
	latest, err := p.announceContent(ctx, realm, mcid, root)
	if err != nil {
		p.forgetShared(realm, mcid)
		return manifest.Mcid{}, err
	}
	a := &announced{latest: latest, stop: make(chan struct{})}
	p.sharer.mu.Lock()
	shared.announcements[mcid] = a
	p.sharer.mu.Unlock()
	go p.renewAnnouncement(realm, mcid, root, a)
	return mcid, nil
}

// UnshareContent stops sharing mcid in realm: it is no longer served, and its
// announcement is withdrawn with a tombstone this node signs. Content not
// shared is nothing to do.
func (p *Pool) UnshareContent(ctx context.Context, realm [32]byte, mcid manifest.Mcid) error {
	a := p.forgetShared(realm, mcid)
	if a == nil {
		return nil
	}
	close(a.stop)
	tombstone, err := record.NewTombstone(a.latest, record.ReasonShutdown, record.TombstoneOptions{})
	if err != nil {
		return err
	}
	signed, err := record.Sign(tombstone, p.key)
	if err != nil {
		return err
	}
	wire, err := record.Encode(signed)
	if err != nil {
		return err
	}
	return p.PutRecord(ctx, wire)
}

// forgetShared drops mcid's root, its chunks and its announcement from realm,
// and returns the announcement, if there was one.
func (p *Pool) forgetShared(realm [32]byte, mcid manifest.Mcid) *announced {
	p.sharer.mu.Lock()
	defer p.sharer.mu.Unlock()
	shared := p.sharer.realms[realm]
	if shared == nil {
		return nil
	}
	if root, held := shared.roots[mcid]; held && root.manifest != nil {
		for i := range root.manifest.Chunks {
			chunkMcid, _ := manifest.ChunkMcid(*root.manifest, i)
			delete(shared.chunks, chunkMcid)
		}
	}
	delete(shared.roots, mcid)
	a := shared.announcements[mcid]
	delete(shared.announcements, mcid)
	return a
}

// sharedRealm is realm's share, serving the content procedure on first use.
func (p *Pool) sharedRealm(ctx context.Context, realm [32]byte) (*sharedRealm, error) {
	p.sharer.mu.Lock()
	if p.sharer.realms == nil {
		p.sharer.realms = map[[32]byte]*sharedRealm{}
	}
	shared := p.sharer.realms[realm]
	p.sharer.mu.Unlock()
	if shared != nil {
		return shared, nil
	}
	shared = &sharedRealm{roots: map[manifest.Mcid]sharedRoot{}, chunks: map[manifest.Mcid][]byte{},
		announcements: map[manifest.Mcid]*announced{}}
	served, err := p.Serve(ctx, Offer{Realm: realm, Procedure: record.OwnProcedure(p.NodeID(), ContentProcedureName),
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			return p.answerFetch(realm, s)
		}}})
	if err != nil {
		return nil, err
	}
	p.sharer.mu.Lock()
	defer p.sharer.mu.Unlock()
	if existing := p.sharer.realms[realm]; existing != nil {
		_ = served.Stop()
		return existing, nil
	}
	shared.served = served
	p.sharer.realms[realm] = shared
	return shared, nil
}

// answerFetch answers one fetch, as macula_content_serve does: one DATA body,
// then the end, or not_shared or malformed.
func (p *Pool) answerFetch(realm [32]byte, s *stationlink.Stream) error {
	args := s.Request().Payload
	mcidBytes, _ := wireBytes(args, "mcid")
	want, _ := wireText(args, "want")
	if len(mcidBytes) != len(manifest.Mcid{}) || mcidBytes[0] != 2 || (want != "root" && want != "block") {
		return s.Abort("malformed", "a fetch names one content id and wants root or block")
	}
	var mcid manifest.Mcid
	copy(mcid[:], mcidBytes)
	p.sharer.mu.Lock()
	var body cbor.Value
	var found bool
	if shared := p.sharer.realms[realm]; shared != nil {
		body, found = shared.body(want, mcid)
	}
	p.sharer.mu.Unlock()
	if !found {
		return s.Abort("not_shared", "this node does not share that content")
	}
	if err := s.SendValue(body); err != nil {
		return err
	}
	return s.Close()
}

// body is what a fetch of want for mcid is answered with; a raw root is not
// served as a chunk.
func (r *sharedRealm) body(want string, mcid manifest.Mcid) (cbor.Value, bool) {
	block := func(b []byte) cbor.Value {
		return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("kind"), Val: cbor.Text("block")},
			{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid[:])}, {Key: cbor.Text("bytes"), Val: cbor.Bytes(b)}})
	}
	if want == "block" {
		b, held := r.chunks[mcid]
		return block(b), held
	}
	root, held := r.roots[mcid]
	switch {
	case !held:
		return cbor.Value{}, false
	case root.manifest == nil:
		return block(root.block), true
	}
	return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("kind"), Val: cbor.Text("manifest")},
		{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid[:])}, {Key: cbor.Text("manifest"), Val: manifest.ToWire(*root.manifest)}}), true
}

// announceContent signs an announcement of mcid in realm, naming a station
// this node is linked to and its content procedure, and puts it in the DHT.
func (p *Pool) announceContent(ctx context.Context, realm [32]byte, mcid manifest.Mcid, root sharedRoot) (record.Record, error) {
	links := p.links()
	if len(links) == 0 {
		return record.Record{}, ErrNoLink
	}
	opts := record.ContentAnnouncementOptions{RealmID: realm, ServingStation: links[0].StationNodeID(),
		Procedure: record.OwnProcedure(p.NodeID(), ContentProcedureName), TTLMs: uint64(contentAnnouncementTTL / time.Millisecond)}
	if root.manifest != nil {
		size, count := root.manifest.Size, uint64(root.manifest.ChunkCount)
		opts.Name, opts.Size, opts.ChunkCount = root.manifest.Name, &size, &count
	} else {
		size := uint64(len(root.block))
		opts.Size = &size
	}
	unsigned, err := record.NewContentAnnouncement(p.NodeID(), mcid[:], opts)
	if err != nil {
		return record.Record{}, err
	}
	signed, err := record.Sign(unsigned, p.key)
	if err != nil {
		return record.Record{}, err
	}
	wire, err := record.Encode(signed)
	if err != nil {
		return record.Record{}, err
	}
	return signed, p.PutRecord(ctx, wire)
}

// renewAnnouncement signs mcid's announcement again at half its lifetime,
// naming the station the pool is linked to then, until it is unshared or the
// pool closes; a failed renewal is tried again at the next half.
func (p *Pool) renewAnnouncement(realm [32]byte, mcid manifest.Mcid, root sharedRoot, a *announced) {
	for {
		select {
		case <-a.stop:
			return
		case <-p.ctx.Done():
			return
		case <-time.After(contentAnnouncementTTL / 2):
		}
		ctx, cancel := context.WithTimeout(context.Background(), stationlink.DefaultCallTimeout)
		latest, err := p.announceContent(ctx, realm, mcid, root)
		cancel()
		if err == nil {
			p.sharer.mu.Lock()
			a.latest = latest
			p.sharer.mu.Unlock()
		}
	}
}

// ---- the fetcher -----------------------------------------------------------

// sharer is an announcing node, where it is served, and on what.
type sharer struct {
	node, station [32]byte
	procedure     string
}

// GetContent fetches the content mcid names in realm from a node that shares
// it, as macula_content_fetch does: the announcements under the content id's
// key that name it, realm, a serving station and a content procedure bound to
// their announcer; the sharers tried one at a time in a random order; a block
// that must hash to mcid, or a manifest that must match mcid before its sizes
// are read and fit o before any chunk is asked for, each chunk on its own
// stream, o.Parallel at a time, checked against its own content id, and the
// whole against the manifest. No realm key is needed. Content nobody
// announces is ErrNotShared; when every sharer fails, ErrContentUnavailable
// joined with each failure.
func (p *Pool) GetContent(ctx context.Context, realm [32]byte, mcid manifest.Mcid, o ContentOptions) ([]byte, error) {
	o = o.withDefaults()
	sharers, err := p.contentSharers(ctx, realm, mcid)
	if err != nil {
		return nil, err
	}
	if len(sharers) == 0 {
		return nil, ErrNotShared
	}
	errs := []error{ErrContentUnavailable}
	for _, s := range sharers {
		data, err := p.fetchFrom(ctx, realm, s, mcid, o)
		if err == nil {
			return data, nil
		}
		if ctx.Err() != nil {
			return nil, errors.Join(append(errs, err)...)
		}
		errs = append(errs, fmt.Errorf("sharer %x: %w", s.node[:4], err))
	}
	return nil, errors.Join(errs...)
}

// contentSharers is every node whose verified announcement of mcid in realm
// names a serving station and a content procedure bound to it, shuffled.
func (p *Pool) contentSharers(ctx context.Context, realm [32]byte, mcid manifest.Mcid) ([]sharer, error) {
	key, err := record.ContentKey(mcid[:])
	if err != nil {
		return nil, err
	}
	found, _, err := p.FindRecords(ctx, key)
	if err != nil && !errors.Is(err, stationlink.ErrRecordNotFound) {
		return nil, err
	}
	var out []sharer
	for _, verified := range found {
		r := verified.Record()
		if r.Type != record.TypeContentAnnouncement {
			continue
		}
		a, err := record.ReadContentAnnouncement(r)
		if err != nil || string(a.MCID) != string(mcid[:]) || a.RealmID != realm || a.ServingStation == ([32]byte{}) ||
			!ContentProcedureBound(a.Procedure, a.AnnouncerNode) {
			continue
		}
		out = append(out, sharer{node: a.AnnouncerNode, station: a.ServingStation, procedure: a.Procedure})
	}
	shuffle(out)
	return out, nil
}

// ContentProcedureBound reports whether procedure is node's content
// procedure: ~<node>/content_v1, or <org>/content_v1_<node> under an org that
// is not empty, "_", nor a ~ namespace, each node as 64 lowercase hex, so an
// announcement cannot point a fetch at another node's procedure.
func ContentProcedureBound(procedure string, node [32]byte) bool {
	nodeHex := hex.EncodeToString(node[:])
	if procedure == record.OwnNamespacePrefix+nodeHex+"/"+ContentProcedureName {
		return true
	}
	org, name, cut := strings.Cut(procedure, "/")
	return cut && org != "" && org != "_" && !strings.HasPrefix(org, record.OwnNamespacePrefix) &&
		name == ContentProcedureName+"_"+nodeHex
}

// fetchFrom fetches mcid from one sharer.
func (p *Pool) fetchFrom(ctx context.Context, realm [32]byte, s sharer, mcid manifest.Mcid, o ContentOptions) ([]byte, error) {
	link, err := p.linkTo(ctx, s.station)
	if err != nil {
		return nil, err
	}
	kind, body, err := fetchOne(ctx, link, realm, s, mcid, "root", o.ChunkTimeout)
	if err != nil {
		return nil, err
	}
	if kind == "block" {
		b, _ := wireBytes(body, "bytes")
		if manifest.BlockMcid(b) != mcid {
			return nil, fmt.Errorf("%w: the block", ErrContentMismatch)
		}
		return b, nil
	}
	value, _ := body.Get("manifest")
	m, err := manifest.FromWire(value)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrContentReply, err)
	}
	if err := manifest.VerifyMcid(m, mcid); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrContentMismatch, err)
	}
	if m.Size > o.MaxBytes || m.ChunkCount > o.MaxChunks {
		return nil, fmt.Errorf("%w: %d bytes in %d chunks", ErrContentTooLarge, m.Size, m.ChunkCount)
	}
	if err := manifest.CheckWhole(m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrContentMismatch, err)
	}
	return fetchChunks(ctx, link, realm, s, m, o)
}

// fetchChunks fetches every chunk of m, o.Parallel at a time, each checked
// against its own content id, then the whole against m.
func fetchChunks(ctx context.Context, link *stationlink.Link, realm [32]byte, s sharer, m manifest.Manifest, o ContentOptions) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	parts := make([][]byte, m.ChunkCount)
	next := make(chan int)
	errs := make(chan error, m.ChunkCount)
	var wg sync.WaitGroup
	for range min(o.Parallel, m.ChunkCount) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				chunkMcid, _ := manifest.ChunkMcid(m, i)
				_, body, err := fetchOne(ctx, link, realm, s, chunkMcid, "block", o.ChunkTimeout)
				b, _ := wireBytes(body, "bytes")
				switch {
				case err != nil:
				case manifest.BlockMcid(b) != chunkMcid:
					err = fmt.Errorf("%w: chunk %d", ErrContentMismatch, i)
				}
				if err != nil {
					errs <- err
					cancel()
					continue
				}
				parts[i] = b
			}
		}()
	}
	for i := range m.ChunkCount {
		select {
		case next <- i:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
	}
	close(next)
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	whole := make([]byte, 0, m.Size)
	for _, part := range parts {
		whole = append(whole, part...)
	}
	if err := manifest.Verify(m, whole); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrContentMismatch, err)
	}
	return whole, nil
}

// fetchOne asks a sharer for want of mcid on a stream of its own and reads its
// one DATA body; the stream is released on every path.
func fetchOne(ctx context.Context, link *stationlink.Link, realm [32]byte, s sharer, mcid manifest.Mcid, want string,
	timeout time.Duration) (string, cbor.Value, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stream, err := link.OpenStream(ctx, stationlink.StreamCall{Realm: realm, Procedure: s.procedure, Target: s.node,
		Mode: frame.ServerStream, Deadline: timeout, Payload: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid[:])}, {Key: cbor.Text("want"), Val: cbor.Text(want)}})})
	if err != nil {
		return "", cbor.Value{}, err
	}
	defer func() { _ = stream.Close() }()
	event, err := stream.Recv(ctx)
	var streamErr *stationlink.StreamError
	switch {
	case errors.As(err, &streamErr) && streamErr.Code == "not_shared":
		return "", cbor.Value{}, fmt.Errorf("%w: %s", ErrNotShared, streamErr.Message)
	case errors.Is(err, io.EOF):
		return "", cbor.Value{}, fmt.Errorf("%w: the stream ended with no body", ErrContentReply)
	case err != nil:
		return "", cbor.Value{}, err
	case event.Kind != stationlink.StreamData:
		return "", cbor.Value{}, fmt.Errorf("%w: a frame that is not DATA", ErrContentReply)
	}
	kind, _ := wireText(event.Body, "kind")
	got, _ := wireBytes(event.Body, "mcid")
	bytesOf, hasBytes := wireBytes(event.Body, "bytes")
	switch {
	case string(got) != string(mcid[:]):
		return "", cbor.Value{}, fmt.Errorf("%w: a body for another content id", ErrContentReply)
	case kind == "block" && hasBytes && len(bytesOf) > maxBlockBytes:
		return "", cbor.Value{}, fmt.Errorf("%w: a block of %d bytes", ErrContentTooLarge, len(bytesOf))
	case kind == "block" && hasBytes, kind == "manifest" && want == "root":
		return kind, event.Body, nil
	}
	return "", cbor.Value{}, fmt.Errorf("%w: kind %q", ErrContentReply, kind)
}

// wireText is field name of v as text, however it arrives.
func wireText(v cbor.Value, name string) (string, bool) {
	field, present := v.Get(name)
	if !present {
		return "", false
	}
	if text, isText := field.AsText(); isText {
		return text, true
	}
	b, isBytes := field.AsBytes()
	return string(b), isBytes
}

// wireBytes is field name of v as bytes.
func wireBytes(v cbor.Value, name string) ([]byte, bool) {
	field, present := v.Get(name)
	if !present {
		return nil, false
	}
	return field.AsBytes()
}

// shuffle orders sharers at random, so a fetch does not always load the same
// one first.
func shuffle(s []sharer) {
	for i := len(s) - 1; i > 0; i-- {
		var b [8]byte
		_, _ = rand.Read(b[:])
		j := int(binary.BigEndian.Uint64(b[:]) % uint64(i+1))
		s[i], s[j] = s[j], s[i]
	}
}
