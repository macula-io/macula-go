package frame

// StreamMode is who's expected to push data on a STREAM_OPEN — matches
// macula_stream:mode().
type StreamMode int

const (
	// ServerStream: the provider pushes chunks at the caller.
	ServerStream StreamMode = iota
	// ClientStream: the caller pushes chunks at the provider (§12.3's
	// push-upload path is exactly this mode).
	ClientStream
	// Bidi: both directions.
	Bidi
)

func (m StreamMode) Name() string {
	switch m {
	case ClientStream:
		return "client_stream"
	case Bidi:
		return "bidi"
	default:
		return "server_stream"
	}
}

func streamModeFromName(name string) (StreamMode, bool) {
	switch name {
	case "server_stream":
		return ServerStream, true
	case "client_stream":
		return ClientStream, true
	case "bidi":
		return Bidi, true
	default:
		return 0, false
	}
}

// StreamEncoding is a hint on a STREAM_DATA for how to interpret body —
// not a second wire codec. body is always an ordinary nested cbor.Value
// in the frame's own canonical-CBOR envelope either way; encoding is
// purely semantic ("treat body as raw bytes" vs "treat it as a
// structured value").
type StreamEncoding int

const (
	// Raw: body is opaque bytes.
	Raw StreamEncoding = iota
	// Msgpack: body is a structured cbor.Value (despite the name -- no
	// msgpack byte-level encoding actually happens; see this type's doc).
	Msgpack
)

func (e StreamEncoding) Name() string {
	if e == Msgpack {
		return "msgpack"
	}
	return "raw"
}

func streamEncodingFromName(name string) (StreamEncoding, bool) {
	switch name {
	case "raw":
		return Raw, true
	case "msgpack":
		return Msgpack, true
	default:
		return 0, false
	}
}

// StreamRole is which direction(s) are closing on a STREAM_END.
type StreamRole int

const (
	// Send: half-close -- this side is done sending, still willing to
	// receive.
	Send StreamRole = iota
	// Both: full close -- this side is done in both directions.
	Both
)

func (r StreamRole) Name() string {
	if r == Both {
		return "both"
	}
	return "send"
}

func streamRoleFromName(name string) (StreamRole, bool) {
	switch name {
	case "send":
		return Send, true
	case "both":
		return Both, true
	default:
		return 0, false
	}
}
