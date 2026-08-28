// Package bolt4 implements the BOLT#4-style error taxonomy for CALL
// failures, ported from src/peering/macula_bolt4.erl
// (macula-io/macula) — see plans/PLAN_WIRE_PROTOCOL.md §9. Adapted
// from Lightning Network's BOLT#4 onion-failure codes: a small,
// specific taxonomy that prevents retry loops and enables post-mortem,
// rather than an open-ended error string.
package bolt4

// Code is one of the 17 codes macula's own table/0 defines.
type Code uint8

const (
	Ok                        Code = 0x00
	UnknownNextPeer           Code = 0x01
	TemporaryRelayFailure     Code = 0x02
	RelayDisabled             Code = 0x03
	NodeNotFoundAtTargetRelay Code = 0x04
	TargetRealmRefused        Code = 0x05
	LoopDetected              Code = 0x06
	ExpiryTooSoon             Code = 0x07
	UpstreamCongestion        Code = 0x08
	InvalidPathHeader         Code = 0x09
	CryptoPuzzleInvalid       Code = 0x0A
	RealmNotAuthoritativeHere Code = 0x0B
	Tombstoned                Code = 0x0C
	PayloadTooLarge           Code = 0x0D
	SignatureInvalid          Code = 0x0E
	UnknownError              Code = 0x0F
	// Unauthorized is direct-dial dual-trust: the caller lacked a valid
	// UCAN capability for a gated procedure.
	Unauthorized Code = 0x10
)

var names = map[Code]string{
	Ok:                        "ok",
	UnknownNextPeer:           "unknown_next_peer",
	TemporaryRelayFailure:     "temporary_relay_failure",
	RelayDisabled:             "relay_disabled",
	NodeNotFoundAtTargetRelay: "node_not_found_at_target_relay",
	TargetRealmRefused:        "target_realm_refused",
	LoopDetected:              "loop_detected",
	ExpiryTooSoon:             "expiry_too_soon",
	UpstreamCongestion:        "upstream_congestion",
	InvalidPathHeader:         "invalid_path_header",
	CryptoPuzzleInvalid:       "crypto_puzzle_invalid",
	RealmNotAuthoritativeHere: "realm_not_authoritative_here",
	Tombstoned:                "tombstoned",
	PayloadTooLarge:           "payload_too_large",
	SignatureInvalid:          "signature_invalid",
	UnknownError:              "unknown_error",
	Unauthorized:              "unauthorized",
}

// nonRetryable mirrors the reference table's none | application |
// crypto_drop classes — everything else means "retry, differently."
var nonRetryable = map[Code]bool{
	Ok:                  true,
	TargetRealmRefused:  true,
	Tombstoned:          true,
	PayloadTooLarge:     true,
	Unauthorized:        true,
	CryptoPuzzleInvalid: true,
	SignatureInvalid:    true,
}

// Name is the machine-readable name a CALL ERROR frame carries
// alongside the numeric code.
func (c Code) Name() string {
	if n, ok := names[c]; ok {
		return n
	}
	return "unknown_error"
}

// IsRetryable reports whether the retry policy for c permits retrying
// at all. Advisory — a caller's own CALL state machine is the actual
// decision point, this just names the policy.
func (c Code) IsRetryable() bool {
	return !nonRetryable[c]
}

// FromU8 parses a wire-carried numeric code, or false if it's outside
// the 17 defined codes.
func FromU8(b uint8) (Code, bool) {
	c := Code(b)
	_, ok := names[c]
	return c, ok
}
