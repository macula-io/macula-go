package main

// #include <stdint.h>
import "C"

import (
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/ucan"
)

// End-to-end confidentiality through the ABI (macula 13, E2E design): the
// *_opts functions take their options as JSON, so options added later need no
// new function. A call or an open takes {"provider", "ucan", "proofs",
// "confidential"}, "confidential" "preferred" (the default) or "required"; a
// served procedure {"policy", "confidential"}, "confidential" also "off".

// callOptions are a call's or an open's options.
type callOptions struct {
	provider     *[32]byte
	creds        credentials
	confidential stationlink.Confidentiality
}

type callOptionsJSON struct {
	Provider     string   `json:"provider"`
	UCAN         string   `json:"ucan"`
	Proofs       []string `json:"proofs"`
	Confidential string   `json:"confidential"`
}

// callOptionsOf reads options_json of a call or an open ("" for none).
func callOptionsOf(text string) (callOptions, error) {
	var o callOptionsJSON
	if text != "" {
		if err := decodeStrict("options_json", text, &o); err != nil {
			return callOptions{}, err
		}
	}
	conf, err := confidentialityOf(o.Confidential)
	if err != nil {
		return callOptions{}, err
	}
	if conf == stationlink.ConfidentialOff {
		// Only an advertisement naming no key is called in the clear; off is
		// an explicit target's, which the ABI does not offer.
		return callOptions{}, invalidArgument("confidential off is refused for a call or an open: it is preferred or required")
	}
	opts := callOptions{confidential: conf}
	if o.Provider != "" {
		id, err := hexID("options_json's provider", o.Provider)
		if err != nil {
			return callOptions{}, err
		}
		opts.provider = &id
	}
	if o.UCAN != "" {
		opts.creds.token = []byte(o.UCAN)
	}
	for _, p := range o.Proofs {
		opts.creds.proofs = append(opts.creds.proofs, []byte(p))
	}
	return opts, nil
}

// serveOptions are a served procedure's options.
type serveOptions struct {
	policy       ucan.Policy
	confidential stationlink.Confidentiality
}

type serveOptionsJSON struct {
	Policy       *policyJSON `json:"policy"`
	Confidential string      `json:"confidential"`
}

// serveOptionsOf reads options_json of a served procedure ("" for none).
func serveOptionsOf(text string) (serveOptions, error) {
	var o serveOptionsJSON
	if text != "" {
		if err := decodeStrict("options_json", text, &o); err != nil {
			return serveOptions{}, err
		}
	}
	conf, err := confidentialityOf(o.Confidential)
	if err != nil {
		return serveOptions{}, err
	}
	opts := serveOptions{confidential: conf}
	if o.Policy != nil {
		policy, err := policyValue(*o.Policy)
		if err != nil {
			return serveOptions{}, err
		}
		opts.policy = policy
	}
	return opts, nil
}

// confidentialityOf is "confidential": preferred when absent.
func confidentialityOf(name string) (stationlink.Confidentiality, error) {
	switch name {
	case "", "preferred":
		return stationlink.ConfidentialPreferred, nil
	case "required":
		return stationlink.ConfidentialRequired, nil
	case "off":
		return stationlink.ConfidentialOff, nil
	}
	return 0, invalidArgument("confidential is preferred, required or off, not %q", name)
}

//export macula_pool_call_opts
func macula_pool_call_opts(h C.uintptr_t, realm32 *C.uint8_t, procedure, payloadJSON, optionsJSON *C.char,
	timeoutMs C.int64_t, token C.uintptr_t, errOut **C.char) *C.char {
	opts, err := callOptionsOf(goString(optionsJSON))
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	return poolCall(h, realm32, procedure, payloadJSON, opts, timeoutMs, token, errOut)
}

//export macula_pool_open_stream_opts
func macula_pool_open_stream_opts(h C.uintptr_t, realm32 *C.uint8_t, procedure *C.char, mode C.int32_t,
	payloadJSON, optionsJSON *C.char, deadlineMs C.int64_t, timeoutMs C.int64_t, token C.uintptr_t,
	errOut **C.char) C.uintptr_t {
	opts, err := callOptionsOf(goString(optionsJSON))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return poolOpenStream(h, realm32, procedure, mode, payloadJSON, opts, deadlineMs, timeoutMs, token, errOut)
}

//export macula_pool_serve_opts
func macula_pool_serve_opts(h C.uintptr_t, realm32 *C.uint8_t, procedure, optionsJSON *C.char,
	errOut **C.char) C.uintptr_t {
	opts, err := serveOptionsOf(goString(optionsJSON))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return poolServe(h, realm32, procedure, opts, errOut)
}

//export macula_pool_serve_stream_opts
func macula_pool_serve_stream_opts(h C.uintptr_t, realm32 *C.uint8_t, procedure *C.char, mode C.int32_t,
	optionsJSON *C.char, errOut **C.char) C.uintptr_t {
	opts, err := serveOptionsOf(goString(optionsJSON))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return poolServeStream(h, realm32, procedure, mode, opts, errOut)
}
