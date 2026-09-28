package main

// #include <stdint.h>
import "C"

import (
	"encoding/hex"
	"encoding/json"

	"github.com/macula-io/macula-go/stationlink"
)

// The seal report through the ABI (macula's DESIGN_E2E_SEAL_REPORT §6): a
// call's is the envelope "report": 1 asks for, a stream's the JSON
// macula_stream_report returns. Both carry "sealed" (0 or 1, never a boolean),
// "provider" (the target's node_id as hex) and, when sealed, "seal_key_id"
// (the key's 8-byte id as hex). Since macula-go v0.19.0.

// reportFields is a report as the ABI carries it.
func reportFields(r stationlink.Report) map[string]any {
	out := map[string]any{"sealed": r.Sealed, "provider": hex.EncodeToString(r.Provider[:])}
	if r.Sealed == 1 {
		out["seal_key_id"] = hex.EncodeToString(r.SealKeyID[:])
	}
	return out
}

// streamReportJSON is a caller stream's settled report, or ErrNotSettled or
// ErrNotACaller.
func streamReportJSON(s *stationlink.Stream) (string, error) {
	report, err := s.Report()
	if err != nil {
		return "", err
	}
	text, _ := json.Marshal(reportFields(report))
	return string(text), nil
}

//export macula_stream_report
func macula_stream_report(h C.uintptr_t, errOut **C.char) *C.char {
	s := streamOf(h, errOut)
	if s == nil {
		return nil
	}
	text, err := streamReportJSON(s)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	return cString(text)
}
