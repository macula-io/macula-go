// Command godevicerequest proves devicerequest against a live realm with a
// fresh identity key that is never saved: a v2 join session over HTTP, the same
// request with its device_info changed after signing (which the realm must
// refuse), and a membership UCAN over the mesh.
//
//	godevicerequest -realm-url https://realm.macula.io -realm io.macula -realm-key <file of hex> \
//	    -station host:port@<node id hex>
//
// It prints each step's outcome and exits 1 if any step is not what the realm
// must answer.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/devicerequest"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
)

func main() {
	realmURL := flag.String("realm-url", "https://realm.macula.io", "the realm's HTTP base URL")
	realmName := flag.String("realm", "io.macula", "the realm's name")
	realmKeyFile := flag.String("realm-key", "", "a file holding the realm key as carried, in hex")
	station := flag.String("station", "", "a station to link to: host:port@<node id hex>")
	flag.Parse()

	key, err := identity.GenerateIdentityKey(profile.PQHybrid, identity.PuzzleDifficulty)
	must(err)
	nodeID, err := key.NodeID()
	must(err)
	fmt.Printf("fresh node %x (never saved)\n", nodeID)
	realm := sha256.Sum256([]byte(*realmName))
	carried := base64.StdEncoding.EncodeToString(key.PublicKey())
	failed := false

	// A join session over HTTP, and the same body tampered after signing.
	body := map[string]any{
		"public_key": carried,
		"agent_mri":  fmt.Sprintf("mri:agent:%s/anonymous/godevicerequest-%x", *realmName, nodeID[:4]),
		"device_info": map[string]any{
			"hostname": "godevicerequest", "os": "linux/amd64", "version": "macula-go devicerequest live check",
		},
	}
	unsigned, _ := json.Marshal(body)
	request, err := devicerequest.JSONRequest(unsigned)
	must(err)
	proof, err := devicerequest.Sign(key, realm, devicerequest.ProcedureJoinSession, request)
	must(err)
	body["proof"] = proof
	status, answer := post(*realmURL+"/api/v1/join/sessions", body)
	failed = report("v2 join session", status == http.StatusCreated, status, answer) || failed
	body["device_info"].(map[string]any)["hostname"] = "tampered"
	status, answer = post(*realmURL+"/api/v1/join/sessions", body)
	failed = report("tampered device_info refused", status == http.StatusUnauthorized && strings.Contains(answer, "bad_proof"),
		status, answer) || failed

	// A membership UCAN over the mesh: the request is the payload less its proof.
	if *station != "" {
		failed = membership(key, nodeID, realm, *realmName, *realmKeyFile, *station) || failed
	}
	if failed {
		os.Exit(1)
	}
}

func membership(key *identity.NodeKey, nodeID, realm [32]byte, realmName, realmKeyFile, station string) bool {
	rawKey, err := os.ReadFile(realmKeyFile)
	must(err)
	realmKey, err := hex.DecodeString(strings.TrimSpace(string(rawKey)))
	must(err)
	at := strings.LastIndex(station, "@")
	colon := strings.LastIndex(station[:at], ":")
	port, err := strconv.Atoi(station[colon+1 : at])
	must(err)
	stationID, err := hex.DecodeString(station[at+1:])
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	p, err := pool.Connect(ctx, []pool.Seed{{Host: strings.Trim(station[:colon], "[]"), Port: uint16(port), NodeID: [32]byte(stationID)}},
		pool.Opts{IdentityKey: key, RealmTrust: map[[32]byte][]byte{realm: realmKey}})
	must(err)
	defer p.Close()
	carried := cbor.Text(base64.StdEncoding.EncodeToString(key.PublicKey()))
	request := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("public_key"), Val: carried}})
	proof, err := devicerequest.Sign(key, realm, devicerequest.ProcedureMembershipUCAN, request)
	must(err)
	payload := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("public_key"), Val: carried},
		{Key: cbor.Text("proof"), Val: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("v"), Val: cbor.Uint64(uint64(proof.V))},
			{Key: cbor.Text("timestamp"), Val: cbor.Uint64(proof.Timestamp)},
			{Key: cbor.Text("nonce"), Val: cbor.Text(proof.Nonce)},
			{Key: cbor.Text("signature"), Val: cbor.Text(proof.Signature)},
		})},
	})
	result, err := p.Call(ctx, pool.Call{Realm: realm, Procedure: realmName + "/_realm/_realm/identity/issue_membership_ucan_v1",
		Payload: payload, Timeout: 15 * time.Second})
	if err != nil {
		return report("v2 membership UCAN", false, 0, err.Error())
	}
	// The realm's handler answers citizen_did as the bytes of its hex text.
	did, _ := result.Get("citizen_did")
	text := did.String()
	if t, ok := did.AsText(); ok {
		text = t
	} else if b, ok := did.AsBytes(); ok {
		text = string(b)
	}
	ok := strings.Contains(strings.ToLower(text), hex.EncodeToString(nodeID[:]))
	return report("v2 membership UCAN", ok, 0, fmt.Sprintf("citizen_did %s", text))
}

func post(url string, body any) (int, string) {
	text, _ := json.Marshal(body)
	res, err := http.Post(url, "application/json", bytes.NewReader(text))
	must(err)
	defer res.Body.Close()
	answer, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(answer)
}

// report prints a step's outcome and reports whether it failed.
func report(step string, ok bool, status int, detail string) bool {
	verdict := "ok  "
	if !ok {
		verdict = "FAIL"
	}
	if len(detail) > 200 {
		detail = detail[:200]
	}
	fmt.Printf("%s %s: HTTP %d %s\n", verdict, step, status, detail)
	return !ok
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "godevicerequest:", err)
		os.Exit(2)
	}
}
