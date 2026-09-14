// Reproduces Mercury's node_id vectors for D5:
// node_id = SHA-256(Label || 0x00 || len(Profile) || Profile || IdentityKey)
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const label = "MACULA-NODE-ID-V1"

func nodeID(profile string, key []byte) string {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0x00, byte(len(profile))})
	h.Write([]byte(profile))
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil))
}

func testKey(n int) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = byte(i % 256)
	}
	return k
}

func main() {
	fmt.Printf("label hex %X (len %d)\n", label, len(label))
	vs := []struct{ name, profile string; n int; want string }{
		{"V1", "pq_pure", 2592, "8c6a28c62bda0112065bccb0d8b02b18f46fef03d16e8b7ae91086025dd209ff"},
		{"V2", "pq_hybrid", 3118, "e9df1133a8238239c58fc7f886d9667e961449ee272c30e968a0eecbb6b0131c"},
		{"V3", "pq_hybrid", 2592, "4e79818f04bffbd7f2df71b82e3e543458d9f74cda64f88a80b352ed8e9af10b"},
	}
	for _, v := range vs {
		got := nodeID(v.profile, testKey(v.n))
		fmt.Printf("%s %-9s %d bytes: %s match=%v\n", v.name, v.profile, v.n, got, got == v.want)
	}
}
