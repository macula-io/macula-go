package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"os"
	"path/filepath"

	bp "github.com/ebfe/brainpool"
)

func must(b []byte, err error) []byte {
	if err != nil {
		fmt.Println("read:", err)
		os.Exit(2)
	}
	return b
}

func main() {
	vec := os.Args[1]
	out := os.Args[2]
	msg := must(os.ReadFile(filepath.Join(vec, "message.bin")))
	h := sha512.Sum384(msg)
	curve := bp.P384r1()
	fail := false

	// 1. OTP-produced brainpoolP384r1 ECDSA signature verifies in Go?
	pubBytes := must(os.ReadFile(filepath.Join(vec, "bp384_pub_uncompressed.bin")))
	x, y := elliptic.Unmarshal(curve, pubBytes)
	if x == nil {
		fmt.Println("  OTP brainpool public key did not parse on this curve")
		fail = true
	} else {
		pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		ok := ecdsa.VerifyASN1(pub, h[:], must(os.ReadFile(filepath.Join(vec, "bp384_sig_der.bin"))))
		fmt.Printf("  OTP brainpool signature verifies in Go: %v\n", ok)
		fail = fail || !ok
	}

	// 2. Go signs with brainpoolP384r1; write it out for OTP to verify.
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Println("  Go brainpool keygen FAILED:", err)
		os.Exit(1)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		fmt.Println("  Go brainpool sign FAILED:", err)
		os.Exit(1)
	}
	self := ecdsa.VerifyASN1(&priv.PublicKey, h[:], sig)
	fmt.Printf("  Go brainpool sign then Go verify: %v (sig %d B)\n", self, len(sig))
	fail = fail || !self
	_ = os.WriteFile(filepath.Join(out, "go_bp384_pub.bin"), elliptic.Marshal(curve, priv.PublicKey.X, priv.PublicKey.Y), 0o644)
	_ = os.WriteFile(filepath.Join(out, "go_bp384_sig_der.bin"), sig, 0o644)

	// 3. OTP-produced ML-DSA-87 signature verifies in Go stdlib?
	mpk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), must(os.ReadFile(filepath.Join(vec, "mldsa87_pub.bin"))))
	if err != nil {
		fmt.Println("  OTP ML-DSA-87 public key parse FAILED:", err)
		fail = true
	} else {
		verr := mldsa.Verify(mpk, msg, must(os.ReadFile(filepath.Join(vec, "mldsa87_sig.bin"))), nil)
		fmt.Printf("  OTP ML-DSA-87 signature verifies in Go: %v\n", verr == nil)
		if verr != nil {
			fmt.Println("    ", verr)
			fail = true
		}
	}

	// 4. Go signs ML-DSA-87; write it out for OTP to verify.
	msk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err == nil {
		msig, serr := msk.Sign(nil, msg, crypto.Hash(0))
		if serr != nil {
			fmt.Println("  Go ML-DSA-87 sign FAILED:", serr)
			fail = true
		} else {
			_ = os.WriteFile(filepath.Join(out, "go_mldsa87_pub.bin"), msk.PublicKey().Bytes(), 0o644)
			_ = os.WriteFile(filepath.Join(out, "go_mldsa87_sig.bin"), msig, 0o644)
		}
	}
	if fail {
		os.Exit(1)
	}
}
