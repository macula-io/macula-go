// V8 check for Go: Macula's composite ML-DSA-87-PS384 (D7).
// M' = Prefix || Label || 0x00 || SHA-512(M); ML-DSA-87 signs M' with an
// empty context; RSA-PSS-4096 signs M' with SHA-384, MGF1-SHA-384, salt 48.
// Signature = ML-DSA sig (4627) || RSA sig (512); key = ML-DSA raw (2592) || DER RSAPublicKey.
package main

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const (
	prefix       = "CompositeAlgorithmSignatures2025"
	label        = "MACULA-ML-DSA-87-PS384"
	mldsaPubLen  = mldsa.MLDSA87PublicKeySize
	mldsaSigLen  = mldsa.MLDSA87SignatureSize
	refMPrimeHex = "436f6d706f73697465416c676f726974686d5369676e617475726573323032354d4143554c412d4d4c2d4453412d38372d505333383400e4f23edffade3a0a47087a2f675e84d4ed9c126f824e93c09ae81c09033b82d3ef4b9c62d5bbc6238b99df1bec305ed30456cd776dca2e8182ecc35e4c72b7f7"
)

var pss = &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}
var failed bool

func mprime(m []byte, lbl string) []byte {
	ph := sha512.Sum512(m)
	out := make([]byte, 0, len(prefix)+len(lbl)+1+len(ph))
	out = append(out, prefix...)
	out = append(out, lbl...)
	out = append(out, 0x00)
	return append(out, ph[:]...)
}

func verify(m, pub, sig []byte, lbl string) bool {
	if len(pub) <= mldsaPubLen || len(sig) <= mldsaSigLen {
		return false
	}
	mpk, err := mldsa.NewPublicKey(mldsa.MLDSA87(), pub[:mldsaPubLen])
	if err != nil {
		return false
	}
	rpk, err := x509.ParsePKCS1PublicKey(pub[mldsaPubLen:])
	if err != nil {
		return false
	}
	mp := mprime(m, lbl)
	mlOK := mldsa.Verify(mpk, mp, sig[:mldsaSigLen], nil) == nil
	h := sha512.Sum384(mp)
	rsaOK := rsa.VerifyPSS(rpk, crypto.SHA384, h[:], sig[mldsaSigLen:], pss) == nil
	return mlOK && rsaOK
}

func check(ok bool, what string) {
	if ok {
		fmt.Println("  ok:  ", what)
		return
	}
	fmt.Println("  FAIL:", what)
	failed = true
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 1
	return c
}

func main() {
	dir := os.Args[1]
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			fmt.Println("read:", err)
			os.Exit(2)
		}
		return b
	}

	ref, _ := hex.DecodeString(refMPrimeHex)
	mRef := mprime([]byte("macula-composite-vector"), label)
	check(len(mRef) == 119, "M' is 119 bytes")
	check(bytes.Equal(mRef, ref), "M' matches Mercury's reference byte for byte")

	// Part 1a: the OTP-produced vector verifies in Go.
	m := read("message.bin")
	oPub, oSig := read("otp_composite_pub.bin"), read("otp_composite_sig.bin")
	check(verify(m, oPub, oSig, label), "OTP composite verifies in Go")
	check(!verify(m, oPub, flip(oSig, 0), label), "altered ML-DSA half is refused")
	check(!verify(m, oPub, flip(oSig, mldsaSigLen), label), "altered RSA-PSS half is refused")
	check(!verify(m, oPub, oSig, "COMPSIG-MLDSA87-RSA4096-PSS-SHA512"), "a different label is refused")

	// Part 1b: Go signs; OTP verifies next.
	msk, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		fmt.Println("mldsa keygen:", err)
		os.Exit(2)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		fmt.Println("rsa keygen:", err)
		os.Exit(2)
	}
	mp := mprime(m, label)
	mlSig, err := msk.Sign(rand.Reader, mp, crypto.Hash(0))
	if err != nil {
		fmt.Println("mldsa sign:", err)
		os.Exit(2)
	}
	h := sha512.Sum384(mp)
	rSig, err := rsa.SignPSS(rand.Reader, rk, crypto.SHA384, h[:], pss)
	if err != nil {
		fmt.Println("rsa sign:", err)
		os.Exit(2)
	}
	der := x509.MarshalPKCS1PublicKey(&rk.PublicKey)
	check(len(der) == 526, fmt.Sprintf("DER RSAPublicKey is 526 bytes (got %d)", len(der)))
	gPub := append(append(make([]byte, 0, mldsaPubLen+len(der)), msk.PublicKey().Bytes()...), der...)
	gSig := append(append(make([]byte, 0, len(mlSig)+len(rSig)), mlSig...), rSig...)
	check(len(gSig) == 5139, fmt.Sprintf("composite signature is 5,139 bytes (got %d)", len(gSig)))
	check(verify(m, gPub, gSig, label), "Go composite verifies in Go")
	_ = os.WriteFile(filepath.Join(dir, "go_composite_pub.bin"), gPub, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "go_composite_sig.bin"), gSig, 0o644)

	if failed {
		os.Exit(1)
	}
}
