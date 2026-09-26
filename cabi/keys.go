package main

// #include <stdint.h>
// #include <stddef.h>
import "C"

import (
	"context"
	"errors"
	"io/fs"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// parseProfile is the profile a binding names; "" (NULL) is pq_hybrid, the
// fleet's.
func parseProfile(name string) (profile.Profile, error) {
	if name == "" {
		return profile.PQHybrid, nil
	}
	p, err := profile.Parse(name)
	if err != nil {
		return "", invalidArgument("%v", err)
	}
	return p, nil
}

// generateKey is a new identity key whose node_id solves the admission
// puzzle, given up when ctx ends.
func generateKey(ctx context.Context, profileName string) (*identity.NodeKey, error) {
	p, err := parseProfile(profileName)
	if err != nil {
		return nil, err
	}
	return identity.GenerateIdentityKeyContext(ctx, p, identity.PuzzleDifficulty)
}

// loadKey reads the identity key file at path in profileName.
func loadKey(path, profileName string) (*identity.NodeKey, error) {
	p, err := parseProfile(profileName)
	if err != nil {
		return nil, err
	}
	return identity.LoadKey(path, identity.PurposeIdentity, p)
}

// loadOrCreateKey reads the key at path, or, when there is no file there,
// generates one and saves it, readable by its owner only. Any other failure
// to read it (its permissions, another profile, a damaged file) is an error,
// never a reason to replace it.
func loadOrCreateKey(ctx context.Context, path, profileName string) (*identity.NodeKey, error) {
	key, err := loadKey(path, profileName)
	if !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}
	key, err = generateKey(ctx, profileName)
	if err != nil {
		return nil, err
	}
	if err := key.Save(path); err != nil {
		return nil, err
	}
	return key, nil
}

//export macula_key_generate
func macula_key_generate(profileName *C.char, token C.uintptr_t, errOut **C.char) C.uintptr_t {
	ctx, cancel, err := callContext(token, 0)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	defer cancel()
	key, err := generateKey(ctx, goString(profileName))
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return 0
	}
	return newHandle(key)
}

//export macula_key_load
func macula_key_load(path, profileName *C.char, errOut **C.char) C.uintptr_t {
	key, err := loadKey(goString(path), goString(profileName))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return newHandle(key)
}

//export macula_key_load_or_create
func macula_key_load_or_create(path, profileName *C.char, token C.uintptr_t, errOut **C.char) C.uintptr_t {
	ctx, cancel, err := callContext(token, 0)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	defer cancel()
	key, err := loadOrCreateKey(ctx, goString(path), goString(profileName))
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return 0
	}
	return newHandle(key)
}

func keyOf(h C.uintptr_t, errOut **C.char) *identity.NodeKey {
	key, ok := valueOf[*identity.NodeKey](h)
	if !ok {
		setErr(errOut, errInvalidHandle)
		return nil
	}
	return key
}

//export macula_key_save
func macula_key_save(h C.uintptr_t, path *C.char, errOut **C.char) {
	if key := keyOf(h, errOut); key != nil {
		setErr(errOut, key.Save(goString(path)))
	}
}

//export macula_key_node_id
func macula_key_node_id(h C.uintptr_t, out *C.uint8_t, errOut **C.char) {
	key := keyOf(h, errOut)
	if key == nil {
		return
	}
	id, err := key.NodeID()
	if err != nil {
		setErr(errOut, err)
		return
	}
	writeFixed(out, id[:])
}

//export macula_key_public_key
func macula_key_public_key(h C.uintptr_t, outLen *C.size_t, errOut **C.char) *C.uint8_t {
	key := keyOf(h, errOut)
	if key == nil {
		return nil
	}
	return cBytes(key.PublicKey(), outLen)
}

//export macula_key_profile
func macula_key_profile(h C.uintptr_t, errOut **C.char) *C.char {
	key := keyOf(h, errOut)
	if key == nil {
		return nil
	}
	return cString(string(key.Profile()))
}

//export macula_key_sign
func macula_key_sign(h C.uintptr_t, data *C.uint8_t, dataLen C.size_t, outLen *C.size_t, errOut **C.char) *C.uint8_t {
	key := keyOf(h, errOut)
	if key == nil {
		return nil
	}
	signature, err := key.Sign(goBytes(data, dataLen))
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	return cBytes(signature, outLen)
}

//export macula_verify
func macula_verify(data *C.uint8_t, dataLen C.size_t, signature *C.uint8_t, signatureLen C.size_t,
	publicKey *C.uint8_t, publicKeyLen C.size_t, profileName *C.char, errOut **C.char) C.int32_t {
	p, err := parseProfile(goString(profileName))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	if identity.Verify(goBytes(data, dataLen), goBytes(signature, signatureLen), goBytes(publicKey, publicKeyLen), p) {
		return 1
	}
	return 0
}

//export macula_key_free
func macula_key_free(h C.uintptr_t) {
	if _, ok := valueOf[*identity.NodeKey](h); ok {
		release(h)
	}
}
