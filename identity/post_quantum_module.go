//go:build !fips140v1.0

package identity

// mldsaInModule is true in a binary whose FIPS 140-3 Go Cryptographic Module has
// ML-DSA: one built without GOFIPS140, or with a module version after v1.0.0.
const mldsaInModule = true
