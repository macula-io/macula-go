//go:build fips140v1.0

package identity

// mldsaInModule is false in a binary built with GOFIPS140=v1.0.0. The go
// command sets the fips140v1.0 build tag for that module, and crypto/mldsa
// builds on the same tag as a stub without ML-DSA.
const mldsaInModule = false
