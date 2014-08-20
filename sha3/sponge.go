package sha3

import (
	"hash"
)

// Sponge defines the interface to cryptographic sponges. A sponge is
// instantiated by a permutation, a padding rule, and a "rate". Its
// capacity (in bytes) is equal to the width of the permutation
// minus the rate.
type Sponge interface {
	hash.Hash // TODO: Should this include hash.Hash?

	SpongeSize() int
	Rate() int

	// Apply the underlying permutation.
	//	Permute()

	// The three basic sponge operations; all apply the underlying
	// permutation when the sponge is dry.
	Absorb([]byte) int          // XOR bytes into state[:rate]
	Squeeze([]byte, int) []byte // Copy bytes out of state[:rate]
	//	Overwrite([]byte) int       // Overwrite bytes in state[:rate]

	// Apply the padding rule to the state, and then permute it.
	// (This is similar to hash finalization.)
	Pad(byte)

	//	NewSponge(rate int)
}
