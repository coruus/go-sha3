// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package sha3

import (
	"hash"
	"io"
)

// Sponge defines the interface to cryptographic sponges.
//
// TODO(dlg): Clear exposition of cryptographic sponge functions in
// ~ 200 words.
// TODO(dlg): Usage examples:
//   - single-call hash functions
//   - sponge CSPRNG with backtracking-resistance (for MakeOneWay()
//   - stream cipher
type Sponge interface {
	hash.Hash
	io.Reader

	// SpongeSize returns the size, in bytes, of the state of the sponge.
	SpongeSize() int
	// Rate returns the number of bytes that can be absorbed or squeezed
	// from the Sponge before the permutation is applied.
	Rate() int
	// SecurityStrength returns the generic security strength, in bits,
	// of this Sponge instance. It is equal to 8 * ((SpongeSize() - Rate()) / 2).
	SecurityStrength() int

	// Absorb xors up to Rate() bytes from the input into the state, applies
	// the permutation, and repeats, until all the input has been absorbed.
	Absorb([]byte) int

	// Squeeze copies up to Rate() bytes from the state into the output buffer,
	// applies the permutation, and repeats until output of the requested length
	// has been provided.
	Squeeze([]byte, int) []byte

	// MakeOneWay overwrites SecurityStrength() / 2 bits of the state with zeros
	// and applies the permutation; after doing this, it is no longer possible
	// to use the inverse of the permutation to recover previous inputs.
	MakeOneWay()

	// Pad xors a domain separator byte into the state, appends multi-bitrate
	// padding, and applies the permutation.
	Pad(dsbyte byte)
}
