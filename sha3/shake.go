// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file defines the VariableHash interface, and provides
// functions for creating SHAKE instances, as well as utility
// functions for hashing bytes to arbitrary-length output.

import (
	"io"
)

// VariableHash defines the interface to hash functions that
// support arbitrary-length output.
type VariableHash interface {
	// Write absorbs more data into the hash's state.
	// It never returns an error.
	io.Writer
	// Read reads more output from the hash; reading affects the hash's
	// state. (VariableHash.Read is thus very different from Hash.Sum)
	// It never returns an error.
	io.Reader

	// Barrier overwrites (200 - rate) bytes of the hash's state
	// with zeros, making it computationally infeasible to recover
	// previous inputs.
	Barrier()

	// Reset resets the Hash to its initial state.
	Reset()
}

// NewShake128 creates a new SHAKE128 variable-output-length Sponge.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() VariableHash { return &state{rate: 168, dsbyte: 0x1f} }

// NewShake256 creates a new SHAKE128 variable-output-length Sponge.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() VariableHash { return &state{rate: 136, dsbyte: 0x1f} }

// ShakeSum128 writes an arbitrary-length digest of data into hash.
func ShakeSum128(hash, data []byte) {
	h := NewShake128()
	h.Write(data)
	h.Read(hash)
}

// ShakeSum256 writes an arbitrary-length digest of data into hash.
func ShakeSum256(hash, data []byte) {
	h := NewShake256()
	h.Write(data)
	h.Read(hash)
}
