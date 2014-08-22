// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file provides functions for creating instances of the SHA-3
// and SHAKE hash functions. NewXXX creates a new fixed output length
// hash.Hash. NewShakeXXX creates a new variable output length Sponge.
import "hash"

/*
func init() {
	crypto.RegisterHash(crypto.SHA3_224, New224)
	crypto.RegisterHash(crypto.SHA3_256, New256)
	crypto.RegisterHash(crypto.SHA3_384, New384)
	crypto.RegisterHash(crypto.SHA3_512, New512)
}*/

// SHA-3 fixed-output-length functions. These are intended for use as
// "drop-in" replacements for the corresponding SHA-2 instances. They
// have the same generic security strengths against all attacks as the
// corresponding SHA-2 instances.

// New224 creates a new SHA3-224 hash
// Its generic security strength is 224 bits against preimage attacks,
// and 112 bits against collision attacks.
func New224() hash.Hash { return &state{rate: 144, outputSize: 28, dsbyte: 0x06} }

// New256 creates a new SHA3-256 hash
// Its generic security strength is 256 bits against preimage attacks,
// and 128 bits against collision attacks.
func New256() hash.Hash { return &state{rate: 136, outputSize: 32, dsbyte: 0x06} }

// New384 creates a new SHA3-384 hash
// Its generic security strength is 384 bits against preimage attacks,
// and 192 bits against collision attacks.
func New384() hash.Hash { return &state{rate: 104, outputSize: 48, dsbyte: 0x06} }

// New512 creates a new SHA3-512 hash.Hash
// Its generic security strength is 512 bits against preimage attacks,
// and 256 bits against collision attacks.
func New512() hash.Hash { return &state{rate: 72, outputSize: 64, dsbyte: 0x06} }

// SHAKE variable-output-length hash functions.

// NewShake128 creates a new SHAKE128 variable-output-length Sponge.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() VariableHash { return &state{rate: 168, dsbyte: 0x1f} }

// NewShake256 creates a new SHAKE128 variable-output-length Sponge.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() VariableHash { return &state{rate: 136, dsbyte: 0x1f} }
