// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// This file provides functions for creating instances of the SHA-3
// and SHAKE hash functions, as well as utility functions for hashing
// bytes.

import "hash"

/*
func init() {
	crypto.RegisterHash(crypto.SHA3_224, New224)
	crypto.RegisterHash(crypto.SHA3_256, New256)
	crypto.RegisterHash(crypto.SHA3_384, New384)
	crypto.RegisterHash(crypto.SHA3_512, New512)
}*/

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

// NewShake128 creates a new SHAKE128 variable-output-length Sponge.
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() VariableHash { return &state{rate: 168, dsbyte: 0x1f} }

// NewShake256 creates a new SHAKE128 variable-output-length Sponge.
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() VariableHash { return &state{rate: 136, dsbyte: 0x1f} }

// Sum224 returns the SHA3-224 digest of the data.
func Sum224(data []byte) (digest [28]byte) {
	h := New224()
	h.Write(data)
	sum := h.Sum(nil)
	copy(digest[:], sum)
	return
}

// Sum256 returns the SHA3-256 digest of the data.
func Sum256(data []byte) (digest [32]byte) {
	h := New256()
	h.Write(data)
	sum := h.Sum(nil)
	copy(digest[:], sum)
	return
}

// Sum384 returns the SHA3-384 digest of the data.
func Sum384(data []byte) (digest [48]byte) {
	h := New384()
	h.Write(data)
	sum := h.Sum(nil)
	copy(digest[:], sum)
	return
}

// Sum512 returns the SHA3-512 digest of the data.
func Sum512(data []byte) (digest [64]byte) {
	h := New512()
	h.Write(data)
	sum := h.Sum(nil)
	copy(digest[:], sum)
	return
}

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
