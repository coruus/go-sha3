// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha3 implements the SHA-3 fixed-output-length hash functions and
// the SHAKE variable-output-length has function defined by FIPS-202.
//
// Both functions use a sponge construction and the KeccakF-1600 permutation.
//
// For a detailed specification of the functions, see http://keccak.noekeon.org/
//
package sha3

import (
	"encoding/binary"
	"errors"
	"hash"
)

/*
func init() {
	crypto.RegisterHash(crypto.SHA3_224, New224)
	crypto.RegisterHash(crypto.SHA3_256, New256)
	crypto.RegisterHash(crypto.SHA3_384, New384)
	crypto.RegisterHash(crypto.SHA3_512, New512)
	crypto.RegisterHash(crypto.SHAKE128, NewShake128)
	crypto.RegisterHash(crypto.SHAKE256, NewShake256)
}*/

type spongeState int

const (
	stateAbsorbing spongeState = 0    // the sponge can absorb more input
	stateSqueezing             = iota // the sponge can *only* be squeezed
	stateSqueezed                     // all the output permitted has been squeezed
)

const (
	bytebufLen = 176 // the length of the input buffer; determines maximum rate
)

var (
	errSha3CanOnlySqueezeOnce = errors.New(
		"fixed-output-length functions can only be squeezed once")
	errSha3DigestTooLong = errors.New(
		"too much output requested from a fixed-output-length hash")
)

// digest is a sponge object (TODO(?): rename?)
type digest struct {
	a           [25]uint64       // main state of the hash
	bytebuf     [bytebufLen]byte // the input buffer
	dsbyte      byte             // the domain separator byte
	fixedOutput bool             // whether this is a fixed-ouput-length instance
	outputSize  int              // desired output size in bytes
	position    int              // position in the input buffer
	rate        int              // the maximum number of bytes to touch in the state
	state       spongeState      // current state of the sponge (absorbing or squeezing)
}

// minInt returns the lesser of two integer arguments.
func minInt(v1, v2 int) int {
	if v1 <= v2 {
		return v1
	}
	return v2
}

// SpongeSize returns the size, in bytes, of the sponge. (For KeccakF-1600, this
// is always 200 bytes.)
func (d *digest) SpongeSize() int {
	return 200
}

// SecurityStrength returns the generic security strength (in bits) of this
// sponge instance.
func (d *digest) SecurityStrength() int {
	return 8 * (200 - (d.rate / 2))
}

// Rate returns the byterate of the sponge
func (d *digest) Rate() int {
	return d.rate
}

// Reset clears the internal state by zeroing the sponge state, as well
// as the byte buffer.
func (d *digest) Reset() {
	d.position = 0
	for i := range d.a {
		d.a[i] = 0
	}
	for i := range d.bytebuf {
		d.bytebuf[i] = 0
	}
	d.state = stateAbsorbing
}

// BlockSize is the rate of the sponge instance underlying the hash function.
func (d *digest) BlockSize() int { return d.rate }

// Size returns the output size of the hash function in bytes.
func (d *digest) Size() int { return d.outputSize }

// xorInBytes xors the input buffer into the state, byte-swapping to
// little-endian as necessary
func (d *digest) xorFromBytebuf() {
	for i := 0; i < 21; i++ {
		ai := binary.LittleEndian.Uint64(d.bytebuf[i*8:])
		d.a[i] ^= ai
	}
	d.position = 0
	for i := range d.bytebuf {
		d.bytebuf[i] = 0
	}
}

// copyToBytebuf copies from the sponge state to the output buffer
func (d *digest) copyToBytebuf() {
	for i := 0; i < 21; i++ {
		binary.LittleEndian.PutUint64(d.bytebuf[i*8:(i+1)*8], d.a[i])
	}
}

// permute applies the KeccakF-1600 permutation
func (d *digest) permute() {
	keccakF(&d.a)
}

// Write absorbs bytes into the state of the SHA3 hash, updating as needed
// when the sponge fills up with rate bytes.
func (d *digest) Write(p []byte) (inputOffset int, err error) {
	toWrite := len(p)
	inputOffset = 0
	for toWrite > 0 {
		canWrite := d.rate - d.position
		willWrite := minInt(toWrite, canWrite)

		copy(d.bytebuf[d.position:], p[inputOffset:inputOffset+willWrite])
		d.position += willWrite
		if d.position == d.rate {
			d.xorFromBytebuf()
			d.permute()
		}
		toWrite -= willWrite
		inputOffset += willWrite
	}
	return int(inputOffset), nil
}

// pad appends the domain separation bits and applies the multi-bitrate
// 10..1 padding rule. (dsbyte must contain the leading 1 bit)
func (d *digest) pad(dsbyte byte) {
	d.bytebuf[d.position] ^= dsbyte
	d.bytebuf[d.rate-1] ^= 0x80
}

// finalize prepares the hash to output data by applying the padding,
// xoring the last block into the state, applying the permutation, and
// copying the first buffer-length of output.
func (d *digest) finalize() {
	// Pad with this instance's domain-separator bits.
	d.pad(d.dsbyte)
	d.xorFromBytebuf()
	d.permute()
	d.copyToBytebuf()
	d.state = stateSqueezing
}

// Squeeze outputs an arbitrary number of bytes from the hash state.
// Squeezing can require multiple calls to the F function (one per rate() bytes
// squeezed).
func (d *digest) Squeeze(in []byte, toSqueeze int) (out []byte, err error) {
	// Check that the sponge is in the correct state.
	switch d.state {
	case stateAbsorbing:
		// If we're still absorbing, pad and apply the permutation.
		d.finalize()
		d.state = stateSqueezing
	case stateSqueezed:
		// This only gets set for the FOFs.
		return nil, errSha3CanOnlySqueezeOnce
	}

	// If this is a fixed-output length instance, we only allow
	// the sponge to be squeezed once, and only allow squeezing
	// up to OutputSize() bytes.
	if d.fixedOutput {
		if toSqueeze > (d.outputSize - d.position) {
			toSqueeze = (d.outputSize - d.position)
		}
		// Set to prevent another call. TODO(dlg): necessary?
		d.state = stateSqueezed
	}

	// Now, do the squeezing.
	out = make([]byte, toSqueeze)
	outOffset := 0
	for toSqueeze != 0 {
		canSqueeze := d.rate - d.position
		willSqueeze := minInt(toSqueeze, canSqueeze)

		// Copy the output from the sponge's buffer.
		copy(out[outOffset:outOffset+willSqueeze],
			d.bytebuf[d.position:d.position+willSqueeze])

		d.position += willSqueeze
		outOffset += willSqueeze
		toSqueeze -= willSqueeze

		// Apply the permutation if we've squeezed the sponge dry.
		if d.position == d.rate {
			d.permute()
			d.copyToBytebuf()
			d.position = 0
		}
	}
	return append(in, out...), nil
}

// Sum applies padding to the hash state and then squeezes out the desired number of output bytes.
func (d *digest) Sum(in []byte) []byte {
	// Make a copy of the original hash so that caller can keep writing and summing.
	dup := *d
	out, err := dup.Squeeze(in, dup.outputSize)
	if err != nil {
		panic("error in sha3.Sum: this should not be possible; an invalid" +
			"output size has been chosen")
		//TODO: what should the error behavior be?
	}
	return out
}

// SHA-3 fixed-output-length functions. These are intended for use as
// "drop-in" replacements for the corresponding SHA-2 instances. They
// have the same generic security strengths. NIST recommends that most
// new applications use a SHAKE variable-output-length instance.

// New224 creates a new SHA3-224 hash
// Its generic security strength is 224 bits against preimage attacks,
// and 112 bits against collision attacks.
func New224() hash.Hash {
	d := &digest{
		outputSize:  224 / 8,
		fixedOutput: true,
		rate:        200 - (2 * 224 / 8),
		dsbyte:      0x06}
	return d
}

// New256 creates a new SHA3-256 hash
// Its generic security strength is 256 bits against preimage attacks,
// and 128 bits against collision attacks.
func New256() hash.Hash {
	return &digest{
		outputSize:  256 / 8,
		fixedOutput: true,
		rate:        200 - (2 * 256 / 8),
		dsbyte:      0x06}
}

// New384 creates a new SHA3-384 hash
// Its generic security strength is 384 bits against preimage attacks,
// and 192 bits against collision attacks.
func New384() hash.Hash {
	return &digest{
		outputSize:  384 / 8,
		fixedOutput: true,
		rate:        200 - (2 * 384 / 8),
		dsbyte:      0x06}
}

// New512 creates a new SHA3-512 hash.Hash
// Its generic security strength is 512 bits against preimage attacks,
// and 256 bits against collision attacks.
func New512() hash.Hash {
	return &digest{
		outputSize:  512 / 8,
		fixedOutput: true,
		rate:        200 - (2 * 512 / 8),
		dsbyte:      0x06}
}

// SHAKE variable-output-length hash functions.

// NewShake128 creates a new SHAKE128 variable-output-length hash.Hash
// Its generic security strength is 128 bits against all attacks if at
// least 32 bytes of its output are used.
func NewShake128() hash.Hash {
	return &digest{
		fixedOutput: false,
		outputSize:  512,
		rate:        200 - (2 * 128 / 8),
		dsbyte:      0x1f}
}

// NewShake256 creates a new SHAKE128 variable-output-length hash.Hash
// Its generic security strength is 256 bits against all attacks if
// at least 64 bytes of its output are used.
func NewShake256() hash.Hash {
	return &digest{
		fixedOutput: false,
		outputSize:  512,
		rate:        200 - (2 * 256 / 8),
		dsbyte:      0x1f}
}

// NewShake creates a new SHAKE variable-output-length hash of any
// desired rate > 0 and < bytebufLen. Note that this is *not* approved
// for use by FIPS-202, unless rate == 168 or rate == 136.
func NewShake(rate int) hash.Hash {
	if rate > bytebufLen || rate <= 0 {
		return nil
	}
	return &digest{
		fixedOutput: false,
		outputSize:  int(rate),
		rate:        int(rate),
		dsbyte:      0x1f}
}
