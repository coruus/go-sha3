// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha3 implements the SHA3 hash algorithm (formerly called Keccak) chosen by NIST in 2012.
// This file provides a SHA3 implementation which implements the standard hash.Hash interface.
// Writing input data, including padding, and reading output data are computed in this file.
// Note that the current implementation can compute the hash of an integral number of bytes only.
// This is a consequence of the hash interface in which a buffer of bytes is passed in.
// The internals of the Keccak-f function are computed in keccakf.go.
// For the detailed specification, refer to the Keccak web site (http://keccak.noekeon.org/).
package sha3

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
)

type spongeState int
const (
	stateAbsorbing spongeState = 0
	stateSqueezing             = iota
	stateSqueezed
)

const (
	bytebufLen = 168
)

var (
	errSha3CanOnlySqueezeOnce = errors.New("fixed-output-length functions can only be squeezed once")
	errSha3DigestTooLong      = errors.New("more output was requested from an SHA-3 fixed-output-length function than it can provide")
)

// digest represents the partial evaluation of a checksum.
type digest struct {
	hash.Hash
	a           [25]uint64       // main state of the hash
	outputSize  int              // desired output size in bytes
	bytebuf     [bytebufLen]byte // the input buffer (max rate == 168)
	rate        int              // the maximum number of bytes to touch in the state
	position    int              // position in the input buffer
	state       spongeState      // current state of the sponge (absorbing or squeezing)
	dsbyte      byte             // the domain separator byte
	fixedOutput bool             // whether this is a fixed-ouput-length instance
}

// minInt returns the lesser of two integer arguments, to simplify the absorption routine.
func minInt(v1, v2 int) int {
	if v1 <= v2 {
		return v1
	}
	return v2
}

func (d *digest) SpongeSize() int {
	return 200
}

// SecurityStrength returns the generic security strength (in bits) of this
// sponge instance.
func (d *digest) SecurityStrength() int {
	return 8 * (200 - (d.rate / 2))
}

// Reset clears the internal state by zeroing bytes in the state buffer.
// This can be skipped for a newly-created hash state; the default zero-allocated state is correct.
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

// BlockSize, required by the hash.Hash interface, does not have a standard intepretation
// for a sponge-based construction like SHA3. We return the data rate: the number of bytes which
// can be absorbed per invocation of the permutation function. For Merkle-Damgård based hashes
// (ie SHA1, SHA2, MD5) the output size of the internal compression function is returned.
// We consider this to be roughly equivalent because it represents the number of bytes of output
// produced per cryptographic operation.
func (d *digest) BlockSize() int { return d.rate }

// Size returns the output size of the hash function in bytes.
func (d *digest) Size() int {
	return d.outputSize
}

// xorInBytes xors the input buffer into the state, performing a byte-swap if
// necessary
func (d *digest) xorFromBytebuf() {
	temp := make([]uint64, 21)
	buf := bytes.NewBuffer(d.bytebuf[:])
	binary.Read(buf, binary.LittleEndian, temp)
	for i, ai := range temp {
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

// Apply the permutation.
func (d *digest) permute() {
	keccakF(&d.a)
}

// Write "absorbs" bytes into the state of the SHA3 hash, updating as needed
// when the sponge "fills up" with rate bytes.
// TODO(dlg): how to handle writing into a closed-out sponge instance? (This isn't
// a problem if only the hash.Hash interface is used, but it would be nice to
// support hash-and-continue.)
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

// pad applies the SHA3 padding scheme based on the number of bytes absorbed.
func (d *digest) pad() {
	d.bytebuf[d.position] ^= d.dsbyte
	d.bytebuf[d.rate-1] ^= 0x80
}

// finalize prepares the hash to output data by applying the padding,
// xoring the last block into the state, applying the permutation, and
// copying the first buffer-length of output.
func (d *digest) finalize() {
	d.pad()
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

	if d.fixedOutput {
		if toSqueeze > d.outputSize {
			return nil, errSha3DigestTooLong
		}
		// Set to prevent another call.
		d.state = stateSqueezed
	}

	// Now, do the squeezing.
	out = make([]byte, toSqueeze)
	outOffset := 0
	for toSqueeze != 0 {
		canSqueeze := d.rate - d.position
		willSqueeze := minInt(toSqueeze, canSqueeze)

		// Copy the output from the sponge's buffer
		copy(out[outOffset:outOffset+willSqueeze], d.bytebuf[d.position:d.position+willSqueeze])

		d.position += willSqueeze
		outOffset += willSqueeze
		toSqueeze -= willSqueeze

		// Apply the permutation when we've used up "rate" bytes.
		if d.position == d.rate {
			d.permute()
			d.copyToBytebuf()
			d.position = 0
		}

	}
	return append(in, out...), nil // Re-slice in case we wrote extra data.
}

// Sum applies padding to the hash state and then squeezes out the desired number of output bytes.
func (d *digest) Sum(in []byte) []byte {
	// Make a copy of the original hash so that caller can keep writing and summing.
	dup := *d
	out, err := dup.Squeeze(in, dup.outputSize)
	if err != nil {
		panic("this should not be possible")
	}
	// TODO: how should errors be handled?
	return out
}

// The NewKeccakX constructors enable initializing a hash in any of the four recommend sizes
// from the Keccak specification, all of which set capacity=2*outputSize. Note that the final
// NIST standard for SHA3 may specify different input/output lengths.
// The output size is indicated in bits but converted into bytes internally.

// New224 creates a new SHA3-224 hash
func New224() *digest {
	d := &digest{
		outputSize:  224 / 8,
		fixedOutput: true,
		rate:        200 - (2 * 224 / 8),
		dsbyte:      0x06}
	return d
}

// New256 creates a new SHA3-224 hash
func New256() *digest {
	return &digest{
		outputSize:  256 / 8,
		fixedOutput: true,
		rate:        200 - (2 * 256 / 8),
		dsbyte:      0x06}
}

// New384 creates a new SHA3-384 hash
func New384() *digest {
	return &digest{
		outputSize:  384 / 8,
		fixedOutput: true,
		rate:        200 - (2 * 384 / 8),
		dsbyte:      0x06}
}

// New512 creates a new SHA3-512 hash
func New512() *digest {
	return &digest{
		outputSize:  512 / 8,
		fixedOutput: true,
		rate:        200 - (2 * 512 / 8),
		dsbyte:      0x06}
}

// NewShake128 creates a new SHAKE128 variable-output-length hash
func NewShake128() *digest {
	return &digest{
		fixedOutput: false,
		outputSize:  512,
		rate:        200 - (2 * 128 / 8),
		dsbyte:      0x1f}
}

// NewShake256 creates a new SHAKE128 variable-output-length hash
func NewShake256() *digest {
	return &digest{
		fixedOutput: false,
		outputSize:  512,
		rate:        200 - (2 * 256 / 8),
		dsbyte:      0x1f}
}
