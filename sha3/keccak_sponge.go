// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha3 implements the SHA-3 fixed-output-length hash functions and
// the SHAKE variable-output-length has function defined by FIPS-202.
//
// Both types of hash function use the sponge construction and
// KeccakF-1600 permutation.
//
// For a detailed specification, see http://keccak.noekeon.org/
package sha3

import (
	"encoding/binary"
)

// SpongeDirection indicates the direction bytes are flowing through the sponge.
type spongeDirection int

const (
	// SpongeAbsorbing indicates the sponge is absorbing input
	SpongeAbsorbing spongeDirection = 0
	// SpongeSqueezing indicates the sponge is being squeezed
	SpongeSqueezing = 1
)

const (
	bufferLen        = 176 // the length of the input buffer; determines maximum rate
	keccakSpongeSize = 200
)

type state struct {
	// Generic sponge components
	a            [25]uint64      // main state of the hash
	inputBuffer  [bufferLen]byte // the input buffer
	outputBuffer [bufferLen]byte // the output buffer
	position     int             // position in the input buffer
	rate         int             // the number of bytes of state to use

	// Specific to multi-bitrate padding.
	dsbyte byte // the domain separator byte

	// Specific to SHA-3 and SHAKE
	fixedOutput bool            // whether this is a fixed-ouput-length instance
	outputSize  int             // the default output size in bytes
	state       spongeDirection // current direction of the sponge
}

// minInt returns the lesser of two integer arguments.
func minInt(v1, v2 int) int {
	if v1 <= v2 {
		return v1
	}
	return v2
}

// BlockSize returns the rate of sponge underlying this hash function.
func (d *state) BlockSize() int { return d.rate }

// Size returns the output size of the hash function in bytes.
func (d *state) Size() int { return d.outputSize }

// Reset clears the internal state by zeroing the sponge state and
// the byte buffer, and setting Sponge.state to absorbing.
func (d *state) Reset() {
	d.position = 0  // Reset position.
	d.zeroBuffers() // Zero buffers.
	// Zero the permutation's state.
	for i := range d.a {
		d.a[i] = 0
	}
	d.state = SpongeAbsorbing
}

func (d *state) zeroBuffers() {
	d.position = 0
	for i := range d.inputBuffer {
		d.inputBuffer[i] = 0
	}
	for i := range d.outputBuffer {
		d.outputBuffer[i] = 0
	}
}

// xorBytesInto xors a buffer into the state, byte-swapping to
// little-endian as necessary; it returns the number of bytes
// copied, including any zeros appended to the bytestring.
//
// Precondition: ((len(buf) + 7) / 8) <= len(a)
func xorBytesFrom(dqw []uint64, buf []byte) int {
	dqwords := len(buf) / 8
	// Xor in the full ulint64s
	for i := 0; i < dqwords; i++ {
		a := binary.LittleEndian.Uint64(buf[i*8:])
		dqw[i] ^= a
	}
	if len(buf)%8 != 0 {
		// Xor in the last partial ulint64.
		last := make([]byte, 8)
		copy(last, buf[dqwords*8:])
		dqw[dqwords] ^= binary.LittleEndian.Uint64(last)
	}

	return ((len(buf) + 7) / 8) * 8
}

// copyToBytebuf copies ulint64s to a byte buffer.
// only copies floor(len(buf) / 8) * 8) bytes
func copyBytesInto(buf []byte, dqw []uint64) int {
	for i := 0; i < len(buf)/8; i++ {
		binary.LittleEndian.PutUint64(buf[i*8:(i+1)*8], dqw[i])
	}
	return (len(buf) / 8) * 8
}

// permute applies the KeccakF-1600 permutation. It handles
// any input-output buffering.
func (d *state) permute() {
	switch d.state {
	case SpongeAbsorbing:
		xorBytesFrom(d.a[:22], d.inputBuffer[:])
		keccakF(&d.a)
	case SpongeSqueezing:
		keccakF(&d.a)
		copyBytesInto(d.outputBuffer[:], d.a[:22])
	}
	d.position = 0
}

// pads appends the domain separation bits in dsbyte, applies
// the multi-bitrate 10..1 padding rule, and permutes the state.
func (d *state) pad(dsbyte byte) {
	// Pad with this instance's domain-separator bits.
	d.inputBuffer[d.position] ^= dsbyte
	d.inputBuffer[d.rate-1] ^= 0x80
	// Apply the permutation
	d.permute()
	d.state = SpongeSqueezing
	copyBytesInto(d.outputBuffer[:d.rate], d.a[:22])
}

// Write absorbs more data into the hash's state.
func (d *state) Write(p []byte) (written int, err error) {
	// The input buffer invariant:
	//     (d.position == 0) ==> (d.inputBuffer[:] == 0)
	toWrite := len(p)
	written = 0
	for toWrite > 0 {
		canWrite := d.rate - d.position
		willWrite := minInt(toWrite, canWrite)

		if willWrite == d.rate {
			// The fast path; absorb a full rate of input and apply the permutation.
			// (willWrite == d.rate) ==> (d.position == 0) ==> d.inputBufer[:] == 0
			xorBytesFrom(d.a[:21], p[written:written+willWrite])
			keccakF(&d.a)
		} else {
			// The slow path; buffer the input until we can fill the sponge,
			// and then xor it in.
			copy(d.inputBuffer[d.position:], p[written:written+willWrite])
			d.position += willWrite
			// (0 < d.rate == d.position)
			if d.position == d.rate {
				d.permute()
				// Zero the input buffer.
				for i := range d.inputBuffer {
					d.inputBuffer[i] = 0
				}
				d.position = 0
			}
		}
		toWrite -= willWrite
		written += willWrite
	}
	return int(written), nil
}

// Read squeezes an arbitrary number of bytes from the sponge.
func (d *state) Read(out []byte) (n int, err error) {
	// Check that the sponge is in the correct state.
	switch d.state {
	case SpongeAbsorbing:
		// If we're still absorbing, pad and apply the permutation.
		d.pad(d.dsbyte)
	}

	// Now, do the squeezing.
	offset := 0
	length := len(out)
	for length != 0 {
		canSqueeze := d.rate - d.position
		willSqueeze := minInt(length, canSqueeze)

		// Copy the output from the sponge's buffer.
		copy(out[offset:offset+willSqueeze],
			d.outputBuffer[d.position:d.position+willSqueeze])

		d.position += willSqueeze
		offset += willSqueeze
		length -= willSqueeze

		// Apply the permutation if we've squeezed the sponge dry.
		if d.position == d.rate {
			d.permute()
		}
	}
	return len(out), err
}

// Sum applies padding to the hash state and then squeezes out the desired
// number of output bytes.
func (d *state) Sum(in []byte) []byte {
	// Make a copy of the original hash so that caller can keep writing
	// and summing.
	dup := *d
	hash := make([]byte, dup.outputSize)
	dup.Read(hash)
	return append(in, hash...)
}

// NewKeccakHash creates a new Keccak-based VariableHash of any
// desired rate > 0 and < bytebufLen. Note that the resulting
// function is *not* a SHAKE function, unless rate is 168 or 136,
// and dsbyte == 0x1f
//
// By default the output size is equal to the rate minus - 1. Any
// amount of output can be requested.
func NewKeccakHash(rate int, dsbyte byte) VariableHash {
	if rate > bufferLen || rate <= 0 {
		return nil
	}
	return &state{
		outputSize: int(rate - 1),
		rate:       int(rate),
		dsbyte:     dsbyte,
	}
}
