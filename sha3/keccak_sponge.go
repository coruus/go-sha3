// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha3 implements the SHA-3 fixed-output-length hash functions and
// the SHAKE variable-output-length has function defined by FIPS-202.
//
// Both functions use a sponge construction and the KeccakF-1600 permutation.
//
// For a detailed specification of the functions, see http://keccak.noekeon.org/
package sha3

import (
	"encoding/binary"
	"errors"
)

// SpongeDirection indicates the direction bytes are flowing through the sponge.
type SpongeDirection int

const (
	// SpongeAbsorbing indicates the sponge is absorbing input
	SpongeAbsorbing SpongeDirection = 0
	// SpongeSqueezing indicates the sponge is being squeezed
	SpongeSqueezing = 1
)

const (
	bufferLen        = 176 // the length of the input buffer; determines maximum rate
	keccakSpongeSize = 200
)

var (
	errSha3CanOnlySqueezeOnce = errors.New(
		"fixed-output-length functions can only be squeezed once")
	errSha3DigestTooLong = errors.New(
		"too much output requested from a fixed-output-length hash")
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
	state       SpongeDirection // current direction of the sponge
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
func (d *state) SpongeSize() int { return keccakSpongeSize }

// SecurityStrength returns the generic security strength (in bits) of this
// sponge instance.
func (d *state) SecurityStrength() int { return 8 * (d.SpongeSize() - (d.Rate() / 2)) }

// State returns whether the sponge is absorbing or squeezing.
func (d *state) State() SpongeDirection { return d.state }

// Rate returns the byterate of the sponge
func (d *state) Rate() int { return d.rate }

// BlockSize returns the rate of sponge underlying this hash function.
func (d *state) BlockSize() int { return d.Rate() }

// Size returns the output size of the hash function in bytes.
func (d *state) Size() int { return d.outputSize }

// Reset clears the internal state by zeroing the sponge state and
// the byte buffer, and setting Sponge.state to absorbing.
func (d *state) Reset() {
	// Reset the position.
	d.position = 0  // reset position
	d.zeroBuffers() // zero buffers
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
		// Xor in the last partial ulint64
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

// Permute applies the KeccakF-1600 permutation.
func (d *state) Permute() {
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

// Pads appends the domain separation bits in dsbyte, applies
// the multi-bitrate 10..1 padding rule, and permutes the state.
func (d *state) Pad(dsbyte byte) {
	// Pad with this instance's domain-separator bits.
	d.inputBuffer[d.position] ^= dsbyte
	d.inputBuffer[d.rate-1] ^= 0x80
	// Apply the permutation
	d.Permute()
	d.state = SpongeSqueezing
	copyBytesInto(d.outputBuffer[:d.rate], d.a[:22])
}

// Absorb xors input bytes into the sponge state, applying
// the permutation as necessary.
//
// The input buffer invariant:
//     (d.position == 0) ==> (d.inputBuffer[:] == 0)
func (d *state) Absorb(p []byte) (written int) {
	toWrite := len(p)
	written = 0
	for toWrite > 0 {
		canWrite := d.rate - d.position
		willWrite := minInt(toWrite, canWrite)

		if willWrite == d.rate {
			// The fast path; absorb a full rate of input and apply the
			// permutation.
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
				d.Permute()
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
	return int(written)
}

// Write absorbs bytes into the state of the SHA3 hash, applying
// the permutation as needed when the sponge fills up with rate bytes.
func (d *state) Write(p []byte) (written int, err error) {
	n := d.Absorb(p)
	return n, nil
}

// Squeeze squeezes an arbitrary number of bytes from the sponge.
func (d *state) Squeeze(in []byte, toSqueeze int) (out []byte) {
	// Check that the sponge is in the correct state.
	switch d.state {
	case SpongeAbsorbing:
		// If we're still absorbing, pad and apply the permutation.
		d.Pad(d.dsbyte)
	}

	// If this is a fixed-output length instance, we only allow
	// squeezing up to OutputSize() bytes; calls after outputSize
	// bytes have been squeezed will result in no output.
	if d.fixedOutput && toSqueeze > (d.outputSize-d.position) {
		toSqueeze = (d.outputSize - d.position)
	}

	// Now, do the squeezing.
	out = make([]byte, toSqueeze)
	outOffset := 0
	for toSqueeze != 0 {
		canSqueeze := d.rate - d.position
		willSqueeze := minInt(toSqueeze, canSqueeze)

		// Copy the output from the sponge's buffer.
		copy(out[outOffset:outOffset+willSqueeze],
			d.outputBuffer[d.position:d.position+willSqueeze])

		d.position += willSqueeze
		outOffset += willSqueeze
		toSqueeze -= willSqueeze

		// Apply the permutation if we've squeezed the sponge dry.
		if d.position == d.rate {
			d.Permute()
		}
	}
	return append(in, out...)
}

// Sum applies padding to the hash state and then squeezes out the desired
// number of output bytes.
func (d *state) Sum(in []byte) []byte {
	// Make a copy of the original hash so that caller can keep writing
	// and summing.
	dup := *d
	return dup.Squeeze(in, dup.outputSize)
}

// NewSponge creates a new Keccak-based sponge instance of any
// desired rate > 0 and < bytebufLen. Note that the resulting
// function is *not* a SHAKE function, unless rate is 168 or 136,
// and dsbyte == 0x1f
//
// By default the output size is equal to the rate minus - 1. Any
// amount of output can be requested.
func NewSponge(rate int, dsbyte byte) Sponge {
	if rate > bufferLen || rate <= 0 {
		return nil
	}
	return &state{
		fixedOutput: false,
		outputSize:  int(rate - 8),
		rate:        int(rate),
		dsbyte:      dsbyte}
}
