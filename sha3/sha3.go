// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

import (
	"encoding/binary"
	"errors"
)

const (
	// MaxKeccakHashRate is the maximum rate supported for a ShakeHash.
	MaxKeccakHashRate = 176
)

// SpongeDirection indicates the direction bytes are flowing through the sponge.
type spongeDirection int

const (
	// spongeAbsorbing indicates the sponge is absorbing input
	spongeAbsorbing spongeDirection = iota
	// spongeSqueezing indicates the sponge is being squeezed
	spongeSqueezing
)

const (
	bufferLen  = 176 // the length of the input buffer; determines maximum rate
	spongeSize = 200 // the size of the permutation's state
)

type state struct {
	// Generic sponge components
	a            [25]uint64      // main state of the hash
	inputBuffer  [bufferLen]byte // the input buffer
	outputBuffer [bufferLen]byte // the output buffer
	position     int             // position in the input buffer
	rate         int             // the number of bytes of state to use

	// Specific to multi-bitrate padding
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
	d.state = spongeAbsorbing
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
func (d *state) xorBytesIn(buf []byte) int {
	dqwords := len(buf) / 8
	// Xor in the full ulint64s
	for i := 0; i < dqwords; i++ {
		a := binary.LittleEndian.Uint64(buf[i*8:])
		d.a[i] ^= a
	}
	if len(buf)%8 != 0 {
		// Xor in the last partial ulint64.
		last := make([]byte, 8)
		copy(last, buf[dqwords*8:])
		d.a[dqwords] ^= binary.LittleEndian.Uint64(last)
	}

	return ((len(buf) + 7) / 8) * 8
}

// copyBytesOut copies ulint64s to a byte buffer.
func (d *state) copyBytesOut(buf []byte) int {
	for i := 0; i < len(buf)/8; i++ {
		binary.LittleEndian.PutUint64(buf[i*8:(i+1)*8], d.a[i])
	}
	return (len(buf) / 8) * 8
}

// permute applies the KeccakF-1600 permutation. It handles
// any input-output buffering.
func (d *state) permute() {
	switch d.state {
	case spongeAbsorbing:
		d.xorBytesIn(d.inputBuffer[:])
		KeccakF1600(&d.a)
	case spongeSqueezing:
		KeccakF1600(&d.a)
		d.copyBytesOut(d.outputBuffer[:])
	}
	d.position = 0
}

// pads appends the domain separation bits in dsbyte, applies
// the multi-bitrate 10..1 padding rule, and permutes the state.
func (d *state) padAndPermute(dsbyte byte) {
	// Pad with this instance's domain-separator bits.
	d.inputBuffer[d.position] ^= dsbyte
	d.inputBuffer[d.rate-1] ^= 0x80
	// Apply the permutation
	d.permute()
	d.state = spongeSqueezing
	d.copyBytesOut(d.outputBuffer[:d.rate])
}

// Write absorbs more data into the hash's state.
func (d *state) Write(p []byte) (written int, err error) {
	// Check that the sponge is in the correct state.
	switch d.state {
	case spongeSqueezing:
		// QQQQ: Should this be an error? (This is how CSF and the Keccak
		// papers describe MAC-and-continue as working, but not standardized.)
		// If we're still squeezing, apply the permutation.
		d.permute()
		d.state = spongeAbsorbing
	}

	// The input buffer invariant:
	// (d.position == 0) ==> (d.inputBuffer[:] == 0)
	toWrite := len(p)
	written = 0
	for toWrite > 0 {
		canWrite := d.rate - d.position
		willWrite := minInt(toWrite, canWrite)

		if willWrite == d.rate {
			// The fast path; absorb a full rate of input and apply the permutation.
			// (willWrite == d.rate) <==> (d.position == 0) ==> (d.inputBufer[:] == 0)
			d.xorBytesIn(p[written : written+willWrite])
			KeccakF1600(&d.a)
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
	case spongeAbsorbing:
		// If we're still absorbing, pad and apply the permutation.
		d.padAndPermute(d.dsbyte)
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

// NewKeccakHash creates a new Keccak-based ShakeHash with
// 8 <= rate <= maxrate && (rate % 8) == 0. Note that the resulting
// function is *not* a SHAKE function, unless rate is 168 or 136,
// and dsbyte == 0x1f.
//
// Please understand the sponge construction before using this
// function. You almost certainly should be using something else.
//
// (The security strength, in bytes, is equal to (200 - rate) / 2.)
//
func NewKeccakHash(rate int, dsbyte byte) (ShakeHash, error) {
	switch {
	case rate > MaxKeccakHashRate || rate < 8:
		return nil, errors.New("Rate must be greater than or equal to 8 and less than MaxKeccakHashRate.")
	case (rate % 8) != 0:
		return nil, errors.New("Rate must be equal to 0 mod 8")
	}
	return &state{
		outputSize: int(rate - 1),
		rate:       int(rate),
		dsbyte:     dsbyte,
	}, nil
}
