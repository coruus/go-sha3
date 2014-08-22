// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// TODO(update comment): These tests are a subset of those provided by the Keccak web site
// (http://keccak.noekeon.org/).

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"strings"
	"testing"
)

const (
	testString  = "brekeccakkeccak koax koax"
	katFilename = "keccakKats.json.deflate"
)

// Internal-use instances of SHAKE used to test against KATs.
func newHashShake128() hash.Hash {
	return &state{rate: 168, dsbyte: 0x1f, outputSize: 512}
}
func newHashShake256() hash.Hash {
	return &state{rate: 136, dsbyte: 0x1f, outputSize: 512}
}

// testDigests contains a function returning a hash.Hash instance
// with output-length equal to the KAT length for both SHA-3 and
// SHAKE instances.
var testDigests = map[string]func() hash.Hash{
	"SHA3-224": New224,
	"SHA3-256": New256,
	"SHA3-384": New384,
	"SHA3-512": New512,
	"SHAKE128": newHashShake128,
	"SHAKE256": newHashShake256,
}

var testShakes = map[string]func() VariableHash{
	"SHAKE128": NewShake128,
	"SHAKE256": NewShake256,
}

// decodeHex converts an hex-encoded string into a raw byte string.
func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// structs used to marshal JSON test-cases
type KeccakKats struct {
	Kats map[string][]struct {
		Digest  string `json:"digest"`
		Length  int64  `json:"length"`
		Message string `json:"message"`
	}
}

// TestKeccakKats tests the SHA-3 and Shake implementations against all the
// ShortMsgKATs from https://github.com/gvanas/KeccakCodePackage
// (The testvectors are stored in keccakKats.json due to their length.)
func TestKeccakKats(t *testing.T) {
	deflated, err := os.Open(katFilename)
	if err != nil {
		t.Errorf("Error opening %s: %s", katFilename, err)
	}
	file := flate.NewReader(deflated)
	dec := json.NewDecoder(file)
	var katSet KeccakKats
	err = dec.Decode(&katSet)
	if err != nil {
		t.Errorf("%s", err)
	}
	for functionName, kats := range katSet.Kats {
		d := testDigests[functionName]()
		t.Logf("%s", functionName)
		for _, kat := range kats {
			d.Reset()
			in, err := hex.DecodeString(kat.Message)
			if err != nil {
				t.Errorf("%s", err)
			}
			d.Write(in[:kat.Length/8])
			got := strings.ToUpper(hex.EncodeToString(d.Sum(nil)))
			want := kat.Digest
			if got != want {
				t.Errorf("function=%s, length=%d\nmessage:\n  %s\ngot:\n  %s\nwanted:\n %s",
					functionName, kat.Length, kat.Message, got, want)
				t.Logf("wanted %r", kat)
				t.FailNow()
			}
		}
	}
}

// dumpState is a debugging function to pretty-print the internal state of the hash.
func (d *state) dumpState() {
	fmt.Printf("SHA3 hash, %d B output, %d B rate\n",
		d.outputSize, d.rate)
	fmt.Printf("Internal state after absorbing %d B:\n", d.position)

	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			fmt.Printf("%v, ", d.a[x*5+y])
		}
		fmt.Println("")
	}
}

// TestUnalignedWrite tests that writing data in an arbitrary pattern with
// small input buffers.
func TestUnalignedWrite(t *testing.T) {
	buf := sequentialBytes(0x10000)
	for alg, df := range testDigests {
		d := df()
		d.Reset()
		d.Write(buf)
		want := d.Sum(nil)
		d.Reset()
		for i := 0; i < len(buf); {
			// Cycle through offsets which make a 137 byte sequence.
			// Because 137 is prime this sequence should exercise all corner cases.
			offsets := [17]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1}
			for _, j := range offsets {
				j = minInt(j, len(buf)-i)
				d.Write(buf[i : i+j])
				i += j
			}
		}
		got := d.Sum(nil)
		if !bytes.Equal(got, want) {
			t.Errorf("Unaligned writes, alg=%s\ngot %q, want %q", alg, got, want)
		}
	}
}

func TestAppend(t *testing.T) {
	d := New224()

	for capacity := 2; capacity < 64; capacity += 64 {
		// The first time around the loop, Sum will have to reallocate.
		// The second time, it will not.
		buf := make([]byte, 2, capacity)
		d.Reset()
		d.Write([]byte{0xcc})
		buf = d.Sum(buf)
		expected := "0000DF70ADC49B2E76EEE3A6931B93FA41841C3AF2CDF5B32A18B5478C39"
		if got := strings.ToUpper(hex.EncodeToString(buf)); got != expected {
			t.Errorf("got %s, want %s", got, expected)
		}
	}
}

func TestAppendNoRealloc(t *testing.T) {
	buf := make([]byte, 1, 200)
	d := New224()
	d.Write([]byte{0xcc})
	buf = d.Sum(buf)
	expected := "00DF70ADC49B2E76EEE3A6931B93FA41841C3AF2CDF5B32A18B5478C39"
	if got := strings.ToUpper(hex.EncodeToString(buf)); got != expected {
		t.Errorf("got %s, want %s", got, expected)
	}
}

// TestSqueezing checks that squeezing the full output a single time produces
// the same output as repeatedly squeezing the instance.
/*
func TestSqueezing(t *testing.T) {
	for functionName, newHash := range testShakes {
		t.Logf("%s", functionName)
		d0 := newHash().(*state)
		d0.Write([]byte(testString))
		ref := d0.Sum(nil)

		d1 := newHash().(*state)
		d1.Write([]byte(testString))
		multiple := d1.Squeeze(nil, 0)
		for _ = range ref {
			multiple = d1.Squeeze(multiple, 1)
		}
		if !bytes.Equal(ref, multiple) {
			t.Errorf("squeezing %d bytes one at a time failed", len(ref))
		}
	}
}*/

// sequentialBytes produces a buffer of size consecutive bytes 0x00, 0x01, ..., used for testing.
func sequentialBytes(size int) []byte {
	result := make([]byte, size)
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

// benchmarkBlockWrite tests the speed of writing data and never calling the permutation function.
func benchmarkBlockWrite(b *testing.B, h hash.Hash) {
	d := h.(*state)
	b.StopTimer()
	d.Reset()
	// Write all but the last byte of a block, to ensure that the permutation is not called.
	data := sequentialBytes(d.rate - 1)
	b.SetBytes(int64(len(data)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		d.position = 0 // Reset absorbed to avoid ever calling the permutation function
		d.Write(data)
		xorBytesFrom(d.a[:], d.inputBuffer[:])
	}
	b.StopTimer()
	d.Reset()
}

// BenchmarkPermutationFunction measures the speed of the permutation function
// with no input data.
func BenchmarkPermutationFunction(b *testing.B) {
	b.SetBytes(int64(200))
	var lanes [25]uint64
	for i := 0; i < b.N; i++ {
		keccakF(&lanes)
	}
}

// BenchmarkSingleByteWrite tests the latency from writing a single byte
func BenchmarkSingleByteWrite(b *testing.B) {
	b.StopTimer()
	d := NewShake256().(*state)
	d.Reset()
	data := sequentialBytes(1) //1 byte buffer
	b.SetBytes(int64(d.rate) - 1)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		d.position = 0 // Reset position to avoid ever calling the permutation function

		// Write all but the last byte of a block, one byte at a time.
		for j := 0; j < d.rate-1; j++ {
			d.Write(data)
		}
	}
	b.StopTimer()
	d.Reset()
}

// BenchmarkSingleByteX measures the block write speed for each size of the state.
func BenchmarkBlockWrite512(b *testing.B)      { benchmarkBlockWrite(b, New512()) }
func BenchmarkBlockWrite384(b *testing.B)      { benchmarkBlockWrite(b, New384()) }
func BenchmarkBlockWrite256(b *testing.B)      { benchmarkBlockWrite(b, New256()) }
func BenchmarkBlockWrite224(b *testing.B)      { benchmarkBlockWrite(b, New224()) }
func BenchmarkBlockWriteShake256(b *testing.B) { benchmarkBlockWrite(b, newHashShake256()) }
func BenchmarkBlockWriteShake128(b *testing.B) { benchmarkBlockWrite(b, newHashShake128()) }

// benchmarkBulkHash tests the speed to hash a 16 KiB buffer.
func benchmarkBulkHash(b *testing.B, h hash.Hash) {
	b.StopTimer()
	h.Reset()
	size := 1 << 14
	data := sequentialBytes(size)
	b.SetBytes(int64(size))
	b.StartTimer()

	var state []byte
	for i := 0; i < b.N; i++ {
		h.Write(data)
		state = h.Sum(state[:0])
	}
	b.StopTimer()
	h.Reset()
}

// benchmarkBulkKeccakX test the speed to hash a 16 KiB buffer by calling benchmarkBulkHash.
func BenchmarkBulkSha3_512(b *testing.B) { benchmarkBulkHash(b, New512()) }
func BenchmarkBulkSha3_384(b *testing.B) { benchmarkBulkHash(b, New384()) }
func BenchmarkBulkSha3_256(b *testing.B) { benchmarkBulkHash(b, New256()) }
func BenchmarkBulkSha3_224(b *testing.B) { benchmarkBulkHash(b, New224()) }
func BenchmarkBulkShake256(b *testing.B) { benchmarkBlockWrite(b, newHashShake256()) }
func BenchmarkBulkShake128(b *testing.B) { benchmarkBlockWrite(b, newHashShake128()) }

func benchmarkSize(b *testing.B, size int) {
	var bench = New256()
	var buf = make([]byte, 8192)

	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(sum[:0])
	}
}

func BenchmarkHash8B(b *testing.B)   { benchmarkSize(b, 8) }
func BenchmarkHash1KiB(b *testing.B) { benchmarkSize(b, 1024) }
func BenchmarkHash8KiB(b *testing.B) { benchmarkSize(b, 8192) }
