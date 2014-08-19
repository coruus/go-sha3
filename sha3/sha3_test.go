// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha3

// These tests are a subset of those provided by the Keccak web site(http://keccak.noekeon.org/).

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"strings"
	"testing"
)

// testDigests maintains a digest state of each standard type.
var testDigests = map[string]func() *digest{
	"SHA3-224": New224,
	"SHA3-256": New256,
	"SHA3-384": New384,
	"SHA3-512": New512,
	"SHAKE128": NewShake128,
	"SHAKE256": NewShake256,
}

// testVector represents a test input and expected outputs from multiple algorithm variants.
type testVector struct {
	desc   string
	input  []byte
	repeat int // input will be concatenated the input this many times.
	want   map[string]string
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
	} /*`json:"SHA3-224"`
	SHA3_256 []struct {
		Digest  string  `json:"digest"`
		Length  float64 `json:"length"`
		Message string  `json:"message"`
	} `json:"SHA3-256"`
	SHA3_384 []struct {
		Digest  string  `json:"digest"`
		Length  float64 `json:"length"`
		Message string  `json:"message"`
	} `json:"SHA3-384"`
	SHA3_512 []struct {
		Digest  string  `json:"digest"`
		Length  float64 `json:"length"`
		Message string  `json:"message"`
	} `json:"SHA3-512"`
	SHAKE128 []struct {
		Digest  string  `json:"digest"`
		Length  float64 `json:"length"`
		Message string  `json:"message"`
	} `json:"SHAKE128"`
	SHAKE256 []struct {
		Digest  string  `json:"digest"`
		Length  float64 `json:"length"`
		Message string  `json:"message"`
	} `json:"SHAKE256"`*/
}

// shortTestVectors stores a series of short testVectors.
// Inputs of 8, 248, and 264 bits from http://keccak.noekeon.org/ are included below.
// The standard defines additional test inputs of all sizes between 0 and 2047 bits.
// Because the current implementation can only handle an integral number of bytes,
// most of the standard test inputs can't be used.
var shortKeccakTestVectors = []testVector{
	{
		desc:   "short-8b",
		input:  decodeHex("CC"),
		repeat: 1,
		want: map[string]string{
			"SHA3-224": "DF70ADC49B2E76EEE3A6931B93FA41841C3AF2CDF5B32A18B5478C39",
			"SHA3-256": "677035391CD3701293D385F037BA32796252BB7CE180B00B582DD9B20AAAD7F0",
			"SHA3-384": "5EE7F374973CD4BB3DC41E3081346798497FF6E36CB9352281DFE07D07FC530CA9AD8EF7AAD56EF5D41BE83D5E543807",
			"SHA3-512": "3939FCC8B57B63612542DA31A834E5DCC36E2EE0F652AC72E02624FA2E5ADEECC7DD6BB3580224B4D6138706FC6E80597B528051230B00621CC2B22999EAA205",
		},
	},
	/*{
		desc:   "short-248b",
		input:  decodeHex("84FB51B517DF6C5ACCB5D022F8F28DA09B10232D42320FFC32DBECC3835B29"),
		repeat: 1,
		want: map[string]string{
			"Sha3_224": "81AF3A7A5BD4C1F948D6AF4B96F93C3B0CF9C0E7A6DA6FCD71EEC7F6",
			"Sha3_256": "D477FB02CAAA95B3280EC8EE882C29D9E8A654B21EF178E0F97571BF9D4D3C1C",
			"Sha3_384": "503DCAA4ADDA5A9420B2E436DD62D9AB2E0254295C2982EF67FCE40F117A2400AB492F7BD5D133C6EC2232268BC27B42",
			"Sha3_512": "9D8098D8D6EDBBAA2BCFC6FB2F89C3EAC67FEC25CDFE75AA7BD570A648E8C8945FF2EC280F6DCF73386109155C5BBC444C707BB42EAB873F5F7476657B1BC1A8",
		},
	},
	{
		desc:   "short-264b",
		input:  decodeHex("DE8F1B3FAA4B7040ED4563C3B8E598253178E87E4D0DF75E4FF2F2DEDD5A0BE046"),
		repeat: 1,
		want: map[string]string{
			"Sha3_224": "F217812E362EC64D4DC5EACFABC165184BFA456E5C32C2C7900253D0",
			"Sha3_256": "E78C421E6213AFF8DE1F025759A4F2C943DB62BBDE359C8737E19B3776ED2DD2",
			"Sha3_384": "CF38764973F1EC1C34B5433AE75A3AAD1AAEF6AB197850C56C8617BCD6A882F6666883AC17B2DCCDBAA647075D0972B5",
			"Sha3_512": "9A7688E31AAF40C15575FC58C6B39267AAD3722E696E518A9945CF7F7C0FEA84CB3CB2E9F0384A6B5DC671ADE7FB4D2B27011173F3EEEAF17CB451CF26542031",
		},
	},*/
}

func TestKeccakKats(t *testing.T) {
	file, err := os.Open("keccakKats.json")
	if err != nil {
		t.Errorf("%s", err)
	}
	dec := json.NewDecoder(file)
	var katSet KeccakKats
	err = dec.Decode(&katSet)
	if err != nil {
		t.Errorf("%s", err)
	}
	for functionName, kats := range katSet.Kats {
		d := testDigests[functionName]()
		for _, kat := range kats {
			d.Reset()
			//t.Errorf("%s %s", i, kat)
			in, err := hex.DecodeString(kat.Message)
			if err != nil {
				t.Errorf("%s", err)
			}
			d.Write(in[:kat.Length/8])
			got := strings.ToUpper(hex.EncodeToString(d.Sum(nil)))
			want := kat.Digest
			if got != want {
				t.Errorf("function=%s, length=%d\nmessage:\n  %s\ngot:\n  %s\nwanted:\n  %s", functionName, kat.Length, kat.Message, got, want)
			} else {
				t.Logf("function=%s, length=%u: OKAY\n", functionName, kat.Length)
			}
		}
	}
}

// dumpState is a debugging function to pretty-print the internal state of the hash.
func (d *digest) dumpState() {
	fmt.Printf("SHA3 hash, %d B output, %db security strength (%d B rate)\n", d.outputSize, d.SecurityStrength(), d.rate)
	fmt.Printf("Internal state after absorbing %d B:\n", d.position)

	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			fmt.Printf("%v, ", d.a[x*5+y])
		}
		fmt.Println("")
	}
}

// TestUnalignedWrite tests that writing data in an arbitrary pattern with small input buffers.
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

// sequentialBytes produces a buffer of size consecutive bytes 0x00, 0x01, ..., used for testing.
func sequentialBytes(size int) []byte {
	result := make([]byte, size)
	for i := range result {
		result[i] = byte(i)
	}
	return result
}

// benchmarkBlockWrite tests the speed of writing data and never calling the permutation function.
func benchmarkBlockWrite(b *testing.B, d *digest) {
	b.StopTimer()
	d.Reset()
	// Write all but the last byte of a block, to ensure that the permutation is not called.
	data := sequentialBytes(d.rate - 1)
	b.SetBytes(int64(len(data)))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		d.position = 0 // Reset absorbed to avoid ever calling the permutation function
		d.Write(data)
		d.xorFromBytebuf()
	}
	b.StopTimer()
	d.Reset()
}

// BenchmarkPermutationFunction measures the speed of the permutation function with no input data.
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
	d := testDigests["SHA3-512"]()
	d.Reset()
	data := sequentialBytes(1) //1 byte buffer
	b.SetBytes(int64(d.rate) - 1)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		d.position = 0 // Reset absorbed to avoid ever calling the permutation function

		// Write all but the last byte of a block, one byte at a time.
		for j := 0; j < d.rate-1; j++ {
			d.Write(data)
		}
	}
	b.StopTimer()
	d.Reset()
}

// BenchmarkSingleByteX measures the block write speed for each size of the digest.
func BenchmarkBlockWrite512(b *testing.B) { benchmarkBlockWrite(b, testDigests["SHA3-512"]()) }
func BenchmarkBlockWrite384(b *testing.B) { benchmarkBlockWrite(b, testDigests["SHA3-384"]()) }
func BenchmarkBlockWrite256(b *testing.B) { benchmarkBlockWrite(b, testDigests["SHA3-256"]()) }
func BenchmarkBlockWrite224(b *testing.B) { benchmarkBlockWrite(b, testDigests["SHA3-224"]()) }

// benchmarkBulkHash tests the speed to hash a 16 KiB buffer.
func benchmarkBulkHash(b *testing.B, h hash.Hash) {
	b.StopTimer()
	h.Reset()
	size := 1 << 14
	data := sequentialBytes(size)
	b.SetBytes(int64(size))
	b.StartTimer()

	var digest []byte
	for i := 0; i < b.N; i++ {
		h.Write(data)
		digest = h.Sum(digest[:0])
	}
	b.StopTimer()
	h.Reset()
}

// benchmarkBulkKeccakX test the speed to hash a 16 KiB buffer by calling benchmarkBulkHash.
func BenchmarkBulkSha3_512(b *testing.B) { benchmarkBulkHash(b, New512()) }
func BenchmarkBulkSha3_384(b *testing.B) { benchmarkBulkHash(b, New384()) }
func BenchmarkBulkSha3_256(b *testing.B) { benchmarkBulkHash(b, New256()) }
func BenchmarkBulkSha3_224(b *testing.B) { benchmarkBulkHash(b, New224()) }
func BenchmarkBulkShake256(b *testing.B) { benchmarkBulkHash(b, NewShake256()) }
func BenchmarkBulkShake128(b *testing.B) { benchmarkBulkHash(b, NewShake128()) }


var bench = New256()
var buf = make([]byte, 8192)

func benchmarkSize(b *testing.B, size int) {
	b.SetBytes(int64(size))
	sum := make([]byte, bench.Size())
	for i := 0; i < b.N; i++ {
		bench.Reset()
		bench.Write(buf[:size])
		bench.Sum(sum[:0])
	}
}

func BenchmarkHash8Bytes(b *testing.B) {
	benchmarkSize(b, 8)
}

func BenchmarkHash1K(b *testing.B) {
	benchmarkSize(b, 1024)
}

func BenchmarkHash8K(b *testing.B) {
	benchmarkSize(b, 8192)
}
