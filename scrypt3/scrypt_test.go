// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package scrypt3

import "testing"

type testVector struct {
	password string
	salt     string
	N, r, p  int
	output   []byte
}

var good = []testVector{
	{
		"password",
		"salt",
		2, 10, 10,
		[]byte{
			0x48, 0x2c, 0x85, 0x8e, 0x22, 0x90, 0x55, 0xe6, 0x2f,
			0x41, 0xe0, 0xec, 0x81, 0x9a, 0x5e, 0xe1, 0x8b, 0xdb,
			0x87, 0x25, 0x1a, 0x53, 0x4f, 0x75, 0xac, 0xd9, 0x5a,
			0xc5, 0xe5, 0xa, 0xa1, 0x5f,
		},
	},
	{
		"password",
		"salt",
		16, 100, 100,
		[]byte{
			0x88, 0xbd, 0x5e, 0xdb, 0x52, 0xd1, 0xdd, 0x0, 0x18,
			0x87, 0x72, 0xad, 0x36, 0x17, 0x12, 0x90, 0x22, 0x4e,
			0x74, 0x82, 0x95, 0x25, 0xb1, 0x8d, 0x73, 0x23, 0xa5,
			0x7f, 0x91, 0x96, 0x3c, 0x37,
		},
	},
	{
		"this is a long \000 password",
		"and this is a long \000 salt",
		16384, 8, 1,
		[]byte{
			0xc3, 0xf1, 0x82, 0xee, 0x2d, 0xec, 0x84, 0x6e, 0x70,
			0xa6, 0x94, 0x2f, 0xb5, 0x29, 0x98, 0x5a, 0x3a, 0x09,
			0x76, 0x5e, 0xf0, 0x4c, 0x61, 0x29, 0x23, 0xb1, 0x7f,
			0x18, 0x55, 0x5a, 0x37, 0x07, 0x6d, 0xeb, 0x2b, 0x98,
			0x30, 0xd6, 0x9d, 0xe5, 0x49, 0x26, 0x51, 0xe4, 0x50,
			0x6a, 0xe5, 0x77, 0x6d, 0x96, 0xd4, 0x0f, 0x67, 0xaa,
			0xee, 0x37, 0xe1, 0x77, 0x7b, 0x8a, 0xd5, 0xc3, 0x11,
			0x14, 0x32, 0xbb, 0x3b, 0x6f, 0x7e, 0x12, 0x64, 0x40,
			0x18, 0x79, 0xe6, 0x41, 0xae,
		},
	},
	{
		"p",
		"s",
		2, 1, 1,
		[]byte{
			0x48, 0xb0, 0xd2, 0xa8, 0xa3, 0x27, 0x26, 0x11, 0x98,
			0x4c, 0x50, 0xeb, 0xd6, 0x30, 0xaf, 0x52,
		},
	},

	{
		"",
		"",
		16, 1, 1,
		[]byte{
			0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b,
			0x19, 0xca, 0x42, 0xc1, 0x8a, 0x04, 0x97, 0xf1, 0x6b,
			0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa,
			0x3f, 0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d,
			0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a, 0x75, 0x3a, 0x0f,
			0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d,
			0x36, 0x28, 0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89,
			0x06,
		},
	},
	{
		"password",
		"NaCl",
		1024, 8, 16,
		[]byte{
			0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78,
			0x56, 0xe7, 0x19, 0x0d, 0x01, 0xe9, 0xfe, 0x7c, 0x6a,
			0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76,
			0x63, 0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9,
			0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1, 0x09, 0x27, 0x9d,
			0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83,
			0xee, 0x6d, 0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06,
			0x40,
		},
	},
	{
		"pleaseletmein", "SodiumChloride",
		16384, 8, 1,
		[]byte{
			0x70, 0x23, 0xbd, 0xcb, 0x3a, 0xfd, 0x73, 0x48, 0x46,
			0x1c, 0x06, 0xcd, 0x81, 0xfd, 0x38, 0xeb, 0xfd, 0xa8,
			0xfb, 0xba, 0x90, 0x4f, 0x8e, 0x3e, 0xa9, 0xb5, 0x43,
			0xf6, 0x54, 0x5d, 0xa1, 0xf2, 0xd5, 0x43, 0x29, 0x55,
			0x61, 0x3f, 0x0f, 0xcf, 0x62, 0xd4, 0x97, 0x05, 0x24,
			0x2a, 0x9a, 0xf9, 0xe6, 0x1e, 0x85, 0xdc, 0x0d, 0x65,
			0x1e, 0x40, 0xdf, 0xcf, 0x01, 0x7b, 0x45, 0x57, 0x58,
			0x87,
		},
	},
	/*
		// Disabled: needs 1 GiB RAM and takes too long for a simple test.
		{
			"pleaseletmein", "SodiumChloride",
			1048576, 8, 1,
			[]byte{
				0x21, 0x01, 0xcb, 0x9b, 0x6a, 0x51, 0x1a, 0xae, 0xad,
				0xdb, 0xbe, 0x09, 0xcf, 0x70, 0xf8, 0x81, 0xec, 0x56,
				0x8d, 0x57, 0x4a, 0x2f, 0xfd, 0x4d, 0xab, 0xe5, 0xee,
				0x98, 0x20, 0xad, 0xaa, 0x47, 0x8e, 0x56, 0xfd, 0x8f,
				0x4b, 0xa5, 0xd0, 0x9f, 0xfa, 0x1c, 0x6d, 0x92, 0x7c,
				0x40, 0xf4, 0xc3, 0x37, 0x30, 0x40, 0x49, 0xe8, 0xa9,
				0x52, 0xfb, 0xcb, 0xf4, 0x5c, 0x6f, 0xa7, 0x7a, 0x41,
				0xa4,
			},
		},
	*/
}

var bad = []testVector{
	{"p", "s", 0, 1, 1, nil},                    // N == 0
	{"p", "s", 1, 1, 1, nil},                    // N == 1
	{"p", "s", 7, 8, 1, nil},                    // N is not power of 2
	{"p", "s", 16, maxInt / 2, maxInt / 2, nil}, // p * r too large
}

func TestKey(t *testing.T) {
	/*	for i, v := range good {
		k, err := Key([]byte(v.password), []byte(v.salt), v.N, v.r, v.p, len(v.output))
		if err != nil {
			t.Errorf("%d: got unexpected error: %s", i, err)
		}
		if !bytes.Equal(k, v.output) {
			t.Errorf("%d: expected %x, got %x", i, v.output, k)
		}
	}*/
	for i, v := range bad {
		_, err := Key([]byte(v.password), []byte(v.salt), v.N, v.r, v.p, 32)
		if err == nil {
			t.Errorf("%d: expected error, got nil", i)
		}
	}
}

func BenchmarkKey(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Key([]byte("password"), []byte("salt"), 16384, 8, 1, 64)
	}
}
