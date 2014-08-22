// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package sha3

import (
	"io"
)

// VariableHash defines the interface to hash functions that
// support arbitrary-length output.
type VariableHash interface {
	// Write absorbs more data into the hash's state.
	// It never returns an error.
	io.Writer
	// Read reads more output from the hash. It affects the hash's
	// state.
	// It never returns an error.
	io.Reader

	// Reset resets the Hash to its initial state.
	Reset()
}
