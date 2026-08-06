// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// unixman, r.20260216.2358
// removed conditional compiler flags

package sha3

// A storageBuf is an aligned array of maxRate bytes.
type storageBuf [maxRate]byte


func (b *storageBuf) asBytes() *[maxRate]byte {
	return (*[maxRate]byte)(b)
}


// #end
