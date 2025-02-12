// Copyright 2016 The Snappy-Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//package snapref
// # unixman : golang/snappy and github.com/klauspost/compress/internal/snapref were unified, but the later one had an extra method EncodeBlockInto() exported here

package snappy

// EncodeBlockInto exposes encodeBlock but checks dst size.
func EncodeBlockInto(dst, src []byte) (d int) {
	if MaxEncodedLen(len(src)) > len(dst) {
		return 0
	}

	// encodeBlock breaks on too big blocks, so split.
	for len(src) > 0 {
		p := src
		src = nil
		if len(p) > maxBlockSize {
			p, src = p[:maxBlockSize], p[maxBlockSize:]
		}
		if len(p) < minNonLiteralBlockSize {
			d += emitLiteral(dst[d:], p)
		} else {
			d += encodeBlock(dst[d:], p)
		}
	}
	return d
}

