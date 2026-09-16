
// Common options for SLH-DSA signatures.
package options

import (
	"crypto"
)


type Options struct {
	// Hash must currently be zero, for pure SLH-DSA.
	Hash crypto.Hash

	// Optional application-specific context string. At most 255 bytes.
	Context string
}

// Implements crypto.SignerOpts
func (o *Options) HashFunc() crypto.Hash {
	if o == nil {
		return 0
	}
	return o.Hash
}


// #end
