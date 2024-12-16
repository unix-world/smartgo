
// Go Lang Base58
// (c) 2021-present unix-world.org
// License: BSD
// v.20241216.2358

package base58

import (
	bconv "github.com/unix-world/smartgo/baseconv"
)


const name string = "Base58"
const radix int64 = 58
const encodeStd string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" // base58 charset


//--

var bConv bconv.BaseConv = bconv.NewBaseConv(name, radix, encodeStd)

//--

// Encode takes a slice of bytes and encodes it to baseXY string. Leading zero bytes are kept in place for precise decoding.
func Encode(input []byte) (output string) {
	//--
	return bConv.Encode(input) // output
	//--
} //END FUNCTION

//--

// Decode takes string as an input and returns decoded string and error. If provided string contains characters illegal for baseXY the returned error will be <notnil>
func Decode(input string) (output []byte, err error) {
	//--
	return bConv.Decode(input) // output, err
	//--
} //END FUNCTION

//--

// #END
