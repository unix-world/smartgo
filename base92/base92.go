package base92

// adapted by unixman from github.com/akamensky/base58
// v.20210813
// License: BSD

import (
	"fmt"
	"math/big"
	"strings"
)

const encodeStd = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#|;,_~`\"" // 0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#|;,_~`"

var (
	bigZero  = big.NewInt(0)
	bigRadix = big.NewInt(92)
	isTableInit = false
	encodeTable = [256]byte{}
	alphabet = []string{}
)

// initEncodingTable returns a new Encoding defined by the given alphabet,
// which must be a 92-byte string.
func initEncodingTable() {
	if(isTableInit == true) {
		return
	}
	alphabet = strings.Split(encodeStd, "")
	for i := 0; i < len(encodeTable); i++ {
		encodeTable[i] = 0xFF
	}
	for i := 0; i < len(encodeStd); i++ {
		encodeTable[encodeStd[i]] = byte(i)
	}
	isTableInit = true
}

// Encode takes a slice of bytes and encodes it to base92 string.
// Leading zero bytes are kept in place for precise decoding.
func Encode(input []byte) (output string) {

	initEncodingTable()

	num := new(big.Int).SetBytes(input)

	for num.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		num.DivMod(num, bigRadix, mod)
		output = alphabet[mod.Int64()] + output
	}

	for _, i := range input {
		if i != 0 {
			break
		}
		output = alphabet[0] + output
	}

	return
}

// Decode takes string as an input and returns decoded string and error
// If provided string contains characters illegal for base92 the returned error will be <notnil>
func Decode(input string) (output []byte, err error) {

	initEncodingTable()

	result := big.NewInt(0)
	multi := big.NewInt(1)

	tmpBig := new(big.Int)

	for i := len(input) - 1; i >= 0; i-- {
		tmp := encodeTable[input[i]]
		if tmp == 255 {
			err = fmt.Errorf("invalid Base92 input string at character \"%s\", position %d", string(input[i]), i)
			return
		}
		tmpBig.SetInt64(int64(tmp))
		tmpBig.Mul(multi, tmpBig)
		result.Add(result, tmpBig)
		multi.Mul(multi, bigRadix)
	}

	tmpBytes := result.Bytes()

	var numZeros int
	for numZeros = 0; numZeros < len(input); numZeros++ {
		if input[numZeros] != encodeStd[0] {
			break
		}
	}
	length := numZeros + len(tmpBytes)
	output = make([]byte, length)
	copy(output[numZeros:], tmpBytes)

	return
}

// #END
