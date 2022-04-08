
// Go Lang Base Conv
// (c) 2021-2022 unix-world.org # inspired from github.com/akamensky/base58 # adapted to support any base
// v.20220408.1556
// License: BSD

package baseconv

import (
	"log"
	"fmt"
	"strings"
	"math/big"
)

//--

type BaseConv struct {
	name 		string
	radix 		int64
	encodeStd 	string
	bigZero  	*big.Int
	bigRadix 	*big.Int
	encodeTable [256]byte
	alphabet 	[]string
}

//--

func NewBaseConv(name string, radix int64, encodeStd string) *BaseConv {
	//--
	if(int64(len(encodeStd)) != radix) {
		log.Println("[ERROR] Invalid BaseConvert[" + name + "] radix:", radix, "for encodeStd: " + encodeStd)
	} //end if
	//--
	bc := &BaseConv{
		name: 			name,
		radix: 			radix,
		encodeStd: 		encodeStd,
		bigZero: 		big.NewInt(0),
		bigRadix: 		big.NewInt(radix),
		encodeTable: 	[256]byte{},
		alphabet: 		[]string{},
	}
	//--
	bc.alphabet = strings.Split(bc.encodeStd, "")
	for i := 0; i < len(bc.encodeTable); i++ {
		bc.encodeTable[i] = 0xFF
	} //end for
	//--
	for i := 0; i < len(bc.encodeStd); i++ {
		bc.encodeTable[bc.encodeStd[i]] = byte(i)
	} //end for
	//--
	return bc
	//--
} //END FUNCTION

//--

func (bc *BaseConv) Encode(input []byte) (output string) { // takes a slice of bytes and encodes it to baseXY where XY is Radix string. Leading zero bytes are kept in place for precise decoding
	//--
	num := new(big.Int).SetBytes(input)
	for num.Cmp(bc.bigZero) > 0 {
		mod := new(big.Int)
		num.DivMod(num, bc.bigRadix, mod)
		output = bc.alphabet[mod.Int64()] + output
	} //end for
	//--
	for _, i := range input {
		if(i != 0) {
			break
		} //end if
		output = bc.alphabet[0] + output
	} //end for
	//--
	return // output
	//--
} //END FUNCTION

//--

func (bc *BaseConv) Decode(input string) (output []byte, err error) {
	//--
	result := big.NewInt(0)
	multi := big.NewInt(1)
	//--
	tmpBig := new(big.Int)
	for i := len(input) - 1; i >= 0; i-- {
		tmp := bc.encodeTable[input[i]]
		if(tmp == 255) {
			err = fmt.Errorf("Invalid " + bc.name + " input string at character \"%s\", position %d", string(input[i]), i)
			return
		} //end if
		tmpBig.SetInt64(int64(tmp))
		tmpBig.Mul(multi, tmpBig)
		result.Add(result, tmpBig)
		multi.Mul(multi, bc.bigRadix)
	} //end for
	//--
	tmpBytes := result.Bytes()
	var numZeros int
	for numZeros = 0; numZeros < len(input); numZeros++ {
		if(input[numZeros] != bc.encodeStd[0]) {
			break
		} //end if
	} //end for
	//--
	length := numZeros + len(tmpBytes)
	output = make([]byte, length)
	copy(output[numZeros:], tmpBytes)
	//--
	return // output, err
	//--
} //END FUNCTION

//--

// #END
