
// based on: github.com/juliankoehn/barcode
// v.20260203.2358
// (c) unix-world.org

package barcodes

import (
	"fmt"
	"math"
	"strconv"
)


var codes = map[string]map[string]string{
	"A": { // left odd parity
		"0": "0001101",
		"1": "0011001",
		"2": "0010011",
		"3": "0111101",
		"4": "0100011",
		"5": "0110001",
		"6": "0101111",
		"7": "0111011",
		"8": "0110111",
		"9": "0001011",
	},
	"B": { // left even parity
		"0": "0100111",
		"1": "0110011",
		"2": "0011011",
		"3": "0100001",
		"4": "0011101",
		"5": "0111001",
		"6": "0000101",
		"7": "0010001",
		"8": "0001001",
		"9": "0010111",
	},
	"C": { // right
		"0": "1110010",
		"1": "1100110",
		"2": "1101100",
		"3": "1000010",
		"4": "1011100",
		"5": "1001110",
		"6": "1010000",
		"7": "1000100",
		"8": "1001000",
		"9": "1110100",
	},
}

var parities = map[int]map[int][]string{
	0: {
		0: {"A", "A", "A", "A", "A", "A"},
		1: {"A", "A", "B", "A", "B", "B"},
		2: {"A", "A", "B", "B", "A", "B"},
		3: {"A", "A", "B", "B", "B", "A"},
		4: {"A", "B", "A", "A", "B", "B"},
		5: {"A", "B", "B", "A", "A", "B"},
		6: {"A", "B", "B", "B", "A", "A"},
		7: {"A", "B", "A", "B", "A", "B"},
		8: {"A", "B", "A", "B", "B", "A"},
		9: {"A", "B", "B", "A", "B", "A"},
	},
	2: {
		0: {"A", "1"},
		1: {"A", "B"},
		2: {"B", "A"},
		3: {"B", "B"},
	},
	3: {
		0: {"B", "B", "A", "A", "A"},
		1: {"B", "A", "B", "A", "A"},
		2: {"B", "A", "A", "B", "A"},
		3: {"B", "A", "A", "A", "B"},
		4: {"A", "B", "B", "A", "A"},
		5: {"A", "A", "B", "B", "A"},
		6: {"A", "A", "A", "B", "B"},
		7: {"A", "B", "A", "B", "A"},
		8: {"A", "B", "A", "A", "B"},
		9: {"A", "A", "B", "A", "B"},
	},
}


var upcParities = map[int]map[int][]string{
	0: {
		0: {"B", "B", "B", "A", "A", "A"},
		1: {"B", "B", "A", "B", "A", "A"},
		2: {"B", "B", "A", "A", "B", "A"},
		3: {"B", "B", "A", "A", "A", "B"},
		4: {"B", "A", "B", "B", "A", "A"},
		5: {"B", "A", "A", "B", "B", "A"},
		6: {"B", "A", "A", "A", "B", "B"},
		7: {"B", "A", "B", "A", "B", "A"},
		8: {"B", "A", "B", "A", "A", "B"},
		9: {"B", "A", "A", "B", "A", "B"},
	},
	1: {
		0: {"A", "A", "A", "B", "B", "B"},
		1: {"A", "A", "B", "A", "B", "B"},
		2: {"A", "A", "B", "B", "A", "B"},
		3: {"A", "A", "B", "B", "B", "A"},
		4: {"A", "B", "A", "A", "B", "B"},
		5: {"A", "B", "B", "A", "A", "B"},
		6: {"A", "B", "B", "B", "A", "A"},
		7: {"A", "B", "A", "B", "A", "B"},
		8: {"A", "B", "A", "B", "B", "A"},
		9: {"A", "B", "B", "A", "B", "A"},
	},
}


/**
 * EAN13 and UPC-A barcodes.
 * EAN13: European Article Numbering international retail product code
 * UPC-A: Universal product code seen on almost all retail products in the USA and Canada
 * UPC-E: Short version of UPC Symbol
 */
func barcodeEANUPC(code string, digit int) *barArray {
	if !onlyDigits(code) {
		fmt.Printf("code may only contain digits but got %s\n", code)
		return nil
	}
	upce := false
	if digit == 6 {
		digit = 12  // UPC-A
		upce = true // UPC-E mode
	}
	dataLen := digit - 1
	// Padding
	if upce {
		code = upce2a(code)
	} else {
		code = fmt.Sprintf("%0*s", dataLen, code)
	}
	codeLen := len(code)

	// calculate check digit
	sumA := 0
	for i := 1; i < dataLen; i += 2 {
		intVal, _ := strconv.Atoi(string(code[i]))
		sumA += intVal
	}
	if digit > 12 {
		sumA *= 3
	}
	sumB := 0
	for i := 0; i < dataLen; i += 2 {
		intVal, _ := strconv.Atoi(string(code[i]))
		sumB += (intVal)
	}
	if digit < 13 {
		sumB *= 3
	}
	r := (sumA + sumB) % 10
	if r > 0 {
		r = (10 - r)
	}
	if codeLen == dataLen {
		// add check digit
		code = code + strconv.Itoa(r)
	} else {
		// validate digit, last char of code must be r
		checkDigitInt, _ := strconv.Atoi(code[len(code)-1:])
		if checkDigitInt != r {
			fmt.Printf("[BARCODE] Check digit of given code %s is invalid must be %d", code, r)
			return nil
		}
	}
	if digit == 12 {
		// UPC-A
		code = "0" + code
	}
	// convert upc-a to upc-e
	var upcecode string
	if upce {
		tmp := code[4:7]
		if tmp == "000" || tmp == "100" || tmp == "200" {
			// manufacturer code ends in 000, 100, 200
			upcecode = code[2:4] + code[9:12] + code[4:5]
		} else {
			tmp = code[5:7]
			if tmp == "00" {
				upcecode = code[2:5] + code[10:12] + "3"
			} else {
				tmp = code[6:7]
				if tmp == "0" {
					upcecode = code[2:6] + code[11:12] + "4"
				} else {
					upcecode = code[2:7] + code[11:12]
				}
			}

		}
	}
	// Convert digits to bars
	seq := "101"
	var bararray barArray
	if upce {
		bararray = barArray{
			Code:  upcecode,
			MaxW:  0,
			MaxH:  1,
			BCode: []bCode{},
		}
		codeIntVal, _ := strconv.Atoi(code[:1])
		p := upcParities[codeIntVal][r]

		for i := 0; i < 6; i++ {
			seq = seq + codes[p[i]][string(upcecode[i])]
		}
		seq = seq + "010101" // right guard bar
	} else {
		bararray = barArray{
			Code:  code,
			MaxW:  0,
			MaxH:  1,
			BCode: []bCode{},
		}
		halfLen := int(math.Ceil(float64(digit) / float64(2)))
		if digit == 8 {
			for i := 0; i < halfLen; i++ {
				seq = seq + codes["A"][string(code[i])]
			}
		} else {
			codeIntVal, _ := strconv.Atoi(code[:1])
			p := parities[0][codeIntVal]
			for i := 1; i < halfLen; i++ {
				seq = seq + codes[p[i-1]][string(code[i])]
			}
			// all others except upc
		}
		// center guard bar
		seq = seq + "01010"
		for i := halfLen; i < digit; i++ {
			seq = seq + codes["C"][string(code[i])]
		}
		seq = seq + "101" // right guard bar
	}

	// calc width
	w := 0
	for i := 0; i < len(seq); i++ {
		w++
		if i == (len(seq)-1) || i < (len(seq)-1) && string(seq[i]) != string(seq[i+1]) {
			var t bool
			if string(seq[i]) == "1" {
				t = true
			}
			bararray.BCode = append(bararray.BCode, bCode{
				T: t,
				W: w,
				H: 1,
				P: 0,
			})
			bararray.MaxW += w
			w = 0
		}
	}

	return &bararray
}


// upce2a converts UPC-E to UPC-A
func upce2a(code string) string {
	var manufacturer string
	var itemNumber string

	if len(code) > 6 {
		code = code[len(code)-6:]
	} else {
		code = fmt.Sprintf("%06v", code)
	}

	switch code[5:6] {
	case "0":
		// substr($code, 0, 1) = 1
		manufacturer = code[:1] + code[1:2] + code[5:6] + "00"
		itemNumber = "00" + code[2:5]

	case "1":
		manufacturer = code[:2] + code[5:6] + "00"
		itemNumber = "00" + code[2:5]
	case "2":
		manufacturer = code[:2] + code[5:6] + "00"
		itemNumber = "00" + code[2:5]
	case "3":
		manufacturer = code[:2] + code[2:3] + "00"
		itemNumber = "000" + code[3:5]
	case "4":
		manufacturer = code[:4] + "0"
		itemNumber = "0000" + code[4:5]
	default:
		manufacturer = code[:5]
		itemNumber = "0000" + code[5:6]
	}
	return "0" + manufacturer + itemNumber
}


// #end
