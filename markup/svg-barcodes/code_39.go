
// based on: github.com/juliankoehn/barcode
// v.20260203.2358
// (c) unix-world.org

package barcodes

import (
	"strconv"
	"strings"
)


var (

	chars = map[rune]int{
		'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
		'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15, 'G': 16, 'H': 17, 'I': 18, 'J': 19, 'K': 20,
		'L': 21, 'M': 22, 'N': 23, 'O': 24, 'P': 25, 'Q': 26, 'R': 27, 'S': 28, 'T': 29, 'U': 30, 'V': 31,
		'W': 32, 'X': 33, 'Y': 34, 'Z': 35, '-': 36, '.': 37, ' ': 38, '$': 39, '/': 40, '+': 41, '%': 42,
	}

	chr = map[string]string{
		"0": "111331311",
		"1": "311311113",
		"2": "113311113",
		"3": "313311111",
		"4": "111331113",
		"5": "311331111",
		"6": "113331111",
		"7": "111311313",
		"8": "311311311",
		"9": "113311311",
		"A": "311113113",
		"B": "113113113",
		"C": "313113111",
		"D": "111133113",
		"E": "311133111",
		"F": "113133111",
		"G": "111113313",
		"H": "311113311",
		"I": "113113311",
		"J": "111133311",
		"K": "311111133",
		"L": "113111133",
		"M": "313111131",
		"N": "111131133",
		"O": "311131131",
		"P": "113131131",
		"Q": "111111333",
		"R": "311111331",
		"S": "113111331",
		"T": "111131331",
		"U": "331111113",
		"V": "133111113",
		"W": "333111111",
		"X": "131131113",
		"Y": "331131111",
		"Z": "133131111",
		"-": "131111313",
		".": "331111311",
		" ": "133111311",
		"$": "131313111",
		"/": "131311131",
		"+": "131113131",
		"%": "111313131",
		"*": "131131311",
	}

)


func barcodeCode39(code string, extended bool, checksum bool) *barArray {
	if code == "" {
		return nil
	}

	if extended {
		// code = encode_code39_ext(code)
		code = encodeCode39Ext(code)
	}

	if checksum {
		code = code + checksumCode39(code)
	}
	code = strings.ToUpper(code)

	// add start and stop codes if they does not exists on code
	if code[len(code)-1:] != "*" {
		code = code + "*"
	}
	if code[:1] != "*" {
		code = "*" + code
	}

	bararray := barArray{
		Code:  code,
		MaxW:  0,
		MaxH:  1,
		BCode: []bCode{},
	}

	// avg 7 iterations
	for i := 0; i < len(code); i++ {
		char := string([]rune(code)[i])

		chrs := chr[char]
		if chrs == "" {
			return nil
		}
		for j := 0; j < 9; j++ {
			var t bool
			if j%2 == 0 {
				t = true
			} else {
				t = false
			}
			w := string([]rune(chr[char])[j])
			wValue, _ := strconv.Atoi(w)
			x := bCode{
				T: t,
				W: wValue,
				H: 1,
				P: 0,
			}

			bararray.BCode = append(bararray.BCode, x)
			bararray.MaxW = bararray.MaxW + wValue
		}
		// gaps
		bararray.BCode = append(bararray.BCode, bCode{
			T: false,
			W: 1,
			H: 1,
			P: 0,
		})
	}
	// 128
	bararray.MaxW += len(code)

	return &bararray
}

/**
 * Calculate Code 39 checksum (modulo 43)
 */
func checksumCode39(code string) string {
	sum := 0

	for _, r := range code {
		v := chars[r]
		sum += v
	}

	sum = sum % 43

	for r, v := range chars {
		if v == sum {
			return string(r)
		}
	}
	return "#"
}

// encodeCode39Ext encode a string to be used for code 39 extended mode
func encodeCode39Ext(code string) string {
	var codeExt string

	for _, r := range code {
		if int(r) > len(encodeDictionary) {
			return ""
		}
		codeExt = codeExt + encodeDictionary[int(r)]
	}

	return codeExt
}


// #end
