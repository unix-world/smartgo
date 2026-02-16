
// based on: github.com/juliankoehn/barcode
// v.20260203.2358
// (c) unix-world.org

package barcodes

import (
	"strconv"
	"strings"
)


var (

	encodeDictionary = map[int]string{ // code93
		0: "%u", 1: "$A", 2: "$B", 3: "$C",
		4: "$D", 5: "$E", 6: "$F", 7: "$G",
		8: "$H", 9: "$I", 10: "$J", 11: "£K",
		12: "$L", 13: "$M", 14: "$N", 15: "$0",
		16: "$P", 17: "$Q", 18: "$R", 19: "$S",
		20: "$T", 21: "$U", 22: "$V", 23: "$W",
		24: "$X", 25: "$Y", 26: "$Z", 27: "%A",
		28: "%B", 29: "%C", 30: "%D", 31: "%E",
		32: " ", 33: "/A", 34: "/B", 35: "/C",
		36: "/D", 37: "/E", 38: "/F", 39: "/G",
		40: "/H", 41: "/I", 42: "/J", 43: "/K",
		44: "/L", 45: "-", 46: ".", 47: "/O",
		48: "0", 49: "1", 50: "2", 51: "3",
		52: "4", 53: "5", 54: "6", 55: "7",
		56: "8", 57: "9", 58: "/Z", 59: "%F",
		60: "%G", 61: "%H", 62: "%I", 63: "%J",
		64: "%V", 65: "A", 66: "B", 67: "C",
		68: "D", 69: "E", 70: "F", 71: "G",
		72: "H", 73: "I", 74: "J", 75: "K",
		76: "L", 77: "M", 78: "N", 79: "O",
		80: "P", 81: "Q", 82: "R", 83: "S",
		84: "T", 85: "U", 86: "V", 87: "W",
		88: "X", 89: "Y", 90: "Z", 91: "%K",
		92: "%L", 93: "%M", 94: "%N", 95: "%O",
		96: "%W", 97: "+A", 98: "+B", 99: "+C",
		100: "+D", 101: "+E", 102: "+F", 103: "+G",
		104: "+H", 105: "+I", 106: "+J", 107: "+K",
		108: "+L", 109: "+M", 110: "+N", 111: "+O",
		112: "+P", 113: "+Q", 114: "+R", 115: "+S",
		116: "+T", 117: "+U", 118: "+V", 119: "+W",
		120: "+X", 121: "+Y", 122: "+Z", 123: "%P",
		124: "%Q", 125: "%R", 126: "%S", 127: "%T",
	}

	chr93 = map[byte]string{ // code93
		48:  "131112", // 0
		49:  "111213", // 1
		50:  "111312", // 2
		51:  "111411", // 3
		52:  "121113", // 4
		53:  "121212", // 5
		54:  "121311", // 6
		55:  "111114", // 7
		56:  "131211", // 8
		57:  "141111", // 9
		65:  "211113", // A
		66:  "211212", // B
		67:  "211311", // C
		68:  "221112", // D
		69:  "221211", // E
		70:  "231111", // F
		71:  "112113", // G
		72:  "112212", // H
		73:  "112311", // I
		74:  "122112", // J
		75:  "132111", // K
		76:  "111123", // L
		77:  "111222", // M
		78:  "111321", // N
		79:  "121122", // O
		80:  "131121", // P
		81:  "212112", // Q
		82:  "212211", // R
		83:  "211122", // S
		84:  "211221", // T
		85:  "221121", // U
		86:  "222111", // V
		87:  "112122", // W
		88:  "112221", // X
		89:  "122121", // Y
		90:  "123111", // Z
		45:  "121131", // -
		46:  "311112", // .
		32:  "311211", // " "
		36:  "321111", // $
		47:  "112131", // /
		43:  "113121", // +
		37:  "211131", // %
		128: "121221", // ($)
		129: "311121", // (/)
		130: "122211", // (+)
		131: "312111", // (%),
		42:  "111141", // start-stop
	}

)

func barcodeCode93(code string) *barArray {
	code = strings.ToUpper(code)

	var codeExt string

	// rune to string
	for _, r := range code {
		codeExt = codeExt + string(r)
	}

	codeExt = codeExt + checksumCode93(code)

	code = "*" + codeExt + "*"

	bararray := barArray{
		Code:  code,
		MaxW:  0,
		MaxH:  1,
		BCode: []bCode{},
	}
	for i := 0; i < len(code); i++ {
		byt := []byte(code)[i]
		if chr93[byt] == "" {
			return nil
		}
		for j := 0; j < 6; j++ {
			var t bool
			if j%2 == 0 {
				t = true
			} else {
				t = false
			}
			w := string([]rune(chr93[byt])[j])
			wValue, _ := strconv.Atoi(w)
			bararray.BCode = append(bararray.BCode, bCode{
				T: t,
				W: wValue,
				H: 1,
				P: 0,
			})
			bararray.MaxW += wValue
		}

	}
	bararray.BCode = append(bararray.BCode, bCode{
		T: true,
		W: 1,
		H: 1,
		P: 0,
	})
	bararray.MaxW++

	return &bararray
}


// checksumCode93 calculates checksum of
// code digit C & K
func checksumCode93(code string) string {
	chars := map[string]int{
		"0": 0, "1": 1, "2": 2, "3": 3, "4": 4, "5": 5, "6": 6, "7": 7, "8": 8, "9": 9,
		"A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17, "I": 18, "J": 19, "K": 20,
		"L": 21, "M": 22, "N": 23, "O": 24, "P": 25, "Q": 26, "R": 27, "S": 28, "T": 29, "U": 30, "V": 31,
		"W": 32, "X": 33, "Y": 34, "Z": 35, "-": 36, ".": 37, " ": 38, "$": 39, "/": 40, "+": 41, "%": 42,
		"<": 43, "=": 44, ">": 45, "?": 46,
	}

	// calc check digit C
	weight := 1
	check := 0
	for i := len(code) - 1; i >= 0; i-- {
		char := string([]rune(code)[i]) // 654321
		k := chars[char]
		check = check + (k * weight)
		// reset weight to 1
		if weight++; weight > 20 {
			weight = 1
		}
	}
	check = check % 47
	var c string
	for key, value := range chars {
		if value == check {
			c = key
		}
	}

	code = code + c

	// calc check digit K
	weight = 1
	check = 0
	for i := len(code) - 1; i >= 0; i-- {
		//fmt.Println(i)
		char := string([]rune(code)[i]) // 654321
		k := chars[char]
		check = check + (k * weight)
		// reset weight to 1
		if weight++; weight > 15 {
			weight = 1
		}
	}
	// should be 26 for QWERTZU
	check = check % 47
	var k string
	for key, value := range chars {
		if value == check {
			k = key
		}
	}
	checksum := c + k
	return checksum
}


// #end
