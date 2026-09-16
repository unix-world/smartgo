
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE
// [ UM / CONV ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"fmt"
)

const (
	SIZE_BYTES_65K uint64 =    65535 // Reference Unit 65KB
	SIZE_BYTES_1M  uint64 =  1048576 // Reference Unit  1MB
	SIZE_BYTES_16M uint64 = 16777216 // Reference Unit 16MB
)


//-----


func ParseHexColor(hexClr string) (error, [3]int) {
	//--
	var r int = 0;
	var g int = 0;
	var b int = 0;
	//--
	var clr [3]int = [3]int{r, g, b}
	//--
	if(hexClr == "") {
		return NewError("Invalid Hex Color, empty"), clr
	} //end if
	if(len(hexClr) != 7) {
		return NewError("Invalid Hex Color, length must be 7"), clr
	} //end if
	if(!StrStartsWith(hexClr, "#")) {
		return NewError("Invalid Hex Color, must start with #"), clr
	} //end if
	//--
	_, err := fmt.Sscanf(StrToUpper(hexClr), "#%02x%02x%02x", &r, &g, &b)
	if(err != nil) {
		return NewError("Parse Hex Color failed: " + err.Error()), clr
	} //end if
	//--
	clr = [3]int{r, g, b}
	//--
	return nil, clr
	//--
} //END FUNCTION


//-----


func PrettyPrintBytes(b uint64) string {
	//--
	const unit uint64 = 1024
	if(b < unit) {
		return fmt.Sprintf("%dB", b)
	} //end if
	div, exp := unit, 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	} //end for
	//--
//	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPEZY"[exp]) // B, KB, MB, GB, TB, PB, EB, ZB, YB
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])   // B, KB, MB, GB, TB, PB, EB ; ZB and YB are overflowing uint64 ...
	//--
} //END FUNCTION


//-----


func BytesToKiloBytes(b uint64) uint64 { // KB
	//--
	return b / 1024
	//--
} //END FUNCTION


func BytesToMegaBytes(b uint64) uint64 { // MB
	//--
	return BytesToKiloBytes(b) / 1024
	//--
} //END FUNCTION


func BytesToGigaBytes(b uint64) uint64 { // GB
	//--
	return BytesToMegaBytes(b) / 1024
	//--
} //END FUNCTION


func BytesToTeraBytes(b uint64) uint64 { // TB
	//--
	return BytesToGigaBytes(b) / 1024
	//--
} //END FUNCTION


func BytesToPetaBytes(b uint64) uint64 { // PB
	//--
	return BytesToTeraBytes(b) / 1024
	//--
} //END FUNCTION


func BytesToExaBytes(b uint64) uint64 { // EB
	//--
	return BytesToPetaBytes(b) / 1024
	//--
} //END FUNCTION

/*
func BytesToZettaBytes(b uint64) uint64 { // ZB ; overflows uint64
	//--
	return BytesToExaBytes(b) / 1024
	//--
} //END FUNCTION
func BytesToYottaBytes(b uint64) uint64 { // YB ; overflows uint64
	//--
	return BytesToZettaBytes(b) / 1024
	//--
} //END FUNCTION
*/

//-----


// #END
