
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260116.2358 :: STABLE
// [ UM / CONV ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"fmt"
)

const (
	SIZE_BYTES_16M uint64 = 16777216 // Reference Unit
)


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
