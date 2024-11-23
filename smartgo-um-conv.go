
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241123.2358 :: STABLE
// [ UM / CONV ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"fmt"
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
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPEZY"[exp]) // B, KB, MB, GB, TB, PB, EB, ZB, YB
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


func BytesToZettaBytes(b uint64) uint64 { // ZB
	//--
	return BytesToExaBytes(b) / 1024
	//--
} //END FUNCTION


func BytesToYottaBytes(b uint64) uint64 { // YB
	//--
	return BytesToZettaBytes(b) / 1024
	//--
} //END FUNCTION


//-----


// #END
