
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260116.2358 :: STABLE
// [ INTL (TEXT) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	intlnorm "github.com/unix-world/smartgo/textproc/intl-norm"
)

//-----


func StrDeaccent(s string) string {
	//--
	defer PanicHandler()
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	ns, err := intlnorm.RemoveDiacritics(s)
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Failed", err)
		return StrRepeat("?", len(s))
	} //end if
	//--
	ns = StrRegexReplaceAll(`[^([:graph:] \t\r\n)]`, ns, "?") // fix: replace all non-iso characters with `?` on failed decoded characters
	//--
	return ns
	//--
} //END FUNCTION


//-----


// #END
