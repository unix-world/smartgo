
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260823.2358 :: STABLE
// [ INTL (TEXT) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"strconv"

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


func StrDecodeUnicodePoints(uniEncoded string) (string, error) {
	//--
	// sample decode: `"\u26c1"` OR `"\u26ad\u26f1 unicode points sample"`
	//--
	defer PanicHandler() // various
	//--
	if(uniEncoded == "") {
		return "", nil // not an error, string may be empty
	} //end if
	//--
	uniDecoded, err := strconv.Unquote(uniEncoded)
	if(err != nil) {
		return "", NewError("Unicode Point decoding Failed for `" + uniEncoded + "`: " + err.Error())
	} //end if
	//--
	if(uniDecoded == "") { // if original encoded string was non-empty and this is empty, it is an error
		return "", NewError("Unicode Point decoding Failed for `" + uniEncoded + "`: " + "Unicode Decoded String is Empty")
	} //end if
	//--
	return uniDecoded, nil
	//--
} //END FUNC


//-----


// #END
