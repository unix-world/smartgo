
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260114.2358 :: STABLE
// [ TEXT / HTML ]

// REQUIRE: go 1.19 or later
package smartgo


//-----


func StrCreateSlug(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	s = StrDeaccent(s)
	s = StrReplaceAll(s, "?", "-") // replace all failed entities as `?` with `-` ; this is faster than regex below, pass through this one first
	//--
	s = StrRegexReplaceAll(`[^a-zA-Z0-9_\-]`, s, "-")
	s = StrRegexReplaceAll(`[\-]+`, s, "-") // suppress multiple -
	s = StrTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func StrCreateHtmId(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	//--
	s = StrRegexReplaceAll(`[^a-zA-Z0-9_\-]`, s, "")
	s = StrTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func StrCreateJsVarName(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	//--
	s = StrRegexReplaceAll(`[^a-zA-Z0-9_\$]`, s, "")
	s = StrTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func StrCreateStdVarName(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	//--
	s = StrRegexReplaceAll(`[^a-zA-Z0-9_]`, s, "")
	s = StrTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


//-----


func Nl2Br(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = StrReplaceAll(s, CARRIAGE_RETURN + LINE_FEED, "<br>")
	s = StrReplaceAll(s, CARRIAGE_RETURN, "<br>")
	s = StrReplaceAll(s, LINE_FEED, "<br>")
	//--
	return s
	//--
} //END FUNCTION


//-----


func TextCutByLimit(s string, length int) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	if(length < 5) {
		length = 5
	} //end if
	//--
	max := len(s)
	if(length >= max) {
		return s
	} //end if
	//--
	s = StrMBSubstr(s, 0, length - 3) // substract -3 because of the trailing dots ...
	s = StrRegexReplaceAll(`\s+?(\S+)?$`, s, "") // {{{SYNC-REGEX-TEXT-CUTOFF}}}
	s = s + "..." // add trailing dots
	//--
	return s
	//--
} //END FUNCTION


//-----


// #END
