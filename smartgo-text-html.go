
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260823.2358 :: STABLE
// [ TEXT / HTML ]

// REQUIRE: go 1.19 or later
package smartgo

const (
	REGEX_HTML_LITERAL_ENTITY 	string = `(?i)&([a-z]+);`
	REGEX_HTML_NUMERIC_ENTITY 	string = `(?i)&\#(x?[a-f0-9]+);`
	REGEX_HTML_ANY_ENTITY 		string = `(?i)&\#?(x?[a-z0-9]+);`

	DATA_URL_EMPTY_PREFIX 		string = "data:,"
	DATA_URL_CSS_PREFIX 		string = "data:text/css,"
	DATA_URL_JS_PREFIX 			string = "data:application/javascript,"
	DATA_URL_SVG_IMAGE_PREFIX 	string = "data:image/svg+xml,"

	SVG_BLANK_CODE 				string = `<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="1" height="1"></svg>`
)

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
