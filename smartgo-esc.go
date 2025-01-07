
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250107.2358 :: STABLE
// [ ESCAPERS ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"fmt"

	"bytes"
	"strings"

	"net/url"

	"html"
	"encoding/xml"
)

//-----


func AddCSlashes(s string, c string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	var tmpRune []rune
	//--
	strRune := []rune(s)
	list := []rune(c)
	for _, ch := range strRune {
		for _, v := range list {
			if ch == v {
				tmpRune = append(tmpRune, '\\')
			} //end if
		} //end for
		tmpRune = append(tmpRune, ch)
	} //end for
	//--
	return string(tmpRune)
	//--
} //END FUNCTION


//-----


func EscapeXml(s string, extraEscapings bool) string { // provides a Smart.Framework ~ EscapeXml
	//-- v.20241228
	if(s == "") {
		return ""
	} //end if
	//--
	buf := bytes.Buffer{}
	err := xml.EscapeText(&buf, []byte(s)) // escapes all characters compliant with XML standard
	if(err != nil) {
		return ""
	} //end if
	//--
	s = buf.String()
	//--
	if(extraEscapings == true) { // as oposite to php, golang (by default) escapes the \r \n \t so it is actually operating in extra escaping mode
		return s // exml
	} //end if
	//--
	xmlExtraEscaper := strings.NewReplacer( // fix back already escaped special entities
		`&#xD;`, "\r", // `&#13;`
		`&#xA;`, "\n", // `&#10;`,
		`&#x9;`, "\t", // `&#09;`,
	)
	return xmlExtraEscaper.Replace(s) // xml
	//--
} //END FUNCTION


//-----


func EscapeHtml(s string) string { // provides a Smart.Framework ~ EscapeHtml
	//--
	if(s == "") {
		return ""
	} //end if
	//--
//	return html.EscapeString(s) // escapes these five characters: < > & ' "
	htmlEscaper := strings.NewReplacer( // do not use the above one, use this (a modified code of the above) because the above one replaces double quote as &#34; instead of &quot; and also single quote ...
		`&`, "&amp;",
	//	`'`, "&#39;", // "&apos;" is only for HTML5
		`<`, "&lt;",
		`>`, "&gt;",
		`"`, "&quot;", // "&#34;"
	)
	return htmlEscaper.Replace(s)
	//--
} //END FUNCTION


// works for HTML and XML too ...
func UnEscapeHtml(s string) string { // provides a Smart.Framework ~ Decode HTML or XML Entities ; since golang this can be used also for XML
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return html.UnescapeString(s)
	//--
} //END FUNCTION


//-----


func EscapeJs(in string) string { // provides a Smart.Framework ~ EscapeJs
	//-- Test
	// RAW: "1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\"'~`!@#$%^&*()+=[]{}|\\<>,.?/\t\r\n"
	// GO :  1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\u0022\u0027~`!@#$%^\u0026*()+=[]{}|\\\u003C\u003E,.?\/\t\r\n
	// PHP:  1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\u0022\u0027~`!@#$%^\u0026*()+=[]{}|\\\u003C\u003E,.?\/\t\r\n
	//--
	if(in == "") {
		return ""
	} //end if
	//--
	out := bytes.Buffer{}
	//--
	for _, c := range in {
		// chars: ASCII 32..126, but not 127 [DELETE] ; exclude: 34 ["] ; 38 [&] ; 39 ['] ; 47 [SLASH/] ; 60 [<] ; 62 [>] ; 92 [BACKSLASH]
		if((c >= 32) && (c <= 126) && (c != 34) && (c != 38) && (c != 39) && (c != 47) && (c != 60) && (c != 62) && (c != 92)) {
			out.WriteRune(c)
		} else if(c == 47) {   // SLASH/ = backslash + slash
			out.WriteRune(92)  // backslash
			out.WriteRune(c)   // slash
		} else if(c == 92) {   // BACKSLASH = backslash + backslash
			out.WriteRune(c)   // backslash
			out.WriteRune(c)   // backslash
		} else if(c == 9) {    // TAB as \t
			out.WriteRune(92)  // backslash
			out.WriteRune(116) // t
		} else if(c == 10) {   // LF as \n
			out.WriteRune(92)  // backslash
			out.WriteRune(110) // n
		} else if(c == 13) {   // CR as \r
			out.WriteRune(92)  // backslash
			out.WriteRune(114) // r
		} else {
			fmt.Fprintf(&out, "\\u%04X", c) // UTF-8
		} //end if else
	} //end for
	//--
	return out.String()
	//--
} //END FUNCTION


//-----


func EscapeCss(s string) string { // provides a Twig-compatible CSS escaper
	//--
	// The following characters have a special meaning in CSS, in sensitive contexts they have to be escaped:
	// !, ", #, $, %, &, ', (, ), *, +, ,, -, ., /, :, ;, <, =, >, ?, @, [, \, ], ^, `, {, |, }, ~
	// Compatible with javascript: MDN: CSS.escape(str)
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	out := bytes.Buffer{}
	//--
	for _, c := range s {
		if((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57)) {
			out.WriteRune(c) // a-zA-Z0-9
		} else {
			fmt.Fprintf(&out, "\\%04X", c) // UTF-8
		} //end if else
	} //end for
	//--
	return out.String()
	//--
} //END FUNCTION


//-----


func EscapeUrl(s string) string { // provides a Smart.Framework ~ EscapeUrl, an alias to RawUrlEncode
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return RawUrlEncode(s)
	//--
} //END FUNCTION


//-----


func RawUrlEncode(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return StrReplaceAll(url.QueryEscape(s), "+", "%20")
	//--
} //END FUNCTION


func RawUrlDecode(s string) string {
	//--
	defer PanicHandler() // req. by raw url decode panic handler with malformed data
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	u, _ := url.QueryUnescape(StrReplaceAll(s, "%20", "+"))
	//--
	return u
	//--
} //END FUNCTION


//-----


// #END
