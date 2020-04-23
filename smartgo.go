
// GO Lang :: SmartGo :: Smart.Framework
// (c) 2020 unix-world.org
// r.20200423.1045

package smartgo


import (
//	"os"
//	"log"
	"fmt"
	"bytes"
	"strings"
	"strconv"
	"regexp"
	"html"
	"unicode"
	"net/url"
	"encoding/json"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)


func strTrimWhitespaces(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
//	s = strings.TrimSpace(s) // TrimSpace returns a slice of the string s, with all leading and trailing white space removed, as defined by Unicode. Not sure if contain also \x00 and \x0B ...
	s = strings.Trim(s, " \t\n\r\x00\x0B") // this is compatible with PHP (not sure if above is quite compatible since there is no clear reference wich are the exact whitespaces it trims)
	//--
	return s
	//--
} //END FUNCTION


func textCutByLimit(s string, length int) string {
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
	s = strGetUnicodeSubstring(s, 0, length - 3) // substract -3 because of the trailing dots ...
	s = regexReplaceAllStr(`\s+?(\S+)?$`, s, "") // {{{SYNC-REGEX-TEXT-CUTOFF}}}
	s = s + "..." // add trailing dots
	//--
	return s
	//--
} //END FUNCTION


func strGetUnicodeSubstring(s string, start int, stop int) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	runes := []rune(s)
	max := len(runes)
	//--
	if(start < 0) {
		start = 0
	} //end if
	if((stop <= 0) || (stop > max)) {
		stop = max
	} //end if
	//--
	return string(runes[start:stop])
	//--
} //END FUNCTION


func strGetAsciiSubstring(s string, start int, stop int) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	max := len(s)
	//--
	if(start < 0) {
		start = 0
	} //end if
	if((stop <= 0) || (stop > max)) {
		stop = max
	} //end if
	//--
	return string(s[start:stop])
	//--
} //END FUNCTION


func parseStringAsBoolStr(s string) string {
	//--
	if((s != "") && (s != "0")) { // fix PHP and Javascript as syntax if(tmp_marker_val){}
		s = "true";
	} else {
		s = "false";
	} //end if else
	//--
	return s
	//--
} //END FUNCTION


func parseIntegerStrAsInt(s string) int {
	//--
	var Int int = 0 // set the integer as zero Int, in the case of parseInt Error
	if tmpInt, convErr := strconv.Atoi(s); convErr == nil {
		Int = tmpInt
	} //end if else
	//--
	return Int
	//--
} //END FUNCTION


func parseInteger64AsStr(s string) string {
	//--
	if tmpInt, convErr := strconv.ParseInt(s, 10, 64); convErr == nil {
		s = strconv.FormatInt(tmpInt, 10)
	} else {
		s = "0" // set the integer as zero (string), in the case of parseInt Error
	} //end if else
	//--
	return s
	//--
} //END FUNCTION


func parseFloatAsStrDecimal(s string, d int) string {
	//--
	if(d < 1) {
		d = 1
	} else if(d > 8) {
		d = 8
	} //end if else
	//--
	var f float64 = 0
	if tmpFlt, convErr := strconv.ParseFloat(s, 64); convErr == nil {
		f = tmpFlt
	} //end if
	s = fmt.Sprintf("%." + strconv.Itoa(d) + "f", f)
	//--
	return string(s)
	//--
} //END FUNCTION


func parseFloatAsStrFloat(s string) string {
	//--
	var f float64 = 0
	if tmpFlt, convErr := strconv.ParseFloat(s, 64); convErr == nil {
		f = tmpFlt
	} //end if
	//--
	s = strconv.FormatFloat(f, 'g', 14, 64) // use precision 14 as in PHP
	//--
	return string(s)
	//--
} //END FUNCTION


func isUnicodeNonspacingMarks(r rune) bool {
	//--
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
	//--
} //END FUNCTION


func strDeaccent(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	t := transform.Chain(norm.NFD, transform.RemoveFunc(isUnicodeNonspacingMarks), norm.NFC)
	//--
	result, _, _ := transform.String(t, s)
	//--
	return string(result)
	//--
} //END FUNCTION


func regexReplaceAllStr(rexpr string, s string, repl string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	re := regexp.MustCompile(rexpr)
	return string(re.ReplaceAllString(s, repl))
	//--
} //END FUNCTION


func strCreateSlug(s string) string {
	//--
	s = strTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	s = strDeaccent(s)
	//--
	s = regexReplaceAllStr(`[^a-zA-Z0-9_\-]`, s, "-")
	s = regexReplaceAllStr(`[\-]+`, s, "-") // suppress multiple -
	s = strTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func strCreateHtmId(s string) string {
	//--
	s = strTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	//--
	s = regexReplaceAllStr(`[^a-zA-Z0-9_\-]`, s, "")
	s = strTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func strCreateJsVar(s string) string {
	//--
	s = strTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	//--
	s = regexReplaceAllStr(`[^a-zA-Z0-9_]`, s, "")
	s = strTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func bin2Hex(str string) string {
	//--
	i, err := strconv.ParseInt(str, 2, 0)
	if(err != nil) {
		return ""
	} //end if
	//--
	return strconv.FormatInt(i, 16)
	//--
} //END FUNCTION


func hex2Bin(hex string) string {
	//--
	ui, err := strconv.ParseUint(hex, 16, 64)
	//--
	if(err != nil) {
		return ""
	} //end if
	//--
	return fmt.Sprintf("%016b", ui)
	//--
} //END FUNCTION


func jsonEncode(data interface{}) string { // https://www.php2golang.com/method/function.json-encode.html
	//--
	jsons, err := json.Marshal(data)
	if(err != nil) {
		return ""
	} //end if
	//--
	return string(jsons)
	//--
} //END FUNCTION


func jsonDecode(data string) map[string]interface{} { // https://www.php2golang.com/method/function.json-decode.html
	//--
	if(data == "") {
		return nil
	} //end if
	//--
	var dat map[string]interface{}
	err := json.Unmarshal([]byte(data), &dat)
	if(err != nil) {
		return nil
	} //end if
	//--
	return dat
	//--
} //END FUNCTION


func rawUrlEncode(s string) string {
	//--
	return strings.Replace(url.QueryEscape(s), "+", "%20", -1) // replace all
	//--
} //END FUNCTION


func escapeHtml(s string) string { // provides a Smart.Framework ~ escapeHtml
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return html.EscapeString(s) // escapes these five characters: < > & ' "
	//--
} //END FUNCTION


func escapeCss(s string) string { // CSS provides a Twig-compatible CSS escaper
	//--
	var out = &bytes.Buffer{}
	//--
	for _, c := range s {
		if((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57)) {
			out.WriteRune(c) // a-zA-Z0-9
		} else {
			fmt.Fprintf(out, "\\%04X", c) // UTF-8
		} //end if else
	} //end for
	//--
	return out.String()
	//--
} //END FUNCTION


func escapeJs(in string) string { // provides a Smart.Framework ~ escapeJs
	//-- Test
	// RAW: "1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\"'~`!@#$%^&*()+=[]{}|\\<>,.?/\t\r\n"
	// GO :  1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\u0022\u0027~`!@#$%^\u0026*()+=[]{}|\\\u003C\u003E,.?\/\t\r\n
	// PHP:  1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\u0022\u0027~`!@#$%^\u0026*()+=[]{}|\\\u003C\u003E,.?\/\t\r\n
	//--
	var out = &bytes.Buffer{}
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
			fmt.Fprintf(out, "\\u%04X", c) // UTF-8
		} //end if else
	} //end for
	//--
	return out.String()
	//--
} //END FUNCTION


func strNl2Br(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = strings.ReplaceAll(s, "\r\n", "<br>")
	s = strings.ReplaceAll(s, "\r", "<br>")
	s = strings.ReplaceAll(s, "\n", "<br>")
	//--
	return s
	//--
} //END FUNCTION


func prepareNosyntaxHtmlMarkersTpl(tpl string) string {
	//--
	if(tpl == "") {
		return "";
	} //end if
	//--
	tpl = strings.Replace(tpl, "[###", "&lbrack;###", -1) // replace all
	tpl = strings.Replace(tpl, "###]", "###&rbrack;", -1) // replace all
	tpl = strings.Replace(tpl, "[%%%", "&lbrack;%%%", -1) // replace all
	tpl = strings.Replace(tpl, "%%%]", "%%%&rbrack;", -1) // replace all
	tpl = strings.Replace(tpl, "[@@@", "&lbrack;@@@", -1) // replace all
	tpl = strings.Replace(tpl, "@@@]", "@@@&rbrack;", -1) // replace all
	tpl = strings.Replace(tpl, "［###", "&lbrack;###", -1) // replace all
	tpl = strings.Replace(tpl, "###］", "###&rbrack;", -1) // replace all
	tpl = strings.Replace(tpl, "［%%%", "&lbrack;%%%", -1) // replace all
	tpl = strings.Replace(tpl, "%%%］", "%%%&rbrack;", -1) // replace all
	tpl = strings.Replace(tpl, "［@@@", "&lbrack;@@@", -1) // replace all
	tpl = strings.Replace(tpl, "@@@］", "@@@&rbrack;", -1) // replace all
	//--
	return tpl;
	//--
} //END FUNCTION


func prepareNosyntaxContentMarkersTpl(tpl string) string {
	//--
	if(tpl == "") {
		return "";
	} //end if
	//--
	tpl = strings.Replace(tpl, "[###", "［###", -1) // replace all
	tpl = strings.Replace(tpl, "###]", "###］", -1) // replace all
	tpl = strings.Replace(tpl, "[%%%", "［%%%", -1) // replace all
	tpl = strings.Replace(tpl, "%%%]", "%%%］", -1) // replace all
	tpl = strings.Replace(tpl, "[@@@", "［@@@", -1) // replace all
	tpl = strings.Replace(tpl, "@@@]", "@@@］", -1) // replace all
	//--
	return tpl
	//--
} //END FUNCTION


func renderMarkersTpl(template string, arrobj map[string]string, isEncoded bool, revertSyntax bool) string { // r.20200121

	var re = regexp.MustCompile(`\[###([A-Z0-9_\-\.]+)((\|[a-z0-9]+)*)###\]`)

	for i, match := range re.FindAllStringSubmatch(template, -1) {
		//--
		var tmp_marker_val string			= "" 									// just initialize
		var tmp_marker_id string			= string(match[0]) 						// [###THE-MARKER|escapings...###]
		var tmp_marker_key string			= string(match[1]) 						// THE-MARKER
		var tmp_marker_esc string			= string(match[2]) 						// |escaping1(|escaping2...|escaping99)
		//--
		mKeyValue, mKeyExists := arrobj[tmp_marker_key]
		//--
		if(mKeyExists) {
			//--
			tmp_marker_val = prepareNosyntaxContentMarkersTpl(mKeyValue)
			//--
			if((tmp_marker_id != "") && (tmp_marker_key != "")) {
				//--
			//	fmt.Println("---------- : " + tmp_marker_val)
			//	fmt.Println(tmp_marker_id + " # found Marker at index: " + strconv.Itoa(i))
			//	fmt.Println(tmp_marker_key + " # found Marker Key at index: ", strconv.Itoa(i))
			//	fmt.Println(tmp_marker_esc + " # found Marker Escaping at index: ", strconv.Itoa(i))
				//--
				if(tmp_marker_esc != "") {
					//--
					var tmp_marker_arr_esc []string	= strings.Split(tmp_marker_esc, "|") // just initialize
					//--
					for j, tmp_marker_each_esc := range tmp_marker_arr_esc {
						//--
						if(tmp_marker_each_esc != "") {
							//--
							var escaping string = "|" + tmp_marker_each_esc
							//--
			//				fmt.Println(escaping + " # found Marker Escaping [Arr] at index: " + strconv.Itoa(i) + "." + strconv.Itoa(j))
							//--
							if(escaping == "|bool") { // Boolean
								tmp_marker_val = parseStringAsBoolStr(tmp_marker_val)
							} else if(escaping == "|int") { // Integer
								tmp_marker_val = parseInteger64AsStr(tmp_marker_val)
							} else if(escaping == "|dec1") { // Decimals: 1
								tmp_marker_val = parseFloatAsStrDecimal(tmp_marker_val, 1)
							} else if(escaping == "|dec2") { // Decimals: 2
								tmp_marker_val = parseFloatAsStrDecimal(tmp_marker_val, 2)
							} else if(escaping == "|dec3") { // Decimals: 3
								tmp_marker_val = parseFloatAsStrDecimal(tmp_marker_val, 3)
							} else if(escaping == "|dec4") { // Decimals: 4
								tmp_marker_val = parseFloatAsStrDecimal(tmp_marker_val, 4)
							} else if(escaping == "|num") { // Number (Float / Decimal / Integer)
								tmp_marker_val = parseFloatAsStrFloat(tmp_marker_val)
							} else if(escaping == "|slug") { // Slug: a-zA-Z0-9_- / - / -- : -
								tmp_marker_val = strCreateSlug(tmp_marker_val)
							} else if(escaping == "|htmid") { // HTML-ID: a-zA-Z0-9_-
								tmp_marker_val = strCreateHtmId(tmp_marker_val)
							} else if(escaping == "|jsvar") { // JS-Variable: a-zA-Z0-9_
								tmp_marker_val = strCreateJsVar(tmp_marker_val)
							} else if((strGetAsciiSubstring(escaping, 0, 7) == "|substr") || (strGetAsciiSubstring(escaping, 0, 7) == "|subtxt")) { // Sub(String|Text) (0,num)
								xstrnum := strTrimWhitespaces(strGetAsciiSubstring(escaping, 7, 0))
								xnum := parseIntegerStrAsInt(xstrnum)
								if(xnum < 1) {
									xnum = 1
								} else if(xnum > 65535) {
									xnum = 65535
								} //end if else
								if(xnum >= 1 && xnum <= 65535) {
									if(len(tmp_marker_val) > xnum) {
										if(strGetAsciiSubstring(escaping, 0, 7) == "|subtxt") {
											tmp_marker_val = textCutByLimit(tmp_marker_val, xnum)
										} else { // '|substr'
											tmp_marker_val = strGetUnicodeSubstring(tmp_marker_val, 0, xnum)
										} //end if
									} //end if else
								} //end if
								xstrnum = ""
								xnum = 0
							} else if(escaping == "|lower") { // apply lowercase
								tmp_marker_val = strings.ToLower(tmp_marker_val)
							} else if(escaping == "|upper") { // apply uppercase
								tmp_marker_val = strings.ToUpper(tmp_marker_val)
							} else if(escaping == "|ucfirst") { // apply uppercase first character
								x1st := strings.ToUpper(strGetUnicodeSubstring(tmp_marker_val, 0, 1)) // get 1st char
								xrest := strings.ToLower(strGetUnicodeSubstring(tmp_marker_val, 1, 0)) // get the rest of characters
								tmp_marker_val = x1st + xrest
								x1st = ""
								xrest = ""
							} else if(escaping == "|ucwords") { // apply uppercase on each word
								tmp_marker_val = strings.Title(strings.ToLower(tmp_marker_val))
							} else if(escaping == "|trim") { // apply trim
								tmp_marker_val = strTrimWhitespaces(tmp_marker_val)
							} else if(escaping == "|url") { // escape URL
								tmp_marker_val = rawUrlEncode(tmp_marker_val)
							} else if(escaping == "|json") { // format as Json Data ; expects pure JSON !!!
								jsonObj := jsonDecode(tmp_marker_val)
								if(jsonObj == nil) {
									tmp_marker_val = "null"
								} else {
									tmp_marker_val = strTrimWhitespaces(jsonEncode(jsonObj))
									if(tmp_marker_val == "") {
										tmp_marker_val = "null"
									} //end if
								} //end if else
								jsonObj = nil
							} else if(escaping == "|js") { // Escape JS
								tmp_marker_val = escapeJs(tmp_marker_val)
							} else if(escaping == "|html") { // Escape HTML
								tmp_marker_val = escapeHtml(tmp_marker_val)
							} else if(escaping == "|css") { // Escape CSS
								tmp_marker_val = escapeCss(tmp_marker_val)
							} else if(escaping == "|nl2br") { // Format NL2BR
								tmp_marker_val = strNl2Br(tmp_marker_val)
							} else if(escaping == "|syntaxhtml") { // fix back markers tpl escapings in html
								tmp_marker_val = prepareNosyntaxHtmlMarkersTpl(tmp_marker_val)
							} else {
								fmt.Println("WARNING: renderMarkersTpl: {### Invalid or Undefined Escaping for Marker [" + strconv.Itoa(i) + "]: " + escaping + " [" + strconv.Itoa(j) + "] - detected in Replacement Key: " + tmp_marker_id)
							} //end if
							//--
						} //end if
						//--
					} //end for
					//--
				} //end if
				//--
				template = strings.Replace(template, tmp_marker_id, tmp_marker_val, -1) // replace all
				//--
			} //end if
			//--
		} //end if
		//--
	} //end for

//	fmt.Println("=====" + "\n" + template)

	return template

} //END FUNCTION


// #END
