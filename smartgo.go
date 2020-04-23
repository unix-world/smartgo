
// GO Lang :: SmartGo :: Smart.Framework
// (c) 2020 unix-world.org
// r.20200423.2257

package smartgo


import (
//	"os"
	"io"
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
	"encoding/hex"
	"encoding/base64"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)


/*

func gzdeflate(str string) string {
	var b bytes.Buffer
	w, _ := gzip.NewWriterLevel(&b, 9)
	w.Write([]byte(str))
	w.Close()
	return b.String()
}

func gzinflate(str string) string {
	b := bytes.NewReader([]byte(str))
	r, _ := gzip.NewReader(b)
	bb2 := new(bytes.Buffer)
	_, _ = io.Copy(bb2, r)
	r.Close()
	byts := bb2.Bytes()
	return string(byts)
}

*/


func Base64Encode(data string) string {
	//--
	return base64.StdEncoding.EncodeToString([]byte(data))
	//--
} //END FUNCTION


func Base64Decode(data string) string {
	//--
	decoded, err := base64.StdEncoding.DecodeString(data)
	if(err != nil) {
		return ""
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


func Md5(str string) string {
	//--
	h := md5.New()
	io.WriteString(h, str)
	//--
	return fmt.Sprintf("%x", h.Sum(nil))
	//--
} //END FUNCTION


func Sha1(str string) string {
	//--
	hash := sha1.New()
	hash.Write([]byte(str))
	//--
	return hex.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func Sha256(str string) string {
	//--
	hash := sha256.New()
	//--
	hash.Write([]byte(str))
	//--
	return fmt.Sprintf("%x", hash.Sum(nil))
	//--
} //END FUNCTION


func Sha384(str string) string {
	//--
	hash := sha512.New384()
	//--
	hash.Write([]byte(str))
	//--
	return fmt.Sprintf("%x", hash.Sum(nil))
	//--
} //END FUNCTION


func Sha512(str string) string {
	//--
	hash := sha512.New()
	//--
	hash.Write([]byte(str))
	//--
	return fmt.Sprintf("%x", hash.Sum(nil))
	//--
} //END FUNCTION


func StrTrimWhitespaces(s string) string {
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
	s = StrGetUnicodeSubstring(s, 0, length - 3) // substract -3 because of the trailing dots ...
	s = RegexReplaceAllStr(`\s+?(\S+)?$`, s, "") // {{{SYNC-REGEX-TEXT-CUTOFF}}}
	s = s + "..." // add trailing dots
	//--
	return s
	//--
} //END FUNCTION


func StrGetUnicodeSubstring(s string, start int, stop int) string {
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


func StrGetAsciiSubstring(s string, start int, stop int) string {
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


func ParseStringAsBoolStr(s string) string {
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


func ParseIntegerStrAsInt(s string) int {
	//--
	var Int int = 0 // set the integer as zero Int, in the case of parseInt Error
	if tmpInt, convErr := strconv.Atoi(s); convErr == nil {
		Int = tmpInt
	} //end if else
	//--
	return Int
	//--
} //END FUNCTION


func ParseInteger64AsStr(s string) string {
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


func ParseFloatAsStrDecimal(s string, d int) string {
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


func ParseFloatAsStrFloat(s string) string {
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


//== PRIVATE
func isUnicodeNonspacingMarks(r rune) bool {
	//--
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
	//--
} //END FUNCTION
//==


func StrDeaccent(s string) string {
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


func RegexReplaceAllStr(rexpr string, s string, repl string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	re := regexp.MustCompile(rexpr)
	return string(re.ReplaceAllString(s, repl))
	//--
} //END FUNCTION


func StrCreateSlug(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	s = StrDeaccent(s)
	//--
	s = RegexReplaceAllStr(`[^a-zA-Z0-9_\-]`, s, "-")
	s = RegexReplaceAllStr(`[\-]+`, s, "-") // suppress multiple -
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
	s = RegexReplaceAllStr(`[^a-zA-Z0-9_\-]`, s, "")
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
	s = RegexReplaceAllStr(`[^a-zA-Z0-9_]`, s, "")
	s = StrTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func Bin2Hex(str string) string { // inspired from: https://www.php2golang.com/
	//--
	i, err := strconv.ParseInt(str, 2, 0)
	if(err != nil) {
		return ""
	} //end if
	//--
	return strconv.FormatInt(i, 16)
	//--
} //END FUNCTION


func Hex2Bin(hex string) string { // inspired from: https://www.php2golang.com/
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


func JsonEncode(data interface{}) string { // inspired from: https://www.php2golang.com/method/function.json-encode.html
	//--
	jsons, err := json.Marshal(data)
	if(err != nil) {
		return ""
	} //end if
	//--
	var safeJson string = string(jsons)
	//-- this JSON string will not be 100% like the one produced via PHP with HTML-Safe arguments but at least have the minimum escapes to avoid conflicting HTML tags
	safeJson = strings.Replace(safeJson, "&", "\\u0026", -1) // replace all :: & 	JSON_HEX_AMP                           ; already done by json.Marshal, but let in just in case if Marshall fails
	safeJson = strings.Replace(safeJson, "<", "\\u003C", -1) // replace all :: < 	JSON_HEX_TAG (use uppercase as in PHP) ; already done by json.Marshal, but let in just in case if Marshall fails
	safeJson = strings.Replace(safeJson, ">", "\\u003E", -1) // replace all :: > 	JSON_HEX_TAG (use uppercase as in PHP) ; already done by json.Marshal, but let in just in case if Marshall fails
	//-- these two are not done by json.Marshal
	safeJson = strings.Replace(safeJson, "/", "\\/",     -1) // replace all :: / 	JSON_UNESCAPED_SLASHES
	safeJson = StrTrimWhitespaces(safeJson)
	//-- Fixes: the JSON Marshall does not make the JSON to be HTML-Safe, thus we need several minimal replacements: https://www.drupal.org/node/479368 + escape / (slash)
	return safeJson
	//--
} //END FUNCTION


func JsonDecode(data string) map[string]interface{} { // inspired from: https://www.php2golang.com/method/function.json-decode.html
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


func RawUrlEncode(s string) string {
	//--
	return strings.Replace(url.QueryEscape(s), "+", "%20", -1) // replace all
	//--
} //END FUNCTION


func EscapeHtml(s string) string { // provides a Smart.Framework ~ EscapeHtml
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return html.EscapeString(s) // escapes these five characters: < > & ' "
	//--
} //END FUNCTION


func EscapeCss(s string) string { // CSS provides a Twig-compatible CSS escaper
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


func EscapeJs(in string) string { // provides a Smart.Framework ~ EscapeJs
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


func StrNl2Br(s string) string {
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


func PrepareNosyntaxHtmlMarkersTpl(tpl string) string {
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


func PrepareNosyntaxContentMarkersTpl(tpl string) string {
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


func RenderMarkersTpl(template string, arrobj map[string]string, isEncoded bool, revertSyntax bool) string { // r.20200121

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
			tmp_marker_val = PrepareNosyntaxContentMarkersTpl(mKeyValue)
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
								tmp_marker_val = ParseStringAsBoolStr(tmp_marker_val)
							} else if(escaping == "|int") { // Integer
								tmp_marker_val = ParseInteger64AsStr(tmp_marker_val)
							} else if(escaping == "|dec1") { // Decimals: 1
								tmp_marker_val = ParseFloatAsStrDecimal(tmp_marker_val, 1)
							} else if(escaping == "|dec2") { // Decimals: 2
								tmp_marker_val = ParseFloatAsStrDecimal(tmp_marker_val, 2)
							} else if(escaping == "|dec3") { // Decimals: 3
								tmp_marker_val = ParseFloatAsStrDecimal(tmp_marker_val, 3)
							} else if(escaping == "|dec4") { // Decimals: 4
								tmp_marker_val = ParseFloatAsStrDecimal(tmp_marker_val, 4)
							} else if(escaping == "|num") { // Number (Float / Decimal / Integer)
								tmp_marker_val = ParseFloatAsStrFloat(tmp_marker_val)
							} else if(escaping == "|slug") { // Slug: a-zA-Z0-9_- / - / -- : -
								tmp_marker_val = StrCreateSlug(tmp_marker_val)
							} else if(escaping == "|htmid") { // HTML-ID: a-zA-Z0-9_-
								tmp_marker_val = StrCreateHtmId(tmp_marker_val)
							} else if(escaping == "|jsvar") { // JS-Variable: a-zA-Z0-9_
								tmp_marker_val = StrCreateJsVarName(tmp_marker_val)
							} else if((StrGetAsciiSubstring(escaping, 0, 7) == "|substr") || (StrGetAsciiSubstring(escaping, 0, 7) == "|subtxt")) { // Sub(String|Text) (0,num)
								xstrnum := StrTrimWhitespaces(StrGetAsciiSubstring(escaping, 7, 0))
								xnum := ParseIntegerStrAsInt(xstrnum)
								if(xnum < 1) {
									xnum = 1
								} else if(xnum > 65535) {
									xnum = 65535
								} //end if else
								if(xnum >= 1 && xnum <= 65535) {
									if(len(tmp_marker_val) > xnum) {
										if(StrGetAsciiSubstring(escaping, 0, 7) == "|subtxt") {
											tmp_marker_val = TextCutByLimit(tmp_marker_val, xnum)
										} else { // '|substr'
											tmp_marker_val = StrGetUnicodeSubstring(tmp_marker_val, 0, xnum)
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
								x1st := strings.ToUpper(StrGetUnicodeSubstring(tmp_marker_val, 0, 1)) // get 1st char
								xrest := strings.ToLower(StrGetUnicodeSubstring(tmp_marker_val, 1, 0)) // get the rest of characters
								tmp_marker_val = x1st + xrest
								x1st = ""
								xrest = ""
							} else if(escaping == "|ucwords") { // apply uppercase on each word
								tmp_marker_val = strings.Title(strings.ToLower(tmp_marker_val))
							} else if(escaping == "|trim") { // apply trim
								tmp_marker_val = StrTrimWhitespaces(tmp_marker_val)
							} else if(escaping == "|url") { // escape URL
								tmp_marker_val = RawUrlEncode(tmp_marker_val)
							} else if(escaping == "|json") { // format as Json Data ; expects pure JSON !!!
								jsonObj := JsonDecode(tmp_marker_val)
								if(jsonObj == nil) {
									tmp_marker_val = "null"
								} else {
									tmp_marker_val = StrTrimWhitespaces(JsonEncode(jsonObj))
									if(tmp_marker_val == "") {
										tmp_marker_val = "null"
									} //end if
								} //end if else
								jsonObj = nil
							} else if(escaping == "|js") { // Escape JS
								tmp_marker_val = EscapeJs(tmp_marker_val)
							} else if(escaping == "|html") { // Escape HTML
								tmp_marker_val = EscapeHtml(tmp_marker_val)
							} else if(escaping == "|css") { // Escape CSS
								tmp_marker_val = EscapeCss(tmp_marker_val)
							} else if(escaping == "|nl2br") { // Format NL2BR
								tmp_marker_val = StrNl2Br(tmp_marker_val)
							} else if(escaping == "|syntaxhtml") { // fix back markers tpl escapings in html
								tmp_marker_val = PrepareNosyntaxHtmlMarkersTpl(tmp_marker_val)
							} else {
								fmt.Println("WARNING: RenderMarkersTpl: {### Invalid or Undefined Escaping for Marker [" + strconv.Itoa(i) + "]: " + escaping + " [" + strconv.Itoa(j) + "] - detected in Replacement Key: " + tmp_marker_id)
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
