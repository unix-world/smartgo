
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241129.2358 :: STABLE
// [ STRINGS ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"
	"time"

	"strings"

	"unicode"
	"unicode/utf8"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"

	"regexp"
	"github.com/unix-world/smartgo/textproc/regexp2"
)

const (
	REGEXP2_DEFAULT_MAX_RECURSION uint32 = 800000 	// Default REGEXP2 Recursion Limit: 800K
	REGEXP2_DEFAULT_MAX_TIMEOUT uint8 = 1			// Default REGEXP2 Max Timeout 1 Second(s)
)


//-----


func NullableStrFromStr(s string) *string {
	//--
	if(s == "") {
		return nil
	} //end if
	//--
	return &s
	//--
} //END FUNCTION


func NullableStrToStr(s *string) string {
	//--
	if(s == nil) {
		return ""
	} //end if
	//--
	return *s
	//--
} //END FUNCTION


//-----


func Ord(c string) int { // this is compatible with PHP, for single byte characters, ASCII ; only returns 0..255
	//-- DO NOT TRIM !
	if(c == "") {
		return -1 // empty
	} //end if
	if(len(c) != 1) {
		return -2 // multibyte
	} //end if
	//--
	r := []rune(c)
	if(len(r) != 1) {
		return -3 // conversion error
	} //end if
	//--
	o := int(r[0]) // ord()
	if(o > 255) {
		return -4 // out of scope, non-ASCII
	}
	if(o < 0) {
		return -5 // this should never happen, just an extra check
	}
	//--
	if(Chr(uint8(o)) != c) { // must be after the above checks: o is 0..255 because must be uint8 !
		return -6 // this should never happen, just an extra check
	} //end if
	//--
	return o
	//--
} //END FUNCTION


func Chr(o uint8) string {
	//--
	if(o < 0) {
		return ""
	} else if(o > 255) {
		return ""
	} //end if
	//--
	c := rune(o) // chr()
	//--
	return string(c)
	//--
} //END FUNCTION


//-----


func ExplodeWithLimit(delimiter string, text string, limit int) []string {
	//--
	return strings.SplitN(text, delimiter, limit)
	//--
} //END FUNCTION


func Explode(delimiter string, text string) []string {
	//--
	return strings.Split(text, delimiter)
	//--
} //END FUNCTION


func Implode(glue string, pieces []string) string {
	//--
	return strings.Join(pieces, glue)
	//--
} //END FUNCTION


//-----


// case sensitive, find position of first occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrPos(haystack string, needle string) int {
	//--
	if((haystack == "") || (needle == "")) {
		return -1
	} //end if
	//--
	pos := strings.Index(haystack, needle) // -1 if needle is not present in haystack
	//--
	if(pos < 0) {
		return -1 // make it standard return
	} //end if
	//--
	rs := []rune(haystack[0:pos])
	//--
	return len(rs)
	//--
} //END FUNCTION


// case insensitive, find position of first occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrIPos(haystack, needle string) int {
	//--
	return StrPos(StrToLower(haystack), StrToLower(needle))
	//--
} //END FUNCTION


// case sensitive, find position of last occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrRPos(haystack string, needle string) int {
	//--
	if((haystack == "") || (needle == "")) {
		return -1
	} //end if
	//--
	pos := strings.LastIndex(haystack, needle) // -1 if needle is not present in haystack
	//--
	if(pos < 0) {
		return -1 // make it standard return
	} //end if
	//--
	rs := []rune(haystack[0:pos])
	//--
	return len(rs)
	//--
} //END FUNCTION


// case insensitive, find position of last occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrRIPos(haystack, needle string) int {
	//--
	return StrRPos(StrToLower(haystack), StrToLower(needle))
	//--
} //END FUNCTION


//-----


func StrStartsWith(str string, part string) bool {
	//--
	return strings.HasPrefix(str, part)
	//--
} //END FUNCTION


func StrIStartsWith(str string, part string) bool {
	//--
	return strings.HasPrefix(StrToLower(str), StrToLower(part))
	//--
} //END FUNCTION


func StrEndsWith(str string, part string) bool {
	//--
	return strings.HasSuffix(str, part)
	//--
} //END FUNCTION


func StrIEndsWith(str string, part string) bool {
	//--
	return strings.HasSuffix(StrToLower(str), StrToLower(part))
	//--
} //END FUNCTION


//-----


func StrContains(str string, part string) bool {
	//--
	return strings.Contains(str, part)
	//--
} //END FUNCTION


func StrIContains(str string, part string) bool {
	//--
	return strings.Contains(StrToLower(str), StrToLower(part))
	//--
} //END FUNCTION


//-----


func StrTrim(s string, cutset string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = strings.Trim(s, cutset)
	//--
	return s
	//--
} //END FUNCTION


func StrTrimLeft(s string, cutset string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = strings.TrimLeft(s, cutset)
	//--
	return s
	//--
} //END FUNCTION


func StrTrimRight(s string, cutset string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = strings.TrimRight(s, cutset)
	//--
	return s
	//--
} //END FUNCTION


func StrTrimWhitespaces(s string) string {
	//--
	return StrTrim(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


func StrTrimLeftWhitespaces(s string) string {
	//--
	return StrTrimLeft(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


func StrTrimRightWhitespaces(s string) string {
	//--
	return StrTrimRight(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


//-----


func StrMBSubstr(s string, start int, stop int) string {
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


func StrSubstr(s string, start int, stop int) string {
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


//-----


func StrNormalizeSpaces(s string) string {
	//--
	s = StrReplaceAll(s, CARRIAGE_RETURN + LINE_FEED, " ")
	s = StrReplaceAll(s, CARRIAGE_RETURN, " ")
	s = StrReplaceAll(s, LINE_FEED, " ")
	s = StrReplaceAll(s, HORIZONTAL_TAB, " ")
	s = StrReplaceAll(s, VERTICAL_TAB, " ")
	s = StrReplaceAll(s, NULL_BYTE, " ")
	s = StrReplaceAll(s, FORM_FEED,   " ")
	//--
	s = StrReplaceAll(s, BACK_SPACE,   " ")
	s = StrReplaceAll(s, ASCII_BELL,   " ")
	//--
	return s
	//--
} //END FUNCTION


//-----


// case sensitive replacer
func StrReplaceWithLimit(s string, part string, replacement string, limit int) string {
	//--
	return strings.Replace(s, part, replacement, limit) // if (limit == -1) will replace all
	//--
} //END FUNCTION


// case sensitive replacer
func StrReplaceAll(s string, part string, replacement string) string {
	//--
//	return strings.ReplaceAll(s, part, replacement)
	return StrReplaceWithLimit(s, part, replacement, -1)
	//--
} //END FUNCTION


// case insensitive replacer
func StrIReplaceWithLimit(s, part, replacement string, limit int) string {
	//--
	if((part == replacement) || (part == "")) {
		return s // avoid allocation
	} //end if
	//--
	t := strings.ToLower(s)
	o := strings.ToLower(part)
	//-- compute number of replacements
	n := strings.Count(t, o)
	if((n == 0) || (limit == 0)) {
		return s // avoid allocation
	} //end if
	if(limit < 0) {
		limit = n
	} //end if
	//-- apply replacements to buffer
	var b strings.Builder
	b.Grow(len(s) + n * (len(replacement) - len(part)))
	start := 0
	for i := 0; i < n; i++ {
		j := start
		if(len(part) == 0) {
			if(i > 0) {
				_, wid := utf8.DecodeRuneInString(s[start:])
				j += wid
			} //end if
		} else {
			j += strings.Index(t[start:], o)
		} //end if else
		b.WriteString(s[start:j])
		b.WriteString(replacement)
		start = j + len(part)
		if(i >= (limit - 1)) {
			break
		} //end if
	} //end for
	b.WriteString(s[start:])
	//--
	return b.String()
	//--
} //END FUNCTION


// case insensitive replacer
func StrIReplaceAll(s string, part string, replacement string) string {
	//--
	return StrIReplaceWithLimit(s, part, replacement, -1)
	//--
} //END FUNCTION


//-----


func StrToLower(str string) string {
	//--
	return strings.ToLower(str)
	//--
} //END FUNCTION


func StrToUpper(str string) string {
	//--
	return strings.ToUpper(str)
	//--
} //END FUNCTION


func StrUcFirst(s string) string {
	//-- the previous approach was to take the first character from string, make it upper using strings and append the rest ; this appear a better approach
	if(s == "") {
		return ""
	} //end if
	//--
	runes := []rune(s)
	runes[0] = unicode.ToUpper(runes[0])
	//--
	return string(runes)
	//--
} //END FUNCTION


func StrUcWords(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return strings.Title(StrToLower(s))
	//--
} //END FUNCTION


//-----


func StrRepeat(str string, count int) string {
	//--
	if(str == "") {
		return ""
	} //end if
	if(count <= 0) {
		return ""
	} //end if
	//--
	return strings.Repeat(str, count)
	//--
} //END FUNC


//-----


func StrPad2LenLeft(s string, padStr string, overallLen int) string { // LeftPad2Len https://github.com/DaddyOh/golang-samples/blob/master/pad.go
	//--
	if(len(s) >= overallLen) { // fix, as in PHP
		return s
	} //end if
	//--
	var padCountInt int = 1 + ((overallLen - len(padStr)) / len(padStr))
	var retStr string = strings.Repeat(padStr, padCountInt) + s
	//--
	return retStr[(len(retStr) - overallLen):]
	//--
} //END FUNCTION


func StrPad2LenRight(s string, padStr string, overallLen int) string { // RightPad2Len https://github.com/DaddyOh/golang-samples/blob/master/pad.go
	//--
	if(len(s) >= overallLen) { // fix, as in PHP
		return s
	} //end if
	//--
	var padCountInt int = 1 + ((overallLen - len(padStr)) / len(padStr))
	var retStr string = s + strings.Repeat(padStr, padCountInt)
	//--
	return retStr[:overallLen]
	//--
} //END FUNCTION


//-----


// ChunkSplit chunk_split()
func StrChunkSplit(body string, chunklen uint, end string) string { // github.com/syyongx/php2go/blob/master/php.go
	//--
	if(end == "") {
		return body
	} //end if
	//--
	runes, erunes := []rune(body), []rune(end)
	l := uint(len(runes))
	if((l <= 1) || (l < chunklen)) {
		return body + end
	} //end if
	ns := make([]rune, 0, len(runes)+len(erunes))
	var i uint
	for i = 0; i < l; i += chunklen {
		if(i+chunklen > l) {
			ns = append(ns, runes[i:]...)
		} else {
			ns = append(ns, runes[i:i+chunklen]...)
		} //end if else
		ns = append(ns, erunes...)
	} //end for
	//--
	return string(ns)
	//--
} //END FUNCTION


//-----


// StrWordCount str_word_count()
func StrWordCount(str string) []string { // github.com/syyongx/php2go/blob/master/php.go
	//--
	return strings.Fields(str)
	//--
} //END FUNCTION


// Strlen strlen()
func StrLen(str string) int {
	//--
	return len(str)
	//--
} //END FUNCTION


// MbStrlen mb_strlen()
func StrUnicodeLen(str string) int { // github.com/syyongx/php2go/blob/master/php.go
	//-- alias: StrMBLen()
	return utf8.RuneCountInString(str)
	//--
} //END FUNCTION


//-----


func StrRev(s string) string { // PHP compatible
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	n := len(s)
	runes := make([]rune, n)
	for _, rune := range s {
		n--
		runes[n] = rune
	} //end for
	//--
	return string(runes[n:])
	//--
} //END FUNCTION


//-----


//== PRIVATE
func isUnicodeNonspacingMarks(r rune) bool {
	//--
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
	//--
} //END FUNCTION
//==


func StrDeaccent(s string) string {
	//--
	defer PanicHandler() // req. by transform panic handler with malformed data
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


//-----


func StrRegexReplaceAll(rexpr string, s string, repl string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	re := regexp.MustCompile(rexpr)
	return string(re.ReplaceAllString(s, repl))
	//--
} //END FUNCTION


func StrRegexMatchString(rexpr string, s string) bool {
	//--
	if((StrTrimWhitespaces(rexpr) == "") || (s == "")) { // s must NOT be trimmed
		return false
	} //end if
	//--
	matched, _ := regexp.MatchString(rexpr, s)
	//--
	return matched
	//--
} //END FUNCTION


func StrRegex2FindAllStringMatches(mode string, rexp string, s string, maxRecursion uint32, maxTimeOut uint8) (rx *regexp2.Regexp, mh []string) {
	//--
	// mode: "ECMA" | "RE2" | "PERL"
	//--
	var flags regexp2.RegexOptions = 0 // the default flag is: 0 (.NET / Perl compatibility mode)
	mode = StrToUpper(StrTrimWhitespaces(mode))
	if(mode == "ECMA") {
		flags = regexp2.ECMAScript
	} else if(mode == "RE2") {
		flags = regexp2.RE2
	} else { // default Perl / .Net
		mode = "PERL"
	} //end if
	//--
	var max int = int(maxRecursion) // max recursion
	if(max <= 0) {
		max = int(REGEXP2_DEFAULT_MAX_RECURSION)
	} //end if
	//--
	var timeout int = int(maxTimeOut) // max timeout
	if(timeout <= 0) {
		timeout = int(REGEXP2_DEFAULT_MAX_TIMEOUT)
	} else if(timeout > 60) {
		timeout = 60
	} //end if
	//--
	var matches []string
	re := regexp2.MustCompile(rexp, flags)
	re.MatchTimeout = time.Duration(timeout) * time.Second
	m, _ := re.FindStringMatch(s)
	for m != nil {
		matches = append(matches, m.String())
		m, _ = re.FindNextMatch(m)
		max--
		if(max <= 0) {
			log.Println("[WARNING] " + CurrentFunctionName() + ": Regexp2 max recursion limit ...")
			break
		} //end if
	} //end for
	//--
	return re, matches
	//--
//	// SAMPLE USAGE:
//	re, matches := StrRegex2FindAllStringMatches("PERL", `[a-z]+`, `Something to match`, 0, 0)
//	for c := 0; c < len(matches); c++ {
//		if m, e := re.FindStringMatch(matches[c]); m != nil && e == nil {
//			g := m.Groups()
//			log.Println(g[0].String(), g[1].String(), "...")
//		} //end if
//	} //end for
	//--
} //END FUNCTION


//-----


// #END
