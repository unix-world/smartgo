
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250214.2358 :: STABLE
// [ STRINGS ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"
	"time"

	"strings"

	"unicode/utf8"

	"regexp"
	"github.com/unix-world/smartgo/textproc/regexp2"
)

const (
	REGEXP2_DEFAULT_MAX_RECURSION uint32 	= 1000000 	// Default REGEXP2 Recursion Limit: 1 million
	REGEXP2_DEFAULT_MAX_TIMEOUT uint8 		=       1	// Default REGEXP2 Max Timeout 1 Second(s)
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
	expl := strings.SplitN(text, delimiter, limit)
	//--
	if(expl == nil) {
		expl = []string{}
	} //end if
	//--
	return expl
	//--
} //END FUNCTION


func Explode(delimiter string, text string) []string {
	//--
	expl := strings.Split(text, delimiter)
	//--
	if(expl == nil) {
		expl = []string{}
	} //end if
	//--
	return expl
	//--
} //END FUNCTION


func Implode(glue string, pieces []string) string {
	//--
	if(pieces == nil) {
		return ""
	} //end if
	if(len(pieces) <= 0) {
		return ""
	} //end if
	//--
	return strings.Join(pieces, glue)
	//--
} //END FUNCTION


//-----


// case sensitive, find position of first occurrence of string in a string
// return -1 if can not find the substring or the position of needle in haystack
func StrPos(haystack string, needle string, binary bool) int {
	//--
	// for PHP compatibility (multi-byte safe), use: binary = false
	//--
	// Benchmark: using this to test if a string starts with some part is slow 218.542µs vs StrStartsWith 35.542µs for a loop of 10000 test cycles
	// even if the rune part was not used it was still slow, 175.792µs vs 37.833µs
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
	if(binary == true) {
		return pos
	} //end if
	//--
	rs := []rune(haystack[0:pos])
	//--
	return len(rs)
	//--
} //END FUNCTION


// case insensitive, find position of first occurrence of string in a string ; PHP compatible
// return -1 if can not find the substring or the position of needle in haystack
func StrIPos(haystack string, needle string, binary bool) int {
	//--
	// for PHP compatibility (multi-byte safe), use: binary = false
	//--
	// Benchmark: use StrIStartsWith() which is much faster instead of this to test if a string starts with some part
	//--
	return StrPos(StrToLower(haystack), StrToLower(needle), binary)
	//--
} //END FUNCTION


// case sensitive, find position of last occurrence of string in a string ; PHP compatible
// return -1 if can not find the substring or the position of needle in haystack
func StrRPos(haystack string, needle string, binary bool) int {
	//--
	// for PHP compatibility (multi-byte safe), use: binary = false
	//--
	// Benchmark: use StrEndsWith() which is much faster instead of this to test if a string ends with some part
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
	if(binary == true) {
		return pos
	} //end if
	//--
	rs := []rune(haystack[0:pos])
	//--
	return len(rs)
	//--
} //END FUNCTION


// case insensitive, find position of last occurrence of string in a string ; PHP compatible
// return -1 if can not find the substring or the position of needle in haystack
func StrRIPos(haystack string, needle string, binary bool) int {
	//--
	// for PHP compatibility (multi-byte safe), use: binary = false
	//--
	// Benchmark: use StrIEndsWith() which is much faster instead of this to test if a string ends with some part
	//--
	return StrRPos(StrToLower(haystack), StrToLower(needle), binary)
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
	return strings.Trim(s, cutset)
	//--
} //END FUNCTION


func StrTrimLeft(s string, cutset string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return strings.TrimLeft(s, cutset)
	//--
} //END FUNCTION


func StrTrimRight(s string, cutset string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return strings.TrimRight(s, cutset)
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
	if(stop <= start) {
		return ""
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
	if(stop <= start) {
		return ""
	} //end if
	//--
	return s[start:stop]
	//--
} //END FUNCTION


//-----


func StrNormalizeSpaces(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
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


func StrToValidUTF8Fix(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return strings.ToValidUTF8(s, INVALID_CHARACTER)
	//--
} //END FUNCTION


//-----


func StrSpnChr(s string, c rune, ofs uint32, length uint32) uint32 {
	//--
	var max uint32 = uint32(len(s))
	if(max <= 0) {
		return 0
	} //end if
	if(ofs >= max) {
		return 0
	} //end if
	//--
	if(length <= 0) {
		length = max
	} //end if
	//--
	var i uint32 = 0
	var cnt uint32 = 0
	for i=ofs; i<max; i++ {
		if(string(s[i]) == string(c)) {
			cnt++
		} else {
			break
		} //end if
		if(cnt >= length) {
			break
		} //end if
	} //end for
	//--
	return cnt
	//--
} //END FUNCTION


//-----


func StrTr(str string, replace map[string]string) string { // php2golang.com # function.strtr
	//--
	// IMPORTANT: use this *ONLY* if the replacements order does not matter ; golang have only UNORDERED MAPS ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
	//--
	if((len(replace) <= 0) || (len(str) <= 0)) {
		return str
	} //end if
	//--
	for old, new := range replace {
		str = strings.ReplaceAll(str, old, new)
	} //end for
	//--
	return str
	//--
} //END FUNCTION


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
func StrIReplaceWithLimit(s string, part string, replacement string, limit int) string {
	//--
	if(s == "") {
		return ""
	} //end if
	if((part == "") || (part == replacement)) {
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
	if(str == "") {
		return ""
	} //end if
	//--
	return strings.ToLower(str)
	//--
} //END FUNCTION


func StrToUpper(str string) string {
	//--
	if(str == "") {
		return ""
	} //end if
	//--
	return strings.ToUpper(str)
	//--
} //END FUNCTION


//-----


func StrUcFirst(s string) string {
	//--
	// the 1st approach was to take the first character from string, make it upper using strings and append the rest ; this appear a better approach
	// the 2nd approach is without unicode which is slow and unicode.ToUpper is differen than strings.ToUpper, so now is using strings.ToUpper
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	runes := []rune(s)
//	runes[0] = unicode.ToUpper(runes[0])
	cRune := []rune(strings.ToUpper(string(runes[0])))
	runes[0] = cRune[0]
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


// PHP strlen()
func StrLen(str string) int {
	//--
	return len(str)
	//--
} //END FUNCTION


// PHP mb_strlen()
func StrUnicodeLen(str string) int { // github.com/syyongx/php2go/blob/master/php.go
	//-- alias: StrMBLen()
	return utf8.RuneCountInString(str)
	//--
} //END FUNCTION


// PHP str_word_count()
func StrWordCount(str string) []string { // github.com/syyongx/php2go/blob/master/php.go
	//--
	wc := strings.Fields(str)
	//--
	if(wc == nil) {
		wc = []string{}
	} //end if
	//--
	return wc
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


func StrRegexCallbackReplaceWithLimit(rexpr string, str string, replFx func(mgroups []string) string, limit int) string {
	//--
	defer PanicHandler() // regex compile
	//--
	// this method is a modified blend, inspired from the following source code:
	// https://github.com/agext/regexp # License: Apache 2.0
	//--
	if(str == "") {
		return ""
	} //end if
	//--
	re, errRx := regexp.Compile(rexpr)
	if((errRx != nil) || (re == nil)) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp Expression", rexpr, errRx)
		return ""
	} //end if
	//--
	if(replFx == nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Regexp Replace Function is Null", rexpr)
		return str
	} //end if
	//--
	result := ""
	lastIndex := 0
	matches := re.FindAllSubmatchIndex([]byte(str), limit)
	for _, v := range matches {
		var groups []string
		for i := 0; i < len(v); i += 2 {
			if v[i] == -1 || v[i+1] == -1 {
				groups = append(groups, "")
			} else {
				groups = append(groups, str[v[i]:v[i+1]])
			} //end if else
		} //end for
		result += str[lastIndex:v[0]] + replFx(groups)
		lastIndex = v[1]
	} //end for
	//--
	return result + str[lastIndex:]
	//--
} //END FUNCTION


func StrRegexCallbackReplaceAll(rexpr string, str string, replFx func(mgroups []string) string) string {
	//--
	defer PanicHandler() // regex compile
	//--
	return StrRegexCallbackReplaceWithLimit(rexpr, str, replFx, -1)
	//--
} //END FUNCTION


func StrRegexReplaceAll(rexpr string, s string, repl string) string {
	//--
	defer PanicHandler() // regex compile
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	re, errRx := regexp.Compile(rexpr)
	if((errRx != nil) || (re == nil)) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp Expression", rexpr, errRx)
		return ""
	} //end if
	//--
	return re.ReplaceAllString(s, repl)
	//--
} //END FUNCTION


func StrRegexReplaceFirst(rexpr string, s string, repl string) string {
	//--
	defer PanicHandler() // regex compile
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	matches, err := StrRegexFindFirstMatch(rexpr, s)
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "ERR:", rexpr, err)
		return ""
	} //end if
	//--
	if(len(matches) > 0) {
		s = StrReplaceWithLimit(s, matches[0], repl, 1)
	} //end if
	//--
	return s
	//--
} //END FUNCTION


func StrRegexMatch(rexpr string, s string) bool {
	//--
	defer PanicHandler() // regex compile
	//--
	if(s == "") {
		return false
	} //end if
	//--
	matched, errRx := regexp.MatchString(rexpr, s)
	if(errRx != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp Expression", rexpr, errRx)
		return false
	} //end if
	//--
	return matched
	//--
} //END FUNCTION


func StrRegexFindFirstMatch(rexp string, s string) ([]string, error) {
	//--
	defer PanicHandler() // regex compile
	//--
	var match []string = []string{}
	//--
	if(s == "") {
		return match, nil
	} //end if
	//--
	matches, err := StrRegexFindAllMatches(rexp, s, 1)
	if(err != nil) {
		return match, err
	} //end if
	if(len(matches) != 1) {
		return match, nil
	} //end if
	//--
	return matches[0], nil
	//--
} //END FUNCTION


func StrRegex2FindFirstMatch(mode string, rexp string, s string, maxTimeOut uint8) ([]string, error) {
	//--
	defer PanicHandler() // regex compile
	//--
	var match []string = []string{}
	//--
	if(s == "") {
		return match, nil
	} //end if
	//--
	matches, err := StrRegex2FindAllMatches(mode, rexp, s, 1, maxTimeOut)
	if(err != nil) {
		return match, err
	} //end if
	if(len(matches) != 1) {
		return match, nil
	} //end if
	//--
	return matches[0], nil
	//--
} //END FUNCTION


func StrRegexFindAllMatches(rexp string, s string, maxRecursion uint32) ([][]string, error) {
	//--
	defer PanicHandler() // regex compile
	//--
	var matches [][]string = [][]string{}
	//--
	if(s == "") {
		return matches, nil
	} //end if
	//--
	var max int = int(maxRecursion) // max recursion
	if(max <= 0) {
		max = int(REGEXP2_DEFAULT_MAX_RECURSION)
	} //end if
	//--
	re, errRx := regexp.Compile(rexp)
	if((errRx != nil) || (re == nil)) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp Expression, Error:", rexp, errRx)
		return matches, NewError("Invalid Regexp Expression, Error")
	} //end if
	if(re == nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp2 Expression, Null:", rexp)
		return matches, NewError("Invalid Regexp Expression, Null")
	} //end if
	matches = re.FindAllStringSubmatch(s, max)
	if(matches == nil) {
		matches = [][]string{}
	} //end if
	//--
	return matches, nil
	//--
} //END FUNCTION


func StrRegex2FindAllMatches(mode string, rexp string, s string, maxRecursion uint32, maxTimeOut uint8) ([][]string, error) {
	//--
	// mode: "ECMA" | "RE2" | "PERL" (default)
	//--
	defer PanicHandler() // regex compile
	//--
	var matches [][]string = [][]string{}
	//--
	mode = StrToUpper(StrTrimWhitespaces(mode))
	var flags regexp2.RegexOptions
	if(mode == "PERL") {
		flags = 0 // the default flag is: 0 (.NET / Perl compatibility mode)
	} else if(mode == "ECMA") {
		flags = regexp2.ECMAScript // Javascript compatibility mode
	} else if(mode == "RE2") {
		flags = regexp2.RE2 // RE2 (regexp package) compatibility mode
	} else {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp2 Mode:", rexp, mode)
		return matches, NewError("Invalid Regexp2 Mode: `" + mode + "`")
	} //end if
	//--
	if(s == "") {
		return matches, nil
	} //end if
	//--
	var max int64 = int64(maxRecursion) // max recursion
	var isNotLimited bool = false
	if(max <= 0) {
		max = int64(REGEXP2_DEFAULT_MAX_RECURSION)
		isNotLimited = true
	} //end if
	//--
	var timeout int64 = int64(maxTimeOut) // max timeout
	if(timeout <= 0) {
		timeout = int64(REGEXP2_DEFAULT_MAX_TIMEOUT)
	} else if(timeout > 60) {
		timeout = 60
	} //end if
	//--
	re, errRx := regexp2.Compile(rexp, flags)
	if((errRx != nil) || (re == nil)) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp2 Expression, ERR:", rexp, errRx)
		return matches, NewError("Invalid Regexp2 Expression, Error")
	} //end if
	if(re == nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp2 Expression, Null:", rexp)
		return matches, NewError("Invalid Regexp2 Expression, Null")
	} //end if
	re.MatchTimeout = time.Duration(timeout) * time.Second
	//--
	m, errFind := re.FindStringMatch(s)
	var step uint64 = 0
	for {
		//--
		if(errFind != nil) {
			log.Println("[WARNING]", CurrentFunctionName(), "Regexp2 Find Failed:", rexp, errFind, "at step:", step)
			return matches, NewError("Regexp2 Find Failed")
		} //end if
		if(m == nil) {
			break
		} //end if
		//--
		g := m.Groups()
		if(g == nil) {
			log.Println("[WARNING]", CurrentFunctionName(), "Regexp2 Find Group Failed (Null):", rexp, "at step:", step)
			return matches, NewError("Regexp2 Find Group Failed, Null")
		} //end if
		if(len(g) <= 0) { // at least group 0 and group 1 should exist if is a regex match
			log.Println("[WARNING]", CurrentFunctionName(), "Regexp2 Find Group Failed (Empty):", rexp, "at step:", step)
			return matches, NewError("Regexp2 Find Group Failed, Empty")
		} //end if
		//--
		var match []string
		for i:=0; i<len(g); i++ {
			match = append(match, g[i].String())
		} //end for
		if(len(match) != len(g)) {
			log.Println("[WARNING]", CurrentFunctionName(), "Regexp2 Find Group Failed (Sync):", rexp, "at step:", step)
			return matches, NewError("Regexp2 Find Group Failed, Sync")
		} //end if
		matches = append(matches, match)
		//--
		m, errFind = re.FindNextMatch(m)
		step++
		//--
		max--
		if(max <= 0) {
			if(isNotLimited) { // if not express limited, this is an error
				log.Println("[WARNING]", CurrentFunctionName(), "Regexp2 max recursion limit forced stop ... on Expression:", rexp, "at step:", step)
				return matches, NewError("Regexp2 Max Recursion Limit")
			} else {
				return matches, nil // no error, if express limited, to emulate the exact behaviour of StrRegexFindAllMatches()
			} //end if else
			break
		} //end if
		//--
	} //end for
	//--
	if(matches == nil) {
		matches = [][]string{}
	} //end if
	//--
	return matches, nil
	//--
} //END FUNCTION


//-----


// #END
