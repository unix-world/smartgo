
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260111.2358 :: STABLE
// [ BYTES ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"bytes"
	"unicode/utf8"

	"regexp"
)


//-----


func BytesConcatenate(src1 []byte, src2 []byte) []byte {
	//--
	if((src1 == nil) && (src2 == nil)) {
		return nil
	} else if(src1 == nil) {
		return src2
	} else if(src2 == nil) {
		return src1
	} //end if
	//--
	return append(src1, src2...)
	//--
} //END FUNCTION


func BytesEqual(src1 []byte, src2 []byte) bool { // compare equality between 2 []byte slices, case sensitive ; ; ex: []byte("go") is equivalent with []byte("go")
	//--
	return bytes.Equal(src1, src2)
	//--
} //END FUNCTION


func BytesIEqual(src1 []byte, src2 []byte) bool { // compare equality between 2 []byte slices, case insensitive ; ex: []byte("Go") is equivalent with []byte("go")
	//--
	return bytes.EqualFold(src1, src2)
	//--
} //END FUNCTION


//-----


func BExplodeWithLimit(delimiter []byte, src []byte, limit int) [][]byte {
	//--
	expl := bytes.SplitN(src, delimiter, limit)
	//--
	if(expl == nil) {
		expl = [][]byte{}
	} //end if
	//--
	return expl
	//--
} //END FUNCTION


func BExplode(delimiter []byte, src []byte) [][]byte {
	//--
	expl := bytes.Split(src, delimiter)
	//--
	if(expl == nil) {
		expl = [][]byte{}
	} //end if
	//--
	return expl
	//--
} //END FUNCTION


func BImplode(glue []byte, pieces [][]byte) []byte {
	//--
	if(pieces == nil) {
		return nil
	} //end if
	if(len(pieces) <= 0) {
		return nil
	} //end if
	//--
	return bytes.Join(pieces, glue)
	//--
} //END FUNCTION

//-----


// case sensitive, find position of first occurrence of a byte slice in another byte slice ; PHP compatible
// return -1 if can not find the substring or the position of needle in haystack
func BytPos(haystack []byte, needle []byte, binary bool) int {
	//--
	// for PHP compatibility (multi-byte safe), use: binary = false
	//--
	// Benchmark: use BytStartsWith() which is much faster instead of this to test if a byte slice starts with some part
	//--
	if((haystack == nil) || (needle == nil)) {
		return -1
	} //end if
	//--
	pos := bytes.Index(haystack, needle) // -1 if needle is not present in haystack
	//--
	if(pos < 0) {
		return -1 // make it standard return
	} //end if
	//--
	if(binary == true) {
		return pos
	} //end if
	//--
	rs := []rune(string(haystack[0:pos]))
	//--
	return len(rs)
	//--
} //END FUNCTION


// case insensitive, find position of first occurrence of a byte slice in another byte slice ; PHP compatible
// return -1 if can not find the substring or the position of needle in haystack
func BytIPos(haystack []byte, needle []byte, binary bool) int {
	//--
	// for PHP compatibility (multi-byte safe), use: binary = false
	//--
	// Benchmark: use BytIStartsWith() which is much faster instead of this to test if a string starts with some part
	//--
	return BytPos(BytToLower(haystack), BytToLower(needle), binary)
	//--
} //END FUNCTION


// case sensitive, find position of last occurrence of a byte slice in another byte slice ; PHP compatible
// return -1 if can not find the substring or the position of needle in haystack
func BytRPos(haystack []byte, needle []byte, binary bool) int {
	//--
	// for PHP compatibility (multi-byte safe), use: binary = false
	//--
	// Benchmark: use BytEndsWith() which is much faster instead of this to test if a string ends with some part
	//--
	if((haystack == nil) || (needle == nil)) {
		return -1
	} //end if
	//--
	pos := bytes.LastIndex(haystack, needle) // -1 if needle is not present in haystack
	//--
	if(pos < 0) {
		return -1 // make it standard return
	} //end if
	//--
	if(binary == true) {
		return pos
	} //end if
	//--
	rs := []rune(string(haystack[0:pos]))
	//--
	return len(rs)
	//--
} //END FUNCTION


// case insensitive, find position of last occurrence of a byte slice in another byte slice ; PHP compatible
// return -1 if can not find the substring or the position of needle in haystack
func BytRIPos(haystack []byte, needle []byte, binary bool) int {
	//--
	// for PHP compatibility (multi-byte safe), use: binary = false
	//--
	// Benchmark: use BytIEndsWith() which is much faster instead of this to test if a string ends with some part
	//--
	return BytRPos(BytToLower(haystack), BytToLower(needle), binary)
	//--
} //END FUNCTION


//-----


func BytStartsWith(src []byte, part []byte) bool {
	//--
	return bytes.HasPrefix(src, part)
	//--
} //END FUNCTION


func BytIStartsWith(src []byte, part []byte) bool {
	//--
	return bytes.HasPrefix(BytToLower(src), BytToLower(part))
	//--
} //END FUNCTION


func BytEndsWith(src []byte, part []byte) bool {
	//--
	return bytes.HasSuffix(src, part)
	//--
} //END FUNCTION


func BytIEndsWith(src []byte, part []byte) bool {
	//--
	return bytes.HasSuffix(BytToLower(src), BytToLower(part))
	//--
} //END FUNCTION


//-----


func BytContains(src []byte, part []byte) bool {
	//--
	return bytes.Contains(src, part)
	//--
} //END FUNCTION


func BytIContains(src []byte, part []byte) bool {
	//--
	return bytes.Contains(BytToLower(src), BytToLower(part))
	//--
} //END FUNCTION


//-----


func BytTrim(src []byte, cutset string) []byte {
	//--
	if(src == nil) {
		return nil
	} //end if
	//--
	return bytes.Trim(src, cutset)
	//--
} //END FUNCTION


func BytTrimLeft(src []byte, cutset string) []byte {
	//--
	if(src == nil) {
		return nil
	} //end if
	//--
	return bytes.TrimLeft(src, cutset)
	//--
} //END FUNCTION


func BytTrimRight(src []byte, cutset string) []byte {
	//--
	if(src == nil) {
		return nil
	} //end if
	//--
	return bytes.TrimRight(src, cutset)
	//--
} //END FUNCTION


func BytTrimWhitespaces(s []byte) []byte {
	//--
	return BytTrim(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


func BytTrimLeftWhitespaces(s []byte) []byte {
	//--
	return BytTrimLeft(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


func BytTrimRightWhitespaces(s []byte) []byte {
	//--
	return BytTrimRight(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


//-----


func BytSubstr(s []byte, start int, stop int) []byte {
	//--
	if(s == nil) {
		return nil
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
		return nil
	} //end if
	//--
	return s[start:stop]
	//--
} //END FUNCTION


//-----


func BytToLower(src []byte) []byte {
	//--
	if(src == nil) {
		return nil
	} //end if
	//--
	return bytes.ToLower(src)
	//--
} //END FUNCTION


func BytToUpper(src []byte) []byte {
	//--
	if(src == nil) {
		return nil
	} //end if
	//--
	return bytes.ToUpper(src)
	//--
} //END FUNCTION


//-----


func BytRepeat(src []byte, count int) []byte {
	//--
	if(src == nil) {
		return nil
	} //end if
	if(count <= 0) {
		return nil
	} //end if
	//--
	return bytes.Repeat(src, count)
	//--
} //END FUNC


//-----


func BytToValidUTF8Fix(src []byte) []byte {
	//--
	if(src == nil) {
		return nil
	} //end if
	//--
	return bytes.ToValidUTF8(src, []byte(INVALID_CHARACTER))
	//--
} //END FUNCTION


//-----


func BytTr(src []byte, replace map[string][]byte) []byte {
	//--
	if((len(replace) <= 0) || (len(src) <= 0)) {
		return src
	} //end if
	//--
	for old, new := range replace {
		src = bytes.ReplaceAll(src, []byte(old), new)
	} //end for
	//--
	return src
	//--
} //END FUNCTION


// case sensitive replacer
func BytReplaceWithLimit(src []byte, part []byte, replacement []byte, limit int) []byte {
	//--
	return bytes.Replace(src, part, replacement, limit) // if (limit == -1) will replace all
	//--
} //END FUNCTION


// case sensitive replacer
func BytReplaceAll(src []byte, part []byte, replacement []byte) []byte {
	//--
//	return bytes.ReplaceAll(src, part, replacement)
	return BytReplaceWithLimit(src, part, replacement, -1)
	//--
} //END FUNCTION


// case insensitive replacer
func BytIReplaceWithLimit(s []byte, part []byte, replacement []byte, limit int) []byte {
	//--
	if(s == nil) {
		return nil
	} //end if
	if((part == nil) || (BytesEqual(part, replacement) == true)) {
		return s // avoid allocation
	} //end if
	//--
	t := bytes.ToLower(s)
	o := bytes.ToLower(part)
	//-- compute number of replacements
	n := bytes.Count(t, o)
	if((n == 0) || (limit == 0)) {
		return s // avoid allocation
	} //end if
	if(limit < 0) {
		limit = n
	} //end if
	//-- apply replacements to buffer
	var b bytes.Buffer
	b.Grow(len(s) + n * (len(replacement) - len(part)))
	start := 0
	for i := 0; i < n; i++ {
		j := start
		if(len(part) == 0) {
			if(i > 0) {
				_, wid := utf8.DecodeRune(s[start:])
				j += wid
			} //end if
		} else {
			j += bytes.Index(t[start:], o)
		} //end if else
		b.Write(s[start:j])
		b.Write(replacement)
		start = j + len(part)
		if(i >= (limit - 1)) {
			break
		} //end if
	} //end for
	b.Write(s[start:])
	//--
	return b.Bytes()
	//--
} //END FUNCTION


// case insensitive replacer
func BytIReplaceAll(s []byte, part []byte, replacement []byte) []byte {
	//--
	return BytIReplaceWithLimit(s, part, replacement, -1)
	//--
} //END FUNCTION


//-----


// PHP strlen()
func BytLen(src []byte) int {
	//--
	return len(src)
	//--
} //END FUNCTION


//-----


func BytRegexCallbackReplaceWithLimit(rexpr string, src []byte, replFx func(mgroups [][]byte) []byte, limit int) []byte {
	//--
	defer PanicHandler() // regex compile
	//--
	// this method is a modified blend, inspired from the following source code:
	// https://github.com/agext/regexp # License: Apache 2.0
	// https://gist.github.com/slimsag/14c66b88633bd52b7fa710349e4c6749 # License: MIT
	//--
	if(src == nil) {
		return nil
	} //end if
	//--
	re, errRx := regexp.Compile(rexpr)
	if((errRx != nil) || (re == nil)) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp Expression", rexpr, errRx)
		return nil
	} //end if
	//--
	if(replFx == nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Regexp Replace Function is Null", rexpr)
		return src
	} //end if
	//--
	var result []byte = nil
	lastIndex := 0
	matches := re.FindAllSubmatchIndex(src, limit)
	for _, v := range matches {
		var groups [][]byte
		for i := 0; i < len(v); i += 2 {
			if v[i] == -1 || v[i+1] == -1 {
				groups = append(groups, []byte(""))
			} else {
				groups = append(groups, src[v[i]:v[i+1]])
			} //end if else
		} //end for
		result = append(result, src[lastIndex:v[0]]...)
		result = append(result, replFx(groups)...)
		lastIndex = v[1]
	} //end for
	//--
	result = append(result, src[lastIndex:]...)
	//--
	return result
	//--
} //END FUNCTION


func BytRegexCallbackReplaceAll(rexpr string, src []byte, replFx func(mgroups [][]byte) []byte) []byte {
	//--
	defer PanicHandler() // regex compile
	//--
	return BytRegexCallbackReplaceWithLimit(rexpr, src, replFx, -1)
	//--
} //END FUNCTION


func BytRegexReplaceAll(rexpr string, s []byte, repl []byte) []byte {
	//--
	defer PanicHandler() // regex compile
	//--
	if(s == nil) {
		return nil
	} //end if
	//--
	re, errRx := regexp.Compile(rexpr)
	if((errRx != nil) || (re == nil)) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp Expression", rexpr, errRx)
		return nil
	} //end if
	//--
	return re.ReplaceAll(s, repl)
	//--
} //END FUNCTION


func BytRegexReplaceFirst(rexpr string, s []byte, repl []byte) []byte {
	//--
	defer PanicHandler() // regex compile
	//--
	if(s == nil) {
		return nil
	} //end if
	//--
	matches, err := BytRegexFindFirstMatch(rexpr, s)
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "ERR:", rexpr, err)
		return nil
	} //end if
	//--
	if(len(matches) > 0) {
		s = BytReplaceWithLimit(s, matches[0], repl, 1)
	} //end if
	//--
	return s
	//--
} //END FUNCTION


func BytRegexMatch(rexpr string, s []byte) bool {
	//--
	defer PanicHandler() // regex compile
	//--
	if(s == nil) {
		return false
	} //end if
	//--
	matched, errRx := regexp.Match(rexpr, s)
	if(errRx != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Invalid Regexp Expression", rexpr, errRx)
		return false
	} //end if
	//--
	return matched
	//--
} //END FUNCTION


func BytRegexFindFirstMatch(rexp string, s []byte) ([][]byte, error) {
	//--
	defer PanicHandler() // regex compile
	//--
	var match [][]byte = [][]byte{}
	//--
	if(s == nil) {
		return match, nil
	} //end if
	//--
	matches, err := BytRegexFindAllMatches(rexp, s, 1)
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


func BytRegexFindAllMatches(rexp string, s []byte, maxRecursion uint32) ([][][]byte, error) {
	//--
	defer PanicHandler() // regex compile
	//--
	var matches [][][]byte = [][][]byte{}
	//--
	if(s == nil) {
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
	matches = re.FindAllSubmatch (s, max)
	if(matches == nil) {
		matches = [][][]byte{}
	} //end if
	//--
	return matches, nil
	//--
} //END FUNCTION


//-----


// #END
