
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231222.1832 :: STABLE
// [ CORE ]

// REQUIRE: go 1.19 or later (depends on Go generics, available since go 1.18 but real stable since go 1.19)
package smartgo

import (
	"runtime"
	"runtime/debug"

	"errors"
	"log"
	"fmt"

	"time"
	"math"
	"bytes"
	"strings"
	"strconv"
	"regexp"
	"unicode"
	"unicode/utf8"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"

	"net/url"

	"mime"
	"html"

	"encoding/json"
	"encoding/hex"
	"encoding/base64"

	"github.com/unix-world/smartgo/base32"
	"github.com/unix-world/smartgo/base36"
	"github.com/unix-world/smartgo/base58"
	"github.com/unix-world/smartgo/base62"
	"github.com/unix-world/smartgo/base85"
	"github.com/unix-world/smartgo/base92"

	"github.com/unix-world/smartgo/regexp2"

	"github.com/unix-world/smartgo/parseini"
	"github.com/unix-world/smartgo/yaml"
	"github.com/unix-world/smartgo/xml2json"
)

const (
	VERSION string = "v.20231222.1832"
	DESCRIPTION string = "Smart.Framework.Go"
	COPYRIGHT string = "(c) 2021-2023 unix-world.org"

	CHARSET string = "UTF-8" // don't change !!

	REGEX_SAFE_APP_NAMESPACE string = `^[_a-z0-9\-\.]+$` 						// Safe App Namespace Regex
	REGEX_SMART_SAFE_NUMBER_FLOAT string = `^[0-9\-\.]+$` 						// SAFETY: SUPPORT ONLY THESE CHARACTERS IN SAFE FLOAT (ex: JSON)

	REGEXP2_DEFAULT_MAX_RECURSION uint32 = 800000 								// Default REGEXP2 Recursion Limit: 800K
	REGEXP2_DEFAULT_MAX_TIMEOUT uint8 = 1										// Default REGEXP2 Max Timeout 1 Second(s)

	TRIM_WHITESPACES string = " \t\n\r\x00\x0B" 								// PHP COMPATIBILITY

	NULL_BYTE string = "\x00" 													// THE NULL BYTE character \x00 or \000
	BACK_SPACE string = "\b" 													// The Backspace Character \b
	ASCII_BELL string = "\a" 													// The ASCII Bell Character \a
	FORM_FEED string = "\f" 													// The Form Feed Character \f or \x0C
	VERTICAL_TAB string = "\v" 													// The Vertical Tab character \v or \x0B

	HORIZONTAL_TAB string = "\t" 												// The Horizontal Tab character \t
	LINE_FEED string = "\n" 													// The Line Feed character \n
	CARRIAGE_RETURN string = "\r" 												// The Carriage Return character \r

	SIZE_BYTES_16M uint64 = 16777216 											// Reference Unit
)


//-----

var (
	DEBUG bool = false

	ini_RUN_IN_BACKGROUND bool = false // if this is set no escape characters are sent in logs (ex: supervisor capture stdout/stderr and log it with color / clear terminal escape sequences, should not appear in logs)
	ini_SMART_SOFTWARE_NAMESPACE string = "smart-framework.go" // set via AppSetNamespace
)

//-----


func AppSetRunInBackground() bool {
	//--
	ini_RUN_IN_BACKGROUND = true
	//--
	return ini_RUN_IN_BACKGROUND
	//--
} //END FUNCTION


func AppSetNamespace(ns string) bool {
	//--
	ns = StrTrimWhitespaces(ns)
	var nLen int = len(ns)
	if((nLen < 4) || (nLen > 63)) {
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo App Namespace must be between 16 and 255 caracters long ...")
		return false
	} //end if
	if(!StrRegexMatchString(REGEX_SAFE_APP_NAMESPACE, ns)) {
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo App Namespace contains invalid characters ...")
		return false
	} //end if
	//--
	ini_SMART_SOFTWARE_NAMESPACE = ns
	//--
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo App Namespace was Set to `" + ini_SMART_SOFTWARE_NAMESPACE + "`: Success")
	//--
	return true
	//--
} //END FUNCTION


func AppGetNamespace() (string, error) {
	//--
	var ns string = StrTrimWhitespaces(ini_SMART_SOFTWARE_NAMESPACE)
	//--
	var nLen int = len(ns)
	if((nLen < 4) || (nLen > 63)) {
		return "", errors.New("SmartGo App Namespace must be between 16 and 255 caracters long")
	} //end if
	if(!StrRegexMatchString(REGEX_SAFE_APP_NAMESPACE, ns)) {
		return "", errors.New("SmartGo App Namespace contains invalid characters")
	} //end if
	//--
	return ns, nil
	//--
} //END FUNCTION


//-----


func CurrentFunctionName() string {
	//--
	counter, _, _, success := runtime.Caller(1)
	//--
    if(!success) {
		return "[Unknown]"
	} //end if
	//--
	var name string = runtime.FuncForPC(counter).Name() // ex: github.com/unix-world/smartgo.CurrentFunctionName
	//--
	if(DEBUG != true) { // if no debug get just the short method name instead of full method name
		arr := Explode(".", name)
		name = arr[len(arr)-1]
	} //end if
	//--
	return name
	//--
} //END FUNCTION


//-----

// call as: defer PanicHandler()
func PanicHandler() {
	if panicInfo := recover(); panicInfo != nil {
		log.Println("[ERROR] !!! PANIC Recovered:", panicInfo, "by", CurrentFunctionName())
		if(DEBUG == true) {
			log.Println("[DEBUG] !!! PANIC Trace Stack:", string(debug.Stack()), "from", CurrentFunctionName())
		} //end if
	} //end if
} //END FUNCTION

//-----

func CreateNewError(err string) error {
	return errors.New(err)
} //END FUNCTION


//-----


func BaseEncode(data []byte, toBase string) string {
	//--
	defer PanicHandler()
	//--
	if(toBase == "b92") {
		return base92.Encode(data)
	} else if(toBase == "b85") {
		return base85.Encode(data)
	} else if(toBase == "b64s") {
		return Base64sEncode(string(data))
	} else if(toBase == "b64") {
		return Base64Encode(string(data))
	} else if(toBase == "b62") {
		return base62.Encode(data)
	} else if(toBase == "b58") {
		return base58.Encode(data)
	} else if(toBase == "b36") {
		return base36.Encode(data)
	} else if(toBase == "b32") {
		return base32.Encode(data)
	} else if((toBase == "b16") || (toBase == "hex")) { // hex (b16)
		return Bin2Hex(string(data))
	} //end if else
	//--
	log.Println("[ERROR] " + CurrentFunctionName() + ":", "Invalid Encoding Base: `" + toBase + "`")
	return ""
	//--
} //END FUNCTION


func BaseDecode(data string, fromBase string) []byte {
	//--
	defer PanicHandler() // req. by hex2bin
	//--
	var decoded []byte = nil
	var err error = nil
	//--
	if(fromBase == "b92") {
		decoded, err = base92.Decode(data)
	} else if(fromBase == "b85") {
		decoded, err = base85.Decode(data)
	} else if(fromBase == "b64s") {
		decoded = []byte(Base64sDecode(data))
	} else if(fromBase == "b64") {
		decoded = []byte(Base64Decode(data))
	} else if(fromBase == "b62") {
		decoded, err = base62.Decode(data)
	} else if(fromBase == "b58") {
		decoded, err = base58.Decode(data)
	} else if(fromBase == "b36") {
		decoded, err = base36.Decode(data)
	} else if(fromBase == "b32") {
		decoded, err = base32.Decode(data)
	} else if((fromBase == "b16") || (fromBase == "hex")) { // hex (b16)
		decoded = []byte(Hex2Bin(data))
	} else {
		err = errors.New("Invalid Decoding Base: `" + fromBase + "`")
	} //end if else
	//--
	if(err != nil) {
		log.Println("[ERROR] " + CurrentFunctionName() + ":", err)
		return nil
	} //end if
	//--
	return decoded
	//--
} //END FUNCTION


//-----


func Base64Encode(data string) string {
	//--
	return base64.StdEncoding.EncodeToString([]byte(data))
	//--
} //END FUNCTION


func Base64Decode(data string) string {
	//--
	defer PanicHandler() // req. by base64 decode panic handler with malformed data
	//--
	data = StrTrimWhitespaces(data) // required, to remove extra space like characters, go b64dec is strict !
	if(data == "") {
		return ""
	} //end if
	//--
	decoded, err := base64.StdEncoding.DecodeString(data)
	if(err != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": ", err)
		//return "" // be flexible, don't return, try to decode as much as possible ...
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


func Base64sEncode(data string) string {
	//--
	data = Base64Encode(data)
	//--
	data = StrReplaceAll(data, "+", "-")
	data = StrReplaceAll(data, "/", "_")
	data = StrReplaceAll(data, "=", ".")
	//--
	return data
	//--
} //END FUNCTION


func Base64sDecode(data string) string {
	//--
	defer PanicHandler() // req. by base64 decode panic handler with malformed data
	//--
	data = StrReplaceAll(data, ".", "=")
	data = StrReplaceAll(data, "_", "/")
	data = StrReplaceAll(data, "-", "+")
	//--
	data = Base64Decode(data)
	//--
	return data
	//--
} //END FUNCTION


func Base64ToBase64s(data string) string {
	//--
	data = StrReplaceAll(data, "+", "-")
	data = StrReplaceAll(data, "/", "_")
	data = StrReplaceAll(data, "=", ".")
	//--
	return data
	//--
} //END FUNCTION


func Base64sToBase64(data string) string {
	//--
	data = StrReplaceAll(data, ".", "=")
	data = StrReplaceAll(data, "_", "/")
	data = StrReplaceAll(data, "-", "+")
	//--
	return data
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


func InListArr[E comparable](v E, arr []E) bool { // depends on Go generics, Go 1.18 or later
	//--
	if(arr == nil) {
		return false
	} //end if
	//--
	for _, vv := range arr {
		if(v == vv) {
			return true
		} //end if
	} //end for
	//--
	return false
	//--
} //END FUNCTION


func ArrMapKeyExists[E comparable](v E, arr map[E]E) bool { // depends on Go generics, Go 1.18 or later
	//--
	if(arr == nil) {
		return false
	} //end if
	//--
	/*
	for kk, _ := range arr {
		if(v == kk) {
			return true
		} //end if
	} //end for
	//--
	return false
	*/
	//--
	_, exists := arr[v]
	//--
	return exists
	//--
} //END FUNCTION


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


func ConvertJsonNumberToStr(data interface{}) string { // after convert to string can be re-converted into int64 / float64 / ...
	//--
	return data.(json.Number).String()
	//--
} //END FUNCTION


//----- IMPORTANT: never use string(number) ... it will lead to strange situations ... use the convert methods from below


func ConvertFloat64ToStr(f float64) string {
	//--
	return strconv.FormatFloat(f, 'g', 14, 64) // use precision 14 as in PHP
	//--
} //END FUNCTION


func ConvertFloat32ToStr(f float32) string {
	//--
	return ConvertFloat64ToStr(float64(f)) // use precision 14 as in PHP
	//--
} //END FUNCTION


//--


func ConvertInt64ToStr(i int64) string {
	//--
	return strconv.FormatInt(i, 10)
	//--
} //END FUNCTION


func ConvertUInt64ToStr(i uint64) string {
	//--
	return strconv.FormatUint(i, 10)
	//--
} //END FUNCTION


func ConvertIntToStr(i int) string {
	//--
	return ConvertInt64ToStr(int64(i))
	//--
} //END FUNCTION


func ConvertUIntToStr(i uint) string {
	//--
	return ConvertUInt64ToStr(uint64(i))
	//--
} //END FUNCTION


func ConvertInt32ToStr(i int32) string {
	//--
	return ConvertInt64ToStr(int64(i))
	//--
} //END FUNCTION


func ConvertUInt32ToStr(i uint32) string {
	//--
	return ConvertUInt64ToStr(uint64(i))
	//--
} //END FUNCTION


func ConvertInt16ToStr(i int16) string {
	//--
	return ConvertInt64ToStr(int64(i))
	//--
} //END FUNCTION


func ConvertUInt16ToStr(i uint16) string {
	//--
	return ConvertUInt64ToStr(uint64(i))
	//--
} //END FUNCTION


func ConvertInt8ToStr(i int8) string {
	//--
	return ConvertInt64ToStr(int64(i))
	//--
} //END FUNCTION


func ConvertUInt8ToStr(i uint8) string {
	//--
	return ConvertUInt64ToStr(uint64(i))
	//--
} //END FUNCTION


//-----


func ParseBoolStrAsBool(s string) bool {
	//--
	s = ParseBoolStrAsStdBoolStr(s)
	//--
	if(s == "true") {
		return true
	} //end if
	return false
	//--
} //END FUNCTION


func ParseBoolStrAsStdBoolStr(s string) string {
	//--
	s = StrToLower(StrTrimWhitespaces(s))
	//--
	if((s != "") && (s != "0") && (s != "false")) { // fix PHP and Javascript as syntax if(tmp_marker_val){}
		s = "true"
	} else {
		s = "false"
	} //end if else
	//--
	return s
	//--
} //END FUNCTION


func ParseFloatStrAsDecimalStr(s string, d uint8) string {
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
	s = fmt.Sprintf("%." + ConvertUInt8ToStr(d) + "f", f)
	//--
	return string(s)
	//--
} //END FUNCTION


func ParseStrAsFloat64(s string) float64 {
	//--
	var num float64 = 0
	conv, err := strconv.ParseFloat(s, 64)
	if(err == nil) {
		num = conv
	} //end if else
	//--
	return num
	//--
} //END FUNCTION


func ParseStrAsFloat64StrFixedPrecision(s string) string {
	//--
	s = strconv.FormatFloat(ParseStrAsFloat64(s), 'g', 14, 64) // use precision 14 as in PHP
	//--
	return string(s)
	//--
} //END FUNCTION


func ParseStrAsInt64(s string) int64 {
	//--
	s = strconv.FormatFloat(math.Round(ParseStrAsFloat64(s)), 'g', 14, 64)
	//--
	var num int64 = 0
	conv, err := strconv.ParseInt(s, 10, 64)
	if(err == nil) {
		num = conv
	} //end if else
	//--
	return num
	//--
} //END FUNCTION


func ParseStrAsUInt64(s string) uint64 {
	//--
	s = strconv.FormatFloat(math.Round(ParseStrAsFloat64(s)), 'g', 14, 64)
	//--
	var num uint64 = 0
	conv, err := strconv.ParseUint(s, 10, 64)
	if(err == nil) {
		num = conv
	} //end if else
	//--
	return num
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
	//--
	return utf8.RuneCountInString(str)
	//--
} //END FUNCTION


//== PRIVATE
func isUnicodeNonspacingMarks(r rune) bool {
	//--
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
	//--
} //END FUNCTION
//==


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


func StrCreateSlug(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	s = StrDeaccent(s)
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


func UInt64ToHex(num uint64) string {
	//--
	return fmt.Sprintf("%x", num)
	//--
} //END FUNCTION


func Bin2Hex(str string) string { // inspired from: https://www.php2golang.com/
	//--
	src := []byte(str)
	encodedStr := hex.EncodeToString(src)
	//--
	return encodedStr
	//--
} //END FUNCTION


func Hex2Bin(str string) string { // inspired from: https://www.php2golang.com/
	//--
	defer PanicHandler() // req. by hex2bin panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str) // required, to remove extra space like characters, go hex2bin is strict !
	if(str == "") {
		return ""
	} //end if
	//--
	decoded, err := hex.DecodeString(str)
	if(err != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + " Failed:", err)
		//return "" // be flexible, don't return, try to decode as much as possible ...
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


//-----


func JsonEncode(data interface{}, prettyprint bool, htmlsafe bool) (string, error) {
	//-- no need any panic handler
	out := bytes.Buffer{}
	//--
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(htmlsafe)
	if(prettyprint == true) {
		encoder.SetIndent("", "    ") // 4 spaces
	} //end if
	//--
	err := encoder.Encode(data)
	if(err != nil) {
		return "", err
	} //end if
	//--
	return StrTrimWhitespaces(out.String()), nil // must trim as will add a new line at the end ...
	//--
} //END FUNCTION


func JsonNoErrChkEncode(data interface{}, prettyprint bool, htmlsafe bool) string {
	//--
	str, _ := JsonEncode(data, prettyprint, htmlsafe)
	//--
	return str
	//--
} //END FUNCTION


func JsonObjDecode(data string) (map[string]interface{}, error) { // can parse just a JSON Object as {"key1":..., "key2":...}
	//-- no need any panic handler
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return nil, nil
	} //end if
	//--
	var dat map[string]interface{}
	dataReader := strings.NewReader(data)
	decoder := json.NewDecoder(dataReader)
	decoder.UseNumber()
	err := decoder.Decode(&dat)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	return dat, nil
	//--
} //END FUNCTION


func JsonArrDecode(data string) ([]interface{}, error) { // can parse just a JSON Array as ["a", 2, "c", { "e": "f" }, ...]
	//-- no need any panic handler
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return nil, nil
	} //end if
	//--
	var dat []interface{}
	dataReader := strings.NewReader(data)
	decoder := json.NewDecoder(dataReader)
	decoder.UseNumber()
	err := decoder.Decode(&dat)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	return dat, nil
	//--
} //END FUNCTION


func JsonStrDecode(data string) (string, error) { // can parse: only a JSON String
	//-- no need any panic handler
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return "", nil
	} //end if
	//--
	var dat string = ""
	dataReader := strings.NewReader(data)
	decoder := json.NewDecoder(dataReader)
	decoder.UseNumber()
	err := decoder.Decode(&dat)
	if(err != nil) {
		return "", err
	} //end if
	//--
	return dat, nil
	//--
} //END FUNCTION


func JsonScalarDecodeToStr(data string) (string, error) { // can parse the following JSON Scalar Types: Int / Float / Bool / Null, String :: will re-map any of these as string only
	//--
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return "", nil
	} //end if
	//--
	switch(data) {
		case "NULL": fallthrough
		case "Null": fallthrough
		case "null":
			data = `""`
			break
		case "FALSE": fallthrough
		case "False": fallthrough
		case "false":
			data = `"false"`
			break
		case "TRUE": fallthrough
		case "True": fallthrough
		case "true":
			data = `"true"`
			break
		default:
			if(StrRegexMatchString(REGEX_SMART_SAFE_NUMBER_FLOAT, data)) {
				data = `"` + data + `"`
			} //end if
	} //end switch
	//--
	return JsonStrDecode(data)
	//--
} //END FUNCTION


//-----


func AddCSlashes(s string, c string) string {
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


func EscapeCss(s string) string { // CSS provides a Twig-compatible CSS escaper
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


func EscapeHtml(s string) string { // provides a Smart.Framework ~ EscapeHtml
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return html.EscapeString(s) // escapes these five characters: < > & ' "
	//--
} //END FUNCTION


func EscapeJs(in string) string { // provides a Smart.Framework ~ EscapeJs
	//-- Test
	// RAW: "1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\"'~`!@#$%^&*()+=[]{}|\\<>,.?/\t\r\n"
	// GO :  1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\u0022\u0027~`!@#$%^\u0026*()+=[]{}|\\\u003C\u003E,.?\/\t\r\n
	// PHP:  1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\u0022\u0027~`!@#$%^\u0026*()+=[]{}|\\\u003C\u003E,.?\/\t\r\n
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


func EscapeUrl(s string) string { // provides a Smart.Framework ~ EscapeUrl, an alias to RawUrlEncode
	//--
	return RawUrlEncode(s)
	//--
} //END FUNCTION


func RawUrlEncode(s string) string {
	//--
	return StrReplaceAll(url.QueryEscape(s), "+", "%20")
	//--
} //END FUNCTION


func RawUrlDecode(s string) string {
	//--
	defer PanicHandler() // req. by raw url decode panic handler with malformed data
	//--
	u, _ := url.QueryUnescape(StrReplaceAll(s, "%20", "+"))
	//--
	return u
	//--
} //END FUNCTION


func StrNl2Br(s string) string {
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


func PrettyPrintBytes(b int64) string {
	//--
	const unit int64 = 1024
	if(b < unit) {
		return fmt.Sprintf("%d B", b)
	} //end if
	div, exp := unit, 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	} //end for
	//--
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
	//--
} //END FUNCTION


//-----


func MimeTypeByFileExtension(fext string) string {
	//--
	fext = StrTrimWhitespaces(fext)
	if(fext == "") {
		return ""
	} //end if
	//--
	return mime.TypeByExtension(fext)
	//--
} //END FUNCTION


func MimeTypeByFilePath(path string) string {
	//--
	path = StrTrimWhitespaces(path)
	if(path == "") {
		return ""
	} //end if
	//--
	return MimeTypeByFileExtension(PathBaseExtension(path))
	//--
} //END FUNCTION


//-----


func IniContentParse(iniContent string, iniKeys []string) (iniMap map[string]string, errMsg string) {
	//--
	iniData, errParseIni := parseini.Load(iniContent)
	if(errParseIni != nil) {
		return nil, "INI # Parse Error: " + errParseIni.Error()
	} //end if
	//--
	var settings map[string]string = map[string]string{}
	if(iniKeys != nil) { // get all these keys ; if key does not exist will fill it with an empty string ; ex: []string where each value is "section:key"
		for i := 0; i < len(iniKeys); i++ {
			if(StrContains(iniKeys[i], ":")) {
				sk := Explode(":", iniKeys[i])
				if(len(sk) == 2) {
					sk[0] = StrTrimWhitespaces(sk[0])
					sk[1] = StrTrimWhitespaces(sk[1])
					if((sk[0] != "") && (sk[1] != "")) {
						settings[sk[0] + ":" + sk[1]] = parseini.GetIniStrVal(iniData, sk[0], sk[1])
					} //end if
				} //end if
			} //end if
		} //end for
	} else { // get all existing keys from ini
		for k, v := range iniData {
			if(v != nil) {
				for kk, _ := range v {
					settings[k + ":" + kk] = parseini.GetIniStrVal(iniData, k, kk)
				} //end for
			} //end if
		} //end for
	} //end if else
	//--
	return settings, ""
	//--
} //END FUNCTION


func YamlDataParse(yamlData string) (yamlMap map[string]interface{}, errMsg string) {
	//--
	yamlData = StrTrimWhitespaces(yamlData)
	if(yamlData == "") {
		return
	} //end if
	yamlData = StrReplaceAll(yamlData, "\r\n", "\n")
	yamlData = StrReplaceAll(yamlData, "\r", "\n")
	yamlData = StrReplaceAll(yamlData, "\t", "    ")
	//--
	errYaml := yaml.Unmarshal([]byte(yamlData), &yamlMap)
	if(errYaml != nil) {
		yamlMap = nil
		errMsg = "YAML # Parse Error: " + errYaml.Error()
		return
	} //end if
	if(yamlMap == nil) {
		errMsg = "YAML # Parse Error: Empty Structure"
		return
	} //end if
	//--
	return
	//--
} //END FUNCTION


func XmlConvertToJson(xmlData string) (string, error) {
	//--
	xml := strings.NewReader(xmlData) // xml is an io.Reader
	json, err := xml2json.Convert(xml)
	if(err != nil) {
		return "", err
	} //end if
	//--
	return json.String(), nil
	//--
} //END FUNCTION


//-----


// #END
