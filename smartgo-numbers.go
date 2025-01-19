
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250118.2358 :: STABLE
// [ NUMBERS ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"fmt"

	"strconv"
	"math"
)

const (
	REGEX_STR_IS_NUMERIC_UINTEGER  = `[0-9]+`
	REGEX_STR_IS_NUMERIC_INTEGER   = `[0-9\-]+`

	REGEX_STR_IS_NUMERIC_DEFAULT  = `[0-9\.\-]+`
	REGEX_STR_IS_NUMERIC_EXTENDED = `[0-9\.\-, ]+` // includes decimal separators: , or space
)


//----- IMPORTANT: never use string(number) ... it will lead to strange situations ... use the convert methods from below


func IsInteger(s string, allowNegatives bool) bool {
	//--
	if(s == "") {
		return false
	} //end if
	//--
	if(allowNegatives) {
		return StrRegexMatch(REGEX_STR_IS_NUMERIC_INTEGER, s)
	} //end if
	//--
	return StrRegexMatch(REGEX_STR_IS_NUMERIC_UINTEGER, s)
	//--
} //END FUNCTION


func IsNumeric(s string, extended bool) bool {
	//--
	if(s == "") {
		return false
	} //end if
	//--
	if(extended) {
		return StrRegexMatch(REGEX_STR_IS_NUMERIC_EXTENDED, s)
	} //end if
	//--
	return StrRegexMatch(REGEX_STR_IS_NUMERIC_DEFAULT, s)
	//--
} //END FUNCTION


//-----


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


//-----


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


func ConvertBoolToStr(i bool) string {
	//--
	if(i == true) {
		return "1"
	} //end if
	return "0"
	//--
} //END FUNCTION


func ConvertBoolsToStr(i bool) string {
	//--
	if(i == true) {
		return "true"
	} //end if
	return "false"
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


//-----


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


//-----


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


// #END
