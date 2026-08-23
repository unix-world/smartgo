
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260823.2358 :: STABLE
// [ NUMBERS ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"fmt"

	"strconv"
	"math"
	"math/big"
)

const (
	REGEX_STR_IS_NUMERIC_UINTEGER  = `[0-9]+`
	REGEX_STR_IS_NUMERIC_INTEGER   = `[0-9\-]+`

	REGEX_STR_IS_NUMERIC_DEFAULT  = `[0-9\.\-]+`
	REGEX_STR_IS_NUMERIC_EXTENDED = `[0-9\.\-, ]+` // includes decimal separators: , or space
)


//----- IMPORTANT:
// never use string(number) ... it will lead to strange situations ... use the convert methods from below
// cast to float types before divisions or complicated calculations between numbers ... strange results may happen if not !


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


func ConvertBoolToUInt8(i bool) uint8 {
	//--
	if(i == true) {
		return 1
	} //end if
	return 0
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


func Float64ToMaxDecimals(num float64, d uint8) float64 { // converts a float64 number to max decimals, not fixed ; for float64 keeping 0 trailing decimal (fixed decimals) is not possible
	//--
	// this method should be used just for display, it is not safe for arithmetics in combination with other Go methods, it uses Rounds Half Up as in PHP
	//--
	if(d < 1) {
		d = 1
	} else if(d > 8) {
		d = 8
	} //end if else
	//--
	factor := math.Pow(10, float64(d))
	if(factor <= 0) {
		return 0 // safety check: avoid below division by zero
	} //end if
	//--
//	return float64(int(num * factor + math.Copysign(0.5,        num * factor))) / factor // Go  Compatible, HalfDown  1.005 = 1.00 or 1
	return float64(int(num * factor + math.Copysign(0.50000001, num * factor))) / factor // PHP Compatible, HalfUp    1.005 = 1.01 ; {{{SYNC-ROUND-HALF-UP-AS-PHP}}}
	//--
} //END FUNCTION


func Float64StrToMaxDecimalsStr(s string, d uint8) string { // converts a float64 string to max decimals, not fixed
	//--
	// this method should be used just for display, it is not safe for arithmetics in combination with other Go methods, it uses Rounds Half Up as in PHP
	//--
	if(d < 1) {
		d = 1
	} else if(d > 8) {
		d = 8
	} //end if else
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		s = "0"
	} //end if
	//--
	ss := Float64StrToFixedDecimalsStr(s, d) // PHP Compatible, HalfUp    1.005 = 1.01 ; {{{SYNC-ROUND-HALF-UP-AS-PHP}}}
	//--
	s = StrTrimRight(StrTrimRight(ss, "0"), ".")
	if(s == "") {
		s = "0"
	} //end if
	//--
	return s
	//--
} //END FUNCTION


func Float64StrToFixedDecimalsStr(s string, d uint8) string { // converts a float64 string to fixed decimals, not fixed
	//--
	// this method should be used just for display, it is not safe for arithmetics in combination with other Go methods, it uses Rounds Half Up as in PHP
	//--
	if(d < 1) {
		d = 1
	} else if(d > 8) {
		d = 8
	} //end if else
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		s = "0"
	} //end if
	//--
	factor := math.Pow(10, float64(d))
	if(factor <= 0) {
		return "0" // safety check: avoid below division by zero
	} //end if
	//--
	xf, _, err := big.ParseFloat(s, 10, 53, big.ToNearestEven) // only use 53 bits of precision (float64)
	if(err != nil) {
		return "0"
	} //end if
	fixed, _ := new(big.Float).Mul(xf, big.NewFloat(factor)).Float64()
//	var num float64 = math.Round(fixed) / factor 				// Go  Compatible, HalfDown  1.005 = 1.00 or 1
	var num float64 = Float64ToMaxDecimals(fixed / factor, d) 	// PHP Compatible, HalfUp    1.005 = 1.01 ; {{{SYNC-ROUND-HALF-UP-AS-PHP}}}
	//--
	s = ConvertFloat64ToStr(num)
	//--
	if(StrContains(s, ".") != true) {
		s += "."
	} //end if
	arr := Explode(".", s)
	if(len(arr) < 1) {
		arr[0] = "0"
	} //end if
	if(len(arr) < 2) {
		arr[1] = ""
	} //end if
	arr[1] = StrPad2LenRight(arr[1], "0", int(d))
	s = Implode(".", arr)
	//--
	return s
	//--
} //END FUNCTION


//-----


func NumberFormat(strNum string, decimals uint8, decPoint string, thousandsSep string) string {
	//--
	// this method should be used just for display, it is not safe for arithmetics in combination with other Go methods, it uses Rounds Half Up as in PHP
	//--
	strNum = StrTrimWhitespaces(strNum)
	if(strNum == "") {
		strNum = "0"
	} //end if
	//--
	var origDecimals uint8 = decimals
	if(decimals < 1) {
		decimals = 1
	} else if(decimals > 8) {
		decimals = 8
	} //end if else
	//--
	decPoint = StrTrimWhitespaces(decPoint)
	if(len(decPoint) != 1) {
		decPoint = "."
	} //end if
	//--
//	thousandsSep = StrTrimWhitespaces(thousandsSep) // do not trim, can be a space !
	if(len(thousandsSep) > 1) {
		thousandsSep = ""
	} //end if
	//--
	if(decPoint == thousandsSep) {
		thousandsSep = ""
	} //end if
	//--
	ss := Float64StrToFixedDecimalsStr(strNum, decimals) // PHP Compatible, HalfUp    1.005 = 1.01 ; {{{SYNC-ROUND-HALF-UP-AS-PHP}}}
	//--
	if(thousandsSep != "") {
		//--
		if(StrContains(ss, ".") != true) {
			ss += "."
		} //end if
		arr := Explode(".", ss)
		if(len(arr) < 1) {
			arr[0] = "0"
		} //end if
		if(len(arr) < 2) {
			arr[1] = ""
		} //end if
		//--
		var rvs string = StrRev(arr[0])
		var nst string = ""
		for i := 0; i < len(rvs); i++ {
			s := StrSubstr(rvs, i, i+1)
			nst += s
			if((i % 3) == 2) {
				nst += thousandsSep
			} //end if
		} //end for
		nst = StrTrimRight(nst, thousandsSep)
		arr[0] = StrRev(nst)
		//--
		if(origDecimals <= 0) {
			arr[1] = ""
		} //end if
		//--
		ss = Implode(".", arr)
		ss = StrTrimRight(ss, ".")
		//--
	} //end if
	//--
	return ss
	//--
} //END FUNCTION


// #END
