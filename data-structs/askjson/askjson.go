
// (c) 2026-present, unix-world.org
// License: BSD
// r.20260218.2358
// the original package was modified by unixman to handle numeric string key as int and many other optimizations

// (c) 2020 Simon Nilsson
// Package ask provides a simple way of accessing nested properties in maps and arrays.
// Works great in combination with encoding/json and other packages that "Unmarshal" arbitrary data into Go data-types.
// Inspired by the get function in the lodash javascript library.
// The purpose of this go package is the need to have a safe json parser by avoid to use "unsafe" as fastjson or gjson are using ...

package askjson

import (
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"math"
	"encoding/json"
)


var digitCheck = regexp.MustCompile(`^[0-9]+$`) // unixman
var tokenMatcher = regexp.MustCompile(`([^[]+)?(?:\[(\d+)])?`)
var mapType = reflect.TypeOf(map[string]interface{}{})
var sliceType = reflect.TypeOf([]interface{}{})


// Answer holds result of call to For, use one of its methods to extract a value.
type Answer struct {
	value interface{}
}


func handleIntPart(current interface{}, part int) (interface{}, bool) {
	val := reflect.ValueOf(current)
	if val.IsValid() && val.CanConvert(sliceType) {
		s := val.Convert(sliceType).Interface().([]interface{})
		if part >= 0 && part < len(s) {
			return s[part], false
		}
	}
	return current, true
}


func handleStringPart(current interface{}, part string) (interface{}, bool) {

	notFound := false
	match := tokenMatcher.FindStringSubmatch(strings.TrimSpace(part))

	if len(match) == 3 {
		if match[1] != "" {
			val := reflect.ValueOf(current)
			if val.IsValid() && val.CanConvert(mapType) {
				current = val.Convert(mapType).Interface().(map[string]interface{})[match[1]]
			} else {
				notFound = true
			}
		}
		if match[2] != "" {
			index, _ := strconv.Atoi(match[2])
			return handleIntPart(current, index)
		}
	}

	return current, notFound
}


//-- unixman
func RootObject(source interface{}) *Answer {
	current := source
	return &Answer{value: current}
}
//-- #


// For is used to select a path from source to return as answer.
func For(source interface{}, path string) *Answer {

	parts := strings.Split(path, ".")
	notFound := false
	current := source

	for _, part := range parts {
		//-- unixman
		if digitCheck.MatchString(part) {
			index, _ := strconv.Atoi(part)
			current, notFound = handleIntPart(current, int(index))
		} else {
		//-- (original)
			current, notFound = handleStringPart(current, part)
		}
		//-- #
		if notFound {
			return &Answer{}
		}
	}

	return &Answer{value: current}
}


// ForArgs is used to select a path using individual arguments from source to return as answer.
func ForArgs(source interface{}, parts ...interface{}) *Answer {

	current := source
	notFound := false

	for _, part := range parts {
		switch vt := part.(type) {
			case uint, uint8, uint16, uint32, uint64, int, int8, int16, int32, int64:
				index := reflect.ValueOf(vt).Int()
				current, notFound = handleIntPart(current, int(index))
				if notFound {
					return &Answer{}
				}
			case string:
				//-- unixman
				if digitCheck.MatchString(vt) {
					index, _ := strconv.Atoi(vt)
					current, notFound = handleIntPart(current, int(index))
				} else {
				//-- (original)
					current, notFound = handleStringPart(current, vt)
				}
				//-- #
				if notFound {
					return &Answer{}
				}
		}
	}

	return &Answer{value: current}
}


// Path does the same thing as For but uses existing answer as source.
func (a *Answer) Get(path string) *Answer { // unixman: renamed from Path()
	return For(a.value, path)
}


// PathArgs does the same thing as ForArgs but uses existing answer as source.
func (a *Answer) GetArgs(parts ...interface{}) *Answer { // unixman: renamed from PathArgs()
	return ForArgs(a.value, parts...)
}


// Exists returns a boolean indicating if the answer exists (not nil).
func (a *Answer) Exists() bool {
	return a.value != nil
}


// Value returns the raw value as type interface{}, can be nil if no value is available.
func (a *Answer) Value() interface{} {
	return a.value
}


//-- unixman
// this can be used in circumstances where get the value as map or slice and after need to get value as string / int / ...
// it is attached to the answer object to avoid call directly askjson library in other contexts
func (a *Answer) RootObject(source interface{}) *Answer {
	current := source
	return &Answer{value: current}
}
//-- #


// Slice attempts asserting answer as a []interface{}.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) XSlice(d []interface{}) ([]interface{}, bool) {
	val := reflect.ValueOf(a.value)
	if val.IsValid() && val.CanConvert(sliceType) {
		return val.Convert(sliceType).Interface().([]interface{}), true
	}
	return d, false
}

func (a *Answer) Slice() []interface{} { // by unixman
	var d []interface{} = nil
	res, _ := a.XSlice(d)
	return res
}


// Map attempts asserting answer as a map[string]interface{}.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) XMap(d map[string]interface{}) (map[string]interface{}, bool) {
	val := reflect.ValueOf(a.value)
	if val.IsValid() && val.CanConvert(mapType) {
		return val.Convert(mapType).Interface().(map[string]interface{}), true
	}
	return d, false
}

func (a *Answer) Map() map[string]interface{} { // by unixman
	var d map[string]interface{} = nil
	res, _ := a.XMap(d)
	return res
}


// String attempts asserting answer as a string.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) XString(d string) (string, bool) {
	//-- unixman
	switch vt := a.value.(type) {
		case json.Number:
			jNum, okJNum := a.value.(json.Number)
			if(okJNum != true) {
				return d, false
			} //end if
			return jNum.String(), true
		case complex64, complex128:
			c := reflect.ValueOf(vt).Complex()
			return strconv.FormatComplex(c, 'g', 14, 128), true // use precision 14 as in PHP
		case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64: // byte is alias for uint8 ; rune is alias for int32
			f := reflect.ValueOf(vt).Float()
			return strconv.FormatFloat(f, 'g', 14, 64), true // use precision 14 as in PHP ; keep in sync with SmartGo.ConvertFloat64ToStr()
		case bool:
			b := reflect.ValueOf(vt).Bool()
			if(b == true) {
				return "true", true
			}
			return "false", true
	}
	//-- #
	str, ok := a.value.(string)
	if ok {
		return str, ok
	}
	return d, false
}

func (a *Answer) String() string { // by unixman
	var d string = ""
	res, _ := a.XString(d)
	return res
}


// Int attempts asserting answer as a int64. Casting from other number types will be done if necessary.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) XInt(d int64) (int64, bool) {
	switch vt := a.value.(type) {
		case json.Number:
			jNum, okJNum := a.value.(json.Number)
			if(okJNum != true) {
				return d, false
			} //end if
			numInt64, errInt64 := jNum.Int64()
			if(errInt64 != nil) {
				return d, false
			} //end if
			return numInt64, true
		case int, int8, int16, int32, int64:
			return reflect.ValueOf(vt).Int(), true
		case uint, uint8, uint16, uint32, uint64:
			val := reflect.ValueOf(vt).Uint()
			if val <= math.MaxInt64 {
				return int64(val), true
			}
		case float32, float64:
			val := reflect.ValueOf(vt).Float()
			if val >= math.MinInt64 && val <= math.MaxInt64 {
				return int64(val), true
			}
		//-- unixman
		case bool:
			val := reflect.ValueOf(vt).Bool()
			if(val == true) {
				return 1, true
			}
			return 0, true
		case string:
			s := reflect.ValueOf(vt).String()
			f, err := strconv.ParseFloat(s, 64)
			if(err == nil) {
				s = strconv.FormatFloat(math.Round(f), 'g', 14, 64)
				num, err2 := strconv.ParseInt(s, 10, 64)
				if(err2 == nil) {
					return num, true
				}
			}
		//-- #
	}
	return d, false
}

func (a *Answer) Int() int64 { // by unixman
	var d int64 = 0
	res, _ := a.XInt(d)
	return res
}


// Uint attempts asserting answer as a uint64. Casting from other number types will be done if necessary.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) XUint(d uint64) (uint64, bool) {
	switch vt := a.value.(type) {
		case json.Number:
			jNum, okJNum := a.value.(json.Number)
			if(okJNum != true) {
				return d, false
			} //end if
			numInt64, errInt64 := jNum.Int64()
			if(errInt64 != nil) {
				return d, false
			} //end if
			if(numInt64 < 0) {
				return d, false
			} //end if
			return uint64(numInt64), true
		case int, int8, int16, int32, int64:
			val := reflect.ValueOf(vt).Int()
			if val >= 0 {
				return uint64(val), true
			}
		case uint, uint8, uint16, uint32, uint64:
			return reflect.ValueOf(vt).Uint(), true
		case float32, float64:
			val := reflect.ValueOf(vt).Float()
			if val >= 0 && val <= math.MaxUint64 {
				return uint64(val), true
			}
		//-- unixman
		case bool:
			val := reflect.ValueOf(vt).Bool()
			if(val == true) {
				return 1, true
			}
			return 0, true
		case string:
			s := reflect.ValueOf(vt).String()
			f, err := strconv.ParseFloat(s, 64)
			if(err == nil) {
				s = strconv.FormatFloat(math.Round(f), 'g', 14, 64)
				num, err2 := strconv.ParseUint(s, 10, 64)
				if(err2 == nil) {
					return num, true
				}
			}
		//-- #
	}
	return d, false
}

func (a *Answer) Uint() uint64 { // by unixman
	var d uint64 = 0
	res, _ := a.XUint(d)
	return res
}


// Float attempts asserting answer as a float64. Casting from other number types will be done if necessary.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) XFloat(d float64) (float64, bool) {
	switch vt := a.value.(type) {
		case json.Number:
			jNum, okJNum := a.value.(json.Number)
			if(okJNum != true) {
				return d, false
			} //end if
			numFlt64, errFlt64 := jNum.Float64()
			if(errFlt64 != nil) {
				return d, false
			} //end if
			return numFlt64, true
		case int, int8, int16, int32, int64:
			return float64(reflect.ValueOf(vt).Int()), true
		case uint, uint8, uint16, uint32, uint64:
			return float64(reflect.ValueOf(vt).Uint()), true
		case float32:
			return float64(vt), true
		case float64:
			return vt, true
		//-- unixman
		case bool:
			val := reflect.ValueOf(vt).Bool()
			if(val == true) {
				return 1, true
			}
			return 0, true
		case string:
			s := reflect.ValueOf(vt).String()
			f, err := strconv.ParseFloat(s, 64)
			if(err == nil) {
				return f, true
			}
		//-- #
	}
	return d, false
}

func (a *Answer) Float() float64 { // by unixman
	var d float64 = 0
	res, _ := a.XFloat(d)
	return res
}


// Bool attempts asserting answer as a bool.
// The first return value is the result, and the second indicates if the operation was successful.
// If not successful the first return value will be set to the d parameter.
func (a *Answer) XBool(d bool) (bool, bool) {
	//-- unixman
	switch vt := a.value.(type) {
		case json.Number:
			jNum, okJNum := a.value.(json.Number)
			if(okJNum != true) {
				return d, false
			} //end if
			numFlt64, errFlt64 := jNum.Float64()
			if(errFlt64 != nil) {
				return d, false
			} //end if
			if(numFlt64 != 0) {
				return true, true
			}
			return false, true
		case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
			f := reflect.ValueOf(vt).Float()
			if(f != 0) {
				return true, true
			}
			return false, true
		case string:
			s := reflect.ValueOf(vt).String()
			if(s != "") {
				return true, true
			}
			return false, true
	}
	//-- #
	res, ok := a.value.(bool)
	if ok {
		return res, ok
	}
	return d, false
}

func (a *Answer) Bool() bool { // by unixman
	var d bool = false
	res, _ := a.XBool(d)
	return res
}


// #end
