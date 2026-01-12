
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260111.2358 :: STABLE
// [ SMART.CORE ]

// REQUIRE: go 1.22 or later (depends on Go generics, available since go 1.18 but stable only since go 1.19)
package smartgo

import (
	"log"
	"errors"

	"strings"

	"runtime"
	"runtime/debug"
)

const (
	VERSION string = "v.20260111.2358"
	NAME string = "SmartGo"

	DESCRIPTION string = "Smart.Framework.Go"
	COPYRIGHT string = "(c) 2021-present unix-world.org"

	CHARSET string = "UTF-8" 						// DO NOT CHANGE !! This is mandatory ...
	INVALID_CHARACTER string = "\uFFFD" 			// Invalid UTF-8 character that will be used for UTF-8 Valid Fix: �

	NULL_BYTE string = "\x00" 						// THE NULL BYTE character \x00 or \000
	BACK_SPACE string = "\b" 						// The Backspace Character \b
	ASCII_BELL string = "\a" 						// The ASCII Bell Character \a
	FORM_FEED string = "\f" 						// The Form Feed Character \f or \x0C
	VERTICAL_TAB string = "\v" 						// The Vertical Tab character \v or \x0B

	HORIZONTAL_TAB string = "\t" 					// The Horizontal Tab character \t
	LINE_FEED string = "\n" 						// The Line Feed character \n
	CARRIAGE_RETURN string = "\r" 					// The Carriage Return character \r

	TRIM_WHITESPACES string = " \t\n\r\x00\x0B" 	// Ultra Wide Compatibility (Javascript / PHP)

	REGEX_ASCII_NOSPACE_CHARACTERS 		string = `^[[:graph:]]+$` 			// match all ASCII safe printable characters except spaces ; [[:graph:]] is equivalent to [[:alnum:][:punct:]]
	REGEX_ASCII_ANDSPACE_CHARACTERS 	string = `^[[:graph:] \t\r\n]+$` 	// match all ASCII safe printable characters ; allow extra safe spaces only: space, tab, line feed, carriage return
	REGEX_ASCII_PRINTABLE_CHARACTERS 	string = `^[[:print:]]+$` 			// match all ASCII printable characters [[:print:]] is equivalent to [[:graph:][:whitespace:]] ; [:whitespace:] match a whitespace character such as space, tab, formfeed, and carriage return
)


//-----

var (
	DEBUG bool = false
)


//-----


func CurrentRuntimeVersion() string {
	//--
	var rt string = runtime.Version() // ex: go1.22.8
	//--
	rt = strings.ToLower(strings.TrimSpace(rt))
	//--
	if(rt == "") {
		rt = "go0.0"
	} //end if
	//--
	return rt
	//--
} //END FUNCTION


//-----


func CurrentOSName() string {
	//--
	var os string = runtime.GOOS // ex: openbsd
	//--
	os = strings.ToLower(strings.TrimSpace(os))
	//--
	if(os == "") {
		os = "unknown-os"
	} //end if
	//--
	return os
	//--
} //END FUNCTION

// see the complete list of supported combination of OS / ARCH: `go tool dist list | column -c 75 | column -t`

func CurrentOSArch() string {
	//--
	var arch string = runtime.GOARCH // ex: amd64
	//--
	arch = strings.ToLower(strings.TrimSpace(arch))
	//--
	if(arch == "") {
		arch = "unknown-arch"
	} //end if
	//--
	return arch
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
	var name string = runtime.FuncForPC(counter).Name() // ex: `main.SomeMethod` or `github.com/unix-world/smartgo.CurrentFunctionName`
	//--
	if(strings.Contains(name, "/")) { // if similar ~ with `github.com/unix-world/smartgo.CurrentFunctionName`
		arr := strings.Split(name, "/")
		if(len(arr) > 0) {
			name = arr[len(arr)-1] // get just the package.MethodName part if have more parts
		} //end if
	} //end if
	//--
	return name // returns: package.MethodName
	//--
} //END FUNCTION


//-----


func NewError(err string) error {
	//--
	return errors.New(err)
	//--
} //END FUNCTION


//-----


// call as: defer PanicHandler()
func PanicHandler() {
	if panicInfo := recover(); panicInfo != nil {
		log.Println("[ERROR] !!! PANIC Recovered:", panicInfo, "by", CurrentFunctionName())
		log.Println("[PANIC] !!! Debug Stack Trace:", string(debug.Stack()), "from", CurrentFunctionName())
	} //end if
} //END FUNCTION


//-----


func MemoryStats() runtime.MemStats {
	//--
	var memStats runtime.MemStats
	//--
	runtime.ReadMemStats(&memStats)
	//--
	return memStats
	//--
} //END FUNCTION


//-----


func InListArr[C comparable](v C, arr []C) bool { // depends on Go generics, Go 1.18 or later
	//--
	// supports the following simple list types such as []%scalar%:
	// []string
	// []int,  []int8,  []int16,  []int32,  []int64
	// []uint, []uint8, []uint16, []uint32, []uint64
	// []float32, []float64
	// []bool
	//--
	if(arr == nil) {
		return false
	} //end if
	if(len(arr) <= 0) {
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


func ArrMapKeyExists[C comparable, A any](v C, arr map[C]A) bool { // depends on Go generics, Go 1.18 or later
	//--
	// supports any type of map[%scalar%]*
	//--
	if(arr == nil) {
		return false
	} //end if
	if(len(arr) <= 0) {
		return false
	} //end if
	//--
	_, exists := arr[v]
	//--
	return exists
	//--
} //END FUNCTION


//-----


func ArrMapStrFlip(m map[string]string) map[string]string {
	//--
	if(len(m) <= 0) {
		return m
	} //end if
	//--
	n := make(map[string]string, len(m))
	//--
	for k, v := range m {
		n[v] = k
	} //end for
	//--
	return n
	//--
} //END FUNCTION


//-----

// converts list `<one>, <two>` to arr['one', 'two']
func SmartListToArr(list string, noSpaces bool) []string {
	//--
	var arr []string = []string{}
	//--
	list = strings.Trim(list, TRIM_WHITESPACES)
	if(list == "") {
		return arr
	} //end if
	//--
	exArr := strings.Split(list, ",") // explode
	if((exArr == nil) || (len(exArr) <= 0)) {
		return arr
	} //end if
	//--
	for i:=0; i<len(exArr); i++ {
		//--
		var val string = exArr[i]
		//--
		val = strings.Trim(val, TRIM_WHITESPACES) // must trim outside <> entries because was exploded by ',' and list can be also ', '
		//--
		val = strings.ReplaceAll(val, "<", "")
		val = strings.ReplaceAll(val, ">", "")
		//--
		if(noSpaces != false) {
			val = strings.Trim(val, TRIM_WHITESPACES) // trim <> inside values only if explicit required (otherwise preserve inside spaces)
		} //end if
		//--
		if(strings.Trim(val, TRIM_WHITESPACES) != "") {
			if(!InListArr(val, arr)) {
				arr = append(arr, val)
			} //end if
		} //end if
		//--
	} //end for
	//--
	return arr
	//--
} //END FUNCTION


// converts arr['one', 'two'] to list `<one>, <two>`
func SmartArrToList(arr []string, sepSpaces bool) string {
	//--
	if(arr == nil) {
		return ""
	} //end if
	if(len(arr) <= 0) {
		return ""
	} //end if
	//--
	var safeArr []string = []string{}
	for i:=0; i<len(arr); i++ {
		//--
		var val string = arr[i]
		//-- must not do strtolower as it is used to store both cases
		val = strings.Trim(val, TRIM_WHITESPACES)
		//-- {{{SYNC-SMARTLIST-BRACKET-REPLACEMENTS}}}
		val = strings.ReplaceAll(val, "<", "‹")
		val = strings.ReplaceAll(val, ">", "›")
		//-- fix just on value
		val = strings.ReplaceAll(val, ",", ";")
		//--
		var listVal string = "<" + val + ">"
		if(!InListArr(listVal, safeArr)) {
			safeArr = append(safeArr, listVal)
		} //end if
		//--
	} //end for
	//--
	if(len(safeArr) <= 0) {
		return ""
	} //end if
	//--
	var glue string = ","
	if(sepSpaces) {
		glue = ", "
	} //end if
	//--
	return strings.Join(safeArr, glue) // implode
	//--
} //END FUNCTION


//-----


// #END
