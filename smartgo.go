
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241129.2358 :: STABLE
// [ SMART.CORE ]

// REQUIRE: go 1.22 or later (depends on Go generics, available since go 1.18 but real stable only since go 1.19)
package smartgo

import (
	"log"
	"errors"

	"runtime"
	"runtime/debug"
)

const (
	VERSION string = "v.20241129.2358"
	NAME string = "SmartGo"

	DESCRIPTION string = "Smart.Framework.Go"
	COPYRIGHT string = "(c) 2021-2024 unix-world.org"

	CHARSET string = "UTF-8" 						// DO NOT CHANGE !! This is mandatory ...

	NULL_BYTE string = "\x00" 						// THE NULL BYTE character \x00 or \000
	BACK_SPACE string = "\b" 						// The Backspace Character \b
	ASCII_BELL string = "\a" 						// The ASCII Bell Character \a
	FORM_FEED string = "\f" 						// The Form Feed Character \f or \x0C
	VERTICAL_TAB string = "\v" 						// The Vertical Tab character \v or \x0B

	HORIZONTAL_TAB string = "\t" 					// The Horizontal Tab character \t
	LINE_FEED string = "\n" 						// The Line Feed character \n
	CARRIAGE_RETURN string = "\r" 					// The Carriage Return character \r

	TRIM_WHITESPACES string = " \t\n\r\x00\x0B" 	// Ultra Wide Compatibility (Javascript / PHP)
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
	rt = StrToLower(StrTrimWhitespaces(rt))
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
	os = StrToLower(StrTrimWhitespaces(os))
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
	arch = StrToLower(StrTrimWhitespaces(arch))
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
	if(StrContains(name, "/")) { // if similar ~ with `github.com/unix-world/smartgo.CurrentFunctionName`
		arr := Explode("/", name)
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


func InListArr[E comparable](v E, arr []E) bool { // depends on Go generics, Go 1.18 or later
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


func ArrMapKeyExists[E comparable](v E, arr map[E]E) bool { // depends on Go generics, Go 1.18 or later
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


// #END
