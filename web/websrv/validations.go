
// GO Lang :: SmartGo / Web Server / Validations :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20251216.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	smart "github.com/unix-world/smartgo"
)

const (
	REGEX_SAFE_WEB_ROUTE string = `^[_a-zA-Z0-9\-\.@,;\!\/]+$` // SAFETY: SUPPORT ONLY THESE CHARACTERS IN WEB ROUTES ... ; w3s alike ; must support everything in REGEX_SMART_SAFE_FILE_NAME except: #, includding A-Z which on register route may be disallowed
)


func WebUrlRouteIsValid(route string) bool { // just for URL Routes
	//--
	defer smart.PanicHandler()
	//--
	route = smart.StrTrimWhitespaces(route)
	//--
	if(route == "/") {
		return true // particular case
	} //end if
	//--
	if(route == "") {
		return false // must be at least slash
	} //end if
	//--
	if(!smart.StrStartsWith(route, "/")) {
		return false
	} //end if
	//--
	if(smart.IsPathAlikeWithSafeFixedPath(route, true) != true) { // need to fix trailing slashes, it is a dir path
		return false
	} //end if
	//--
	if((route == ".") || (route == "..") || (smart.StrContains(route, "..")) || (smart.StrContains(route, "\\")) || (smart.StrContains(route, ":"))) {
		return false
	} //end if
	if(smart.StrContains(route, "#")) {
		return false
	} //end if
	//--
	if(smart.PathIsBackwardUnsafe(route) == true) {
		return false
	} //end if
	//--
	if(!smart.StrRegexMatch(REGEX_SAFE_WEB_ROUTE, route)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func WebUrlPathIsValid(urlPath string) bool { // just for URL Paths, a sub-set of URL Routes
	//--
	defer smart.PanicHandler()
	//--
	if(!WebUrlRouteIsValid(urlPath)) {
		return false
	} //end if
	//--
	if(urlPath == "/") {
		return true // special case
	} //end if
	//--
	urlPath = smart.StrTrimLeft(urlPath, "/") // fix: for the test below, it filesys paths allowed must not start with a slash /
	if(!smart.PathIsWebSafeValidSafePath(urlPath)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func WebDirIsValid(path string) bool {
	//--
	defer smart.PanicHandler()
	//--
	path = smart.StrTrimWhitespaces(path)
	if(path == "") {
		return false
	} //end if
	//--
	if(!smart.PathIsWebSafeValidSafePath(path)) {
		return false
	} //end if
	//--
	if(smart.StrEndsWith(path, "/") != true) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func WebPathExists(path string) bool {
	//--
	defer smart.PanicHandler()
	//--
	path = smart.StrTrimWhitespaces(path)
	//--
	if((smart.PathIsSafeValidPath(path) != true) || (!smart.PathExists(path))) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func WebDirExists(path string) bool {
	//--
	defer smart.PanicHandler()
	//--
	path = smart.StrTrimWhitespaces(path)
	//--
	if(!WebPathExists(path)) {
		return false
	} //end if
	//--
	if(!smart.PathIsDir(path)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func WebFileExists(path string) bool {
	//--
	defer smart.PanicHandler()
	//--
	path = smart.StrTrimWhitespaces(path)
	//--
	if(!WebPathExists(path)) {
		return false
	} //end if
	//--
	if(!smart.PathIsFile(path)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


// #END
