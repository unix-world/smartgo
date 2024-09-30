
// GO Lang :: SmartGo / Web Server / Validations :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240930.1531 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	smart "github.com/unix-world/smartgo"
)

const (
	REGEX_SAFE_WEB_ROUTE string = `^[_a-zA-Z0-9\-\.@,;\!\/]+$` // SAFETY: SUPPORT ONLY THESE CHARACTERS IN WEB ROUTES ... ; w3s alike ; must support everything in REGEX_SMART_SAFE_FILE_NAME except: #, includding A-Z which on register route may be disallowed
)


func webUrlRouteIsValid(route string) bool { // just for URL Routes
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
	if(!smart.StrRegexMatchString(REGEX_SAFE_WEB_ROUTE, route)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func webUrlPathIsValid(urlPath string) bool { // just for URL Paths, a sub-set of URL Routes
	//--
	defer smart.PanicHandler()
	//--
	if(!webUrlRouteIsValid(urlPath)) {
		return false
	} //end if
	//--
	if(urlPath == "/") {
		return true // special case
	} //end if
	//--
	urlPath = smart.StrTrimLeft(urlPath, "/") // fix: for the test below, it filesys paths allowed must not start with a slash /
	if(!webPathIsValid(urlPath)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func webPathIsValid(path string) bool { // must work for dir or file
	//--
	defer smart.PanicHandler()
	//--
	path = smart.StrTrimWhitespaces(path)
	if(path == "") {
		return false
	} //end if
	//--
	if((path == ".") || (path == "./") || (path == "..") || smart.StrContains(path, "..") || smart.StrContains(path, " ") || smart.StrContains(path, "\\") || smart.StrContains(path, ":")) {
		return false
	} //end if
	//--
	if(smart.StrStartsWith(path, "/") == true) { // safety: dissalow start with / ; will be later checked for absolute path, but this is much clear to have also
		return false
	} //end if
	//--
	if(smart.IsPathAlikeWithSafeFixedPath(path, true) != true) { // need to fix trailing slashes, it can be a dir path
		return false
	} //end if
	//--
	if((smart.PathIsEmptyOrRoot(path) == true) || (smart.PathIsSafeValidPath(path) != true) || (smart.PathIsBackwardUnsafe(path) == true)) {
		return false
	} //end if
	if((smart.PathIsAbsolute(path) == true) || (smart.PathIsSafeValidSafePath(path) != true)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func webDirIsValid(path string) bool {
	//--
	defer smart.PanicHandler()
	//--
	path = smart.StrTrimWhitespaces(path)
	if(path == "") {
		return false
	} //end if
	//--
	if(!webPathIsValid(path)) {
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


func webPathExists(path string) bool {
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


func webDirExists(path string) bool {
	//--
	defer smart.PanicHandler()
	//--
	path = smart.StrTrimWhitespaces(path)
	//--
	if(!webPathExists(path)) {
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


func webFileExists(path string) bool {
	//--
	defer smart.PanicHandler()
	//--
	path = smart.StrTrimWhitespaces(path)
	//--
	if(!webPathExists(path)) {
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
