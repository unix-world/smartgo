
// GO Lang :: SmartGo / Web Server / Internals :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250207.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"sort"

	smart "github.com/unix-world/smartgo"
)


func getUrlPathSegments(urlPath string) (headPath string, tailPaths []string) {
	//--
	// algorithm: shiftPath
	//--
	headPath = ""
	tailPaths = []string{}
	//--
	urlPath = smart.StrTrimWhitespaces(smart.StrTrim(urlPath, " /"))
	if(urlPath == "") {
		return
	} //end if
	//--
	urlPath = smart.SafePathFixSeparator(urlPath)
	//--
	if(!smart.StrContains(urlPath, "/")) {
		headPath = urlPath
		return
	} //end if
	//--
	arr := smart.Explode("/", urlPath)
	if(len(arr) < 1) {
		headPath = ""
		return
	} //end if
	//--
	headPath = smart.StrTrimWhitespaces(arr[0])
	if(len(arr) > 1) {
		for i:=1; i<len(arr); i++ { // start at 1, skip headPath
			tailPaths = append(tailPaths, arr[i])
		} //end for
	} //end if
	//--
	return
	//--
} //END FUNCTION


func listActiveWebAuthProviders() []string {
	//--
	var authProviders []string = []string{}
	//--
	if(smart.AuthBasicIsEnabled() == true) {
		authProviders = append(authProviders, "Auth:Basic")
	} //end if
	if(smart.AuthTokenIsEnabled() == true) {
		authProviders = append(authProviders, "Auth:Token")
	} //end if
	if(smart.AuthCookieIsEnabled() == true) {
		authProviders = append(authProviders, "Auth:Cookie")
	} //end if
	if(smart.AuthBearerIsEnabled() == true) {
		authProviders = append(authProviders, "Auth:Bearer")
	} //end if
	if(smart.AuthApikeyIsEnabled() == true) {
		authProviders = append(authProviders, "Auth:ApiKey")
	} //end if
	//--
	return authProviders
	//--
} //END FUNCTION


func listMethods(methods []string) string {
	//--
	var options string = "OPTIONS"
	//--
	if((methods != nil) && (len(methods) > 0)) {
		sort.Strings(methods)
		for _, method := range methods {
			method = smart.StrToUpper(smart.StrTrimWhitespaces(method))
			if(method != "OPTIONS") {
				options += ", " + method
			} //end if
		} //end for
	} //end if
	//--
	return options
	//--
} //END FUNCTION


// #END
