
// GO Lang :: SmartGo / Web Server / Routing :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260823.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"sort"

	smart "github.com/unix-world/smartgo"
)


type GetParam struct {
	Optional bool   `json:"optional,omitempty"`
	Value    string `json:"value"`
}

type PostParam struct {
	Optional bool   `json:"optional,omitempty"`
	Type     string `json:"type"` // "var" | "file"
	Value    string `json:"value"`
}

type ApiRouteType = struct {
	Method 		string               `json:"method"`
	Output 		string               `json:"output"`
	UrlParams 	map[string]GetParam  `json:"urlParams,omitempty"`
	PostParams 	map[string]PostParam `json:"postParams,omitempty"`
}


func GetNamedRoutes() map[string]string {
	//--
	if(urlNamedRoutesMap == nil) {
		return map[string]string{}
	} //end if
	//--
	return urlNamedRoutesMap
	//--
} //END FUNCTION


func UrlHandlerRegisterNamedRoute(name string, route string) bool {
	//--
	var isOK bool = false
	//--
	name = smart.StrTrimWhitespaces(name)
	if(name != "") {
		urlNamedRoutesMap[route] = name // use the URL as key to avoid duplicates
		isOK = true
	} //end if
	//--
	return isOK
	//--
} //END FUNCTION


func UrlHandlerRegisterRoute(route string, skipAuth bool, methods []string, maxTailSegments int, fxHandler HttpHandlerFunc) bool {
	//--
	defer smart.PanicHandler()
	//--
	if(handlersAreLocked == true) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), msgErrHandlersLocked, "Route: `" + route + "`")
		return false
	} //end if
	//--
	handlersWriteMutex.Lock()
	defer handlersWriteMutex.Unlock()
	//--
	route = smart.StrTrimWhitespaces(route)
	if(route == "") {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Route: Empty")
		return false
	} //end if
	//--
	if(!WebUrlRouteIsValid(route)) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Route: Contains Invalid or Unsafe Characters: `" + route + "`")
		return false
	} //end if
	//--
	if(!smart.StrStartsWith(route, "/")) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Route: Must Start with a `/` Slash: `" + route + "`")
		return false
	} //end if
	if(route != "/") {
		if(smart.StrEndsWith(route, "/")) { // {{{SYNC-PATH-FROM-SLASH-REDIRECT}}} ; this in combination
			log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Route: Must NOT End with a `/` Slash, except Web Root, which is always `/`: `" + route + "`")
			return false
		} //end if
	} //end if
	//--
	if((route == webDavUrlPath()) || (smart.StrStartsWith(route, webDavUrlPath()+"/"))) { // {{{SYNC-WEBSRV-ROUTE-WEBDAV}}}
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Route: Disallowed (Reserved for WebDAV Service): `" + route + "`")
		return false
	} //end if
	//--
	if((route == "/lib") || smart.StrStartsWith(route, "/lib/")) { // reserved for assets
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Route: Disallowed (Reserved for Assets): `" + route + "`")
		return false
	} //end if
	//--
	if(fxHandler == nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Handler for Route: NULL: `" + route + "`")
		return false
	} //end if
	//--
	_, ok := urlHandlersMap[route]
	if(ok) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Route already have set a Handler. To replace a route it must be Un-Registered first: `" + route + "`")
		return false
	} //end if
	//--
	if(methods == nil) {
		methods = []string{}
	} //end if
	var allowedRouteMethods []string = allowedMethods // OPTIONS is reserved !!
	var allowedSafeMethods []string = []string{}
	for _, method := range methods {
		method = smart.StrToUpper(smart.StrTrimWhitespaces(method))
		if(!smart.InListArr(method, allowedRouteMethods)) {
			log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Method [" + method + "] for Route: `" + route + "`")
			return false
		} else {
			allowedSafeMethods = append(allowedSafeMethods, method)
		} //end if else
	} //end for
	if(len(allowedSafeMethods) <= 0) {
		allowedSafeMethods = append(allowedSafeMethods, "HEAD")
		allowedSafeMethods = append(allowedSafeMethods, "GET")
		allowedSafeMethods = append(allowedSafeMethods, "POST")
	} //end if
	//--
	sr := smartRoute{
		AuthSkip: 			skipAuth,
		AllowedMethods:  	allowedSafeMethods,
		MaxTailSegments:  	maxTailSegments,
		FxHandler:  		fxHandler,
	}
	urlHandlersMap[route] = sr
	//--
	return true
	//--
} //END FUNCTION


func UrlHandlerUnRegisterRoute(route string) bool {
	//--
	defer smart.PanicHandler()
	//--
	if(handlersAreLocked == true) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), msgErrHandlersLocked, "Route: `" + route + "`")
		return false
	} //end if
	//--
	handlersWriteMutex.Lock()
	defer handlersWriteMutex.Unlock()
	//--
	route = smart.StrTrimWhitespaces(route)
	if(route == "") {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Route: Empty")
		return false
	} //end if
	//--
	if((urlHandlersMap == nil) || (len(urlHandlersMap) <= 0)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "No Registered URL Handlers Found")
		return true
	} //end if
	//--
	_, ok1 := urlHandlersMap[route]
	if(!ok1) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Route: Not Registered: `" + route + "`")
	} else {
		delete(urlHandlersMap, route)
	} //end if else
	//--
	return true
	//--
} //END FUNCTION


func listAuthSkipRoutes() []string {
	//--
	var skipAuthRoutes []string = []string{}
	//--
	if((urlHandlersMap != nil) && (len(urlHandlersMap) > 0)) {
		for route, sr := range urlHandlersMap {
			if(sr.AuthSkip == true) {
				skipAuthRoutes = append(skipAuthRoutes, "`" + route + "`")
			} //end if
		} //end for
	} //end if
	//--
	sort.Strings(skipAuthRoutes)
	//--
	return skipAuthRoutes
	//--
} //END FUNCTION


func listRoutes() []string {
	//--
	var theRoutes []string = []string{}
	//--
	if((urlHandlersMap != nil) && (len(urlHandlersMap) > 0)) {
		for route, _ := range urlHandlersMap {
			theRoutes = append(theRoutes, "`" + route + "`")
		} //end for
	} //end if
	//--
	sort.Strings(theRoutes)
	//--
	return theRoutes
	//--
} //END FUNCTION


// #END
