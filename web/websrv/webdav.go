
// GO Lang :: SmartGo / Web Server / WebDAV :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240112.1858 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"

	"os"
	"context"

	"net/http"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
	webdav 			"github.com/unix-world/smartgo/web/webdav" // a modified version of [golang.org / x / net / webdav]: added extra path security checks
)


func webDavUrlPath() string {
	//--
	return smart.GetHttpProxyBasePath() + DAV_URL_PATH // {{{SYNC-WEBSRV-ROUTE-WEBDAV}}}
	//--
} //END FUNCTION


func registerWebDavService() *webdav.Handler {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if(!webPathIsValid(DAV_STORAGE_RELATIVE_ROOT_PATH)) { // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-STORAGE-PATH}}}
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Failed to Initialize the WebDAV Service, WebDAV Storage Path is Invalid: `" + DAV_STORAGE_RELATIVE_ROOT_PATH + "`")
		return nil
	} //end if
	//--
	var webDavRealUrlPath string = smart.StrTrimWhitespaces(webDavUrlPath())
	if((webDavRealUrlPath == "") || (!smart.StrStartsWith(webDavRealUrlPath, "/")) || (!webUrlRouteIsValid(webDavRealUrlPath))) { // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-URL-PATH}}}
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Failed to Initialize the WebDAV Service, WebDAV Route is Invalid: `" + webDavRealUrlPath + "`")
		return nil
	} //end if
	//--
	wdav := &webdav.Handler{
		Prefix:     webDavRealUrlPath,
		FileSystem: webdav.Dir(DAV_STORAGE_RELATIVE_ROOT_PATH),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			remoteAddr, remotePort := smart.GetHttpRemoteAddrIpAndPortFromRequest(r)
			realClientIp := getVisitorRealIpAddr(r)
			if(err != nil) {
				if(os.IsNotExist(err)) {
					log.Printf("[NOTICE] WebDAV Service :: WEBDAV.NOTFOUND: %s :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", err, "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
				} else {
					log.Printf("[WARNING] WebDAV Service :: WEBDAV.ERROR: %s :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", err, "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
				} //end if
			} else {
				log.Printf("[LOG] WebDAV Service :: WEBDAV :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
			} //end if else
		},
	}
	//--
	return wdav
	//--
} //END FUNCTION


func webDavHttpHandler(w http.ResponseWriter, r *http.Request, wdav *webdav.Handler, webdavSharedStorage bool, webDavUseSmartSafeValidPaths bool, isAuthActive bool, allowedIPs string, authUser string, authPass string, customAuthCheck smarthttputils.HttpAuthCheckFunc) { // serves the WebDAV Handler the path: `/webdav/*`
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if(!webPathIsValid(DAV_STORAGE_RELATIVE_ROOT_PATH)) { // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-STORAGE-PATH}}}
		log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service Initialization Error, WebDAV Storage Path is Invalid: `" + DAV_STORAGE_RELATIVE_ROOT_PATH + "`")
		smarthttputils.HttpStatus500(w, r, "WebDAV Service Internal Error", true)
		return
	} //end if
	//--
	var webDavRealUrlPath string = smart.StrTrimWhitespaces(webDavUrlPath())
	if((webDavRealUrlPath == "") || (!smart.StrStartsWith(webDavRealUrlPath, "/")) || (!webUrlRouteIsValid(webDavRealUrlPath))) { // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-URL-PATH}}}
		log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service Initialization Error, WebDAV Route is Invalid: `" + webDavRealUrlPath + "`")
		smarthttputils.HttpStatus500(w, r, "WebDAV Service cannot handle this Path: `" + smart.GetHttpPathFromRequest(r) + "`", true)
		return
	} //end if
	//-- auth check
	if(isAuthActive != true) {
		log.Println("[NOTICE]", smart.CurrentFunctionName(), "WebDAV Service: Auth is NOT Enabled, Serving WebDAV as Public")
	} else {
		var auth401IsHtml bool = false
		var crrRoute string = smart.GetHttpPathFromRequest(r)
		if((crrRoute == webDavUrlPath()) || (crrRoute == webDavUrlPath()+"/")) {
			auth401IsHtml = true // outputs HTML just for the entry route on WebDAV, otherwise outputs Text
		} //end if
		authErr, authData := smarthttputils.HttpBasicAuthCheck(w, r, HTTP_AUTH_REALM, authUser, authPass, allowedIPs, customAuthCheck, auth401IsHtml)
		if((authErr != nil) || (authData.OK != true) || (authData.ErrMsg != "")) {
			log.Println("[WARNING]", smart.CurrentFunctionName(), "WebDAV Service / Storage Area :: Authentication Failed:", "authData.OK:", authData.OK, "authData.ErrMsg:", authData.ErrMsg, "Error:", authErr)
			// MUST NOT USE smarthttputils.HttpStatus401() here, is handled directly by smarthttputils.HttpBasicAuthCheck()
			return
		} //end if
		if(webdavSharedStorage != true) {
			if(smart.PathIsSafeValidFileName(authData.UserID) != true) {
				log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service", "Invalid User ID (Unsafe): `" + authData.UserID + "`")
				smarthttputils.HttpStatus403(w, r, "WebDAV: Invalid User ID (Unsafe): `" + authData.UserID + "`", true)
				return
			} //end if
			var theUserPath string = smart.PathAddDirLastSlash(DAV_STORAGE_RELATIVE_ROOT_PATH) + authData.UserID
			if((smart.PathIsSafeValidPath(theUserPath) != true) || (smart.PathIsBackwardUnsafe(theUserPath) == true)) {
				log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service", "Invalid User Path (Unsafe): `" + theUserPath + "`")
				smarthttputils.HttpStatus403(w, r, "WebDAV: Invalid User Path (Unsafe): `" + theUserPath + "`", true)
				return
			} //end if
			if(smart.PathIsFile(theUserPath)) {
				log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service", "Invalid User Path cannot be created (is a file): `" + theUserPath + "`")
				smarthttputils.HttpStatus403(w, r, "WebDAV: User Path cannot be created: `" + theUserPath + "`", true)
				return
			} //end if
			if(!smart.PathExists(theUserPath)) {
				okUserPath, errUserPath := smart.SafePathDirCreate(theUserPath, false, true)
				if(errUserPath != nil) {
					log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service", "Error while Creating the User Path:", theUserPath, "Err:", errUserPath)
					smarthttputils.HttpStatus403(w, r, "WebDAV: User Path Cannot be created (Error): `" + theUserPath + "`", true)
					return
				} else if(okUserPath != true) {
					log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service", "Failed to Create User Path:", theUserPath)
					smarthttputils.HttpStatus403(w, r, "WebDAV: User Path Cannot be created: `" + theUserPath + "`", true)
					return
				} //end if
			} //end if
			if(!smart.PathExists(theUserPath)) {
				log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service", "Invalid User Path is N/A (missing): `" + theUserPath + "`")
				smarthttputils.HttpStatus403(w, r, "WebDAV: User Path is N/A: `" + theUserPath + "`", true)
				return
			} //end if
			log.Println("[NOTICE]", smart.CurrentFunctionName(), "WebDAV + Auth is using Per-User Dir Separate Space: `" + theUserPath + "` ; Authenticated User/ID: `" + authData.UserName + "`/`" + authData.UserID + "`")
			wdav.FileSystem = webdav.Dir(theUserPath)
		} else {
			log.Println("[NOTICE]", smart.CurrentFunctionName(), "WebDAV + Auth is using Shared Dir Space: `" + DAV_STORAGE_RELATIVE_ROOT_PATH + "`")
		} //end if // storagePath
	} //end if
	//-- #end auth check
	if((r.Method == http.MethodHead) || (r.Method == http.MethodGet) || (r.Method == http.MethodPost)) { // all 3 methods are handles by a single webdav internal method handleGetHeadPost()
		var wdirPath string = smart.StrSubstr(r.URL.Path, len(webDavRealUrlPath), 0)
		if(smart.StrTrimWhitespaces(wdirPath) == "") {
			wdirPath = "/"
		} //end if
		info, err := wdav.FileSystem.Stat(context.TODO(), wdirPath)
		if(err == nil) {
			if(info.IsDir()) {
				r.Method = "PROPFIND" // this is a mapping for a directory from GET to PROPFIND ; TODO: it can be later supplied as a HTML Page listing all entries ; by mapping to PROPFIND will serve an XML
				r.Header.Set("Depth", "1") // fix: ignore depth infinity, to avoid overload the file system
			} //end if
		} //end if
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "WebDAV Service", "Method:", r.Method, "Depth:", r.Header.Get("Depth"))
	} //end if
	//--
	wdav.ServeHTTP(w, r, webDavUseSmartSafeValidPaths) // if all ok above (basic auth + credentials ok, serve ...)
	//--
} //END FUNCTION


// #END
