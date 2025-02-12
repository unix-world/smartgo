
// GO Lang :: SmartGo / Web Server :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250211.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"sync"
	"time"

	"net/http"

	smart 			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web/assets/web-assets"
	srvassets 		"github.com/unix-world/smartgo/web/assets/srv-assets"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)

var (
	DEBUG bool = smart.DEBUG

	httpAuthRealm string = "SmartGo.Web.Server: Auth Area"
	httpServeSecure bool = false
	httpServerAddr string = ""
	httpServerPort string = ""

	maxPostSize uint64 = smart.SIZE_BYTES_16M * 8 // 128 MB
)

const (
	VERSION string = "r.20250211.2358"
	SIGNATURE string = smart.COPYRIGHT

	SERVE_HTTP2 bool = false // HTTP2 still have many bugs and many security flaws, disable

	SERVER_ADDR string = "127.0.0.1" // default
	SERVER_PORT uint16 = 17788 // default

	WEB_PUBLIC_RELATIVE_ROOT_PATH string = "./web-public/"
	DEFAULT_DIRECTORY_INDEX_HTML string = "index.html"

	DAV_PUBLIC_SAFETY_FILE string = "./webdav-allow-public-no-auth"
	DAV_STORAGE_RELATIVE_ROOT_PATH  string = "./webdav" // do not add trailing slash
	DAV_URL_PATH string = "webdav"

	CACHED_EXP_TIME_SECONDS uint32 = assets.CACHED_EXP_TIME_SECONDS * 3  // 24h

	CERTIFICATES_DEFAULT_PATH string = "./ssl/"
	CERTIFICATE_PEM_CRT string = "cert.crt"
	CERTIFICATE_PEM_KEY string = "cert.key"
)

const TheStrName string = "SmartGO Web Server"
const TheStrSignature string = TheStrName + " " + VERSION

const apiErrorDefaultCode uint16 = 65535
const apiErrorDefaultMsg  string = "Unknown Error"

type versionStruct struct {
	Platform  string `json:"platform"`
	Server    string `json:"server"`
	Version   string `json:"version"`
	GoVersion string `json:"goVersion"`
	OsName    string `json:"osName"`
	OsArch    string `json:"osArch"`
	Copyright string `json:"copyright,omitempty"`
}

type HttpResponse struct {
	StatusCode         uint16
	ContentStream      smarthttputils.HttpStreamerFunc
	ContentBody        string
	ContentFileName    string
	ContentDisposition string
	CacheExpiration    int
	CacheLastModified  string
	CacheControl       string
	Headers            map[string]string
	Cookies            []smarthttputils.CookieData
	LogMessage         string
}
type HttpHandlerFunc func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (response HttpResponse)
type smartRoute struct {
	AuthSkip 		bool 				// if Auth is Enabled: all routes are enforced to authenticate, so to skip a particular route (w/o tails) from authentication set this to TRUE ; if Auth is not enabled this setting has no effect
	AllowedMethods  []string 			// "OPTIONS" is handled separately (not allowed to be selected here) ; if is nil will (default) allow "HEAD", "GET", "POST" ; otherwise if explicit must be one or many of the: "HEAD", "GET", "POST", "PUT", "PATCH", "DELETE"
	MaxTailSegments int 				// if is zero, will allow no tails ; if is -1 will allow any number of tails and will pass them to controller ; if is 1 will alow one tail ; if is 2 will allow 2 tails, and so on ...
	FxHandler  		HttpHandlerFunc 	// see UrlHandlerRegisterRoute()
}
var allowedMethods []string = []string{ "HEAD", "GET", "POST", "PUT", "PATCH", "DELETE" } // OPTIONS is always available thus must not be includded here
var urlHandlersMap = map[string]smartRoute{}
var handlersWriteMutex sync.Mutex
var handlersAreLocked bool = false // after server boot process no more handlers are allowed to be registered, by setting this flag to TRUE
const msgErrHandlersLocked string = "Web Server Handlers are Locked after starting the server. Operation Disallowed."

type WebdavRunOptions struct {
	Enabled        bool
	SharedMode     bool
	SmartSafePaths bool
}


func WebServerSetMaxPostSize(size uint64) bool {
	//--
	if(handlersAreLocked == true) {
		return false // disallow changing after server started
	} //end if
	//--
	if(size <= 0) {
		return false
	} //end if
	//--
	maxPostSize = size
	//--
	return true
	//--
} //END FUNCTION


// IMPORTANT: If using Proxy with different PROXY_HTTP_BASE_PATH than "/" (ex: "/api/") the Proxy MUST strip back PROXY_HTTP_BASE_PATH to "/" for this backend
func WebServerRun(servePublicPath bool, webdavOptions *WebdavRunOptions, serveSecure bool, certifPath string, httpAddr string, httpPort uint16, timeoutSeconds uint32, allowedIPs string, authRealm string, authUser string, authPass string, authToken string, customAuthCheck smarthttputils.HttpAuthCheckFunc, rateLimit int, rateBurst int) int16 {

	//--
	// this method should return (error codes) just int16, only positive, values and zero if ok ; negative values are reserved for outsite managers
	//--

	defer smart.PanicHandler()

	//--
	httpServeSecure = serveSecure
	//--

	//-- lock routes
	handlersAreLocked = true
	//-- todo: check if there is at leat one handler and for /
	if(urlHandlersMap == nil) {
		log.Println("[ERROR] Web Server: Internal Error, Handlers are NULL")
		return 1001
	} //en dif
	//--

	log.Println("[META] Web Server: Allowed Methods:", listMethods(allowedMethods))

	//-- ip restriction list

	allowedIPs = smart.StrTrimWhitespaces(allowedIPs)
	if(allowedIPs != "") {
		errValidateAllowedIpList := smart.ValidateIPAddrList(allowedIPs) // {{{SYNC-VALIDATE-IP-LIST-BEFORE-VERIFY-IP}}} ; validate here because is used later in a sub-method of this method (by the routes to check access)
		if(errValidateAllowedIpList != nil) {
			log.Println("[ERROR] Web Server: ALLOWED IP LIST Error: " + errValidateAllowedIpList.Error())
			return 1002
		} //end if
	} //end if

	//-- auth user / pass

	var isAuthActive bool = false
	authUser = smart.StrTrimWhitespaces(authUser)
	if(authUser != "") {
		isAuthActive = true
		if((smart.StrTrimWhitespaces(authPass) == "") && (smart.StrTrimWhitespaces(authToken) == "")) {
			log.Println("[ERROR] Web Server: Empty Auth Password and Token when a UserName is Set")
			return 1100
		} //end if
		if(customAuthCheck != nil) {
			log.Println("[ERROR] Web Server: Auth User / Pass / Token is set but also a custom Auth Handler")
			return 1101
		} //end if
	} else if(customAuthCheck != nil) {
		isAuthActive = true
		if((smart.StrTrimWhitespaces(authUser) != "") && (smart.StrTrimWhitespaces(authPass) != "")) {
			log.Println("[ERROR] Web Server: Custom Auth Handler is Set but also Auth User / Pass")
			return 1102
		} //end if
	} //end if

	var isAuthCustom bool = false
	if(customAuthCheck != nil) {
		isAuthCustom = true
	} //end if

	if(isAuthActive) {
		//--
		if(allowedIPs != "") {
			log.Println("[INFO]", "Web Server: Authentication ALLOWED IP LIST is: `" + allowedIPs + "`")
		} //end if
		//--
		if(authRealm != "") {
			if(smarthttputils.IsValidHttpAuthRealm(authRealm) != true) {
				log.Println("[ERROR]", "Web Server: Authentication Realm is Invalid: `" + authRealm + "`")
				return 1103
			} //end if
			httpAuthRealm = authRealm
		} //end if
		log.Println("[INFO]", "Web Server: Authentication Realm is: `" + httpAuthRealm + "`")
		//--
		authProviders := listActiveWebAuthProviders()
		//--
		var authDescr string = "Default.Handler"
		if(isAuthCustom == true) {
			authDescr = "Custom.Handler"
		} //end if
		//--
		if(len(authProviders) > 0) {
			log.Println("[OK]", "Web Server: Authentication [" + authDescr + "] is ENABLED using the following Auth Providers: [ " + smart.Implode(", ", authProviders) + " ]")
		} else {
			log.Println("[ERROR]", "Web Server: Authentication [" + authDescr + "] is ENABLED but there are no active Auth Providers")
			return 1104
		} //end if else
		//--
		if(smart.Auth2FACookieIsEnabled() == true) {
			log.Println("[INFO]", "Web Server: Authentication 2FA is ENABLED")
		} else {
			log.Println("[NOTICE]", "Web Server: Authentication 2FA is DISABLED")
		} //end if else
		//--
		var skipAuthRoutes []string = listAuthSkipRoutes()
		if(len(skipAuthRoutes) <= 0) {
			log.Println("[OK]", "Web Server: Authentication is ENABLED for All Registered Routes")
		} else {
			log.Println("[WARNING]", "Web Server: Authentication is DISABLED for", len(skipAuthRoutes) ,"Registered Routes: [", smart.Implode(" ; ", skipAuthRoutes), "] - check the routes listed here and ensure this is not a security concern ...")
		} //end if else
		//--
	} else {
		//--
		if(allowedIPs != "") {
			log.Println("[INFO]", "Web Server: Access ALLOWED IP LIST is: `" + allowedIPs + "`")
		} else {
			log.Println("[WARNING]", "Web Server: Authentication is NOT ENABLED")
		} //end if
		//--
	} //end if

	//-- http(s) address and port(s)

	httpAddr = smart.StrTrimWhitespaces(httpAddr)
	if((!smart.IsNetValidIpAddr(httpAddr)) && (!smart.IsNetValidHostName(httpAddr))) {
		log.Println("[WARNING]", "Web Server: Invalid Server Address (Host):", httpAddr, "using the default host:", SERVER_ADDR)
		httpAddr = SERVER_ADDR
	} //end if
	if(smart.StrContains(httpAddr, ":")) {
		httpAddr = "[" + httpAddr + "]" // {{{SYNC-SMART-SERVER-DOMAIN-IPV6-BRACKETS}}}
	} //end if
	httpServerAddr = httpAddr

	if(!smart.IsNetValidPortNum(int64(httpPort))) {
		log.Println("[WARNING]", "Web Server: Invalid Server Address (Port):", httpPort, "using the default port:", SERVER_PORT)
		httpPort = SERVER_PORT
	} //end if
	httpServerPort = smart.ConvertUInt16ToStr(httpPort)

	//-- certif path (can be absolute)
	if(serveSecure == true) {
		if(WebDirIsValid(CERTIFICATES_DEFAULT_PATH) != true) {
			log.Println("[ERROR]", "Web Server: Certificates Default Path is Invalid:", CERTIFICATES_DEFAULT_PATH)
			return 1201
		} //end if
		if(WebDirExists(CERTIFICATES_DEFAULT_PATH) != true) {
			log.Println("[ERROR]", "Web Server: Certificates Default Path does not Exists or Is Not a Valid Directory:", CERTIFICATES_DEFAULT_PATH)
			return 1202
		} //end if
	} //end if
	if(serveSecure == true) {
		certifPath = smart.StrTrimWhitespaces(certifPath)
		certifPath = smart.SafePathFixClean(certifPath)
		if((certifPath == "") || (certifPath == ".") || (smart.PathIsEmptyOrRoot(certifPath) == true) || (smart.PathIsBackwardUnsafe(certifPath) == true)) {
			certifPath = CERTIFICATES_DEFAULT_PATH
		} //end if
		certifPath = smart.PathGetAbsoluteFromRelative(certifPath)
	} else {
		certifPath = CERTIFICATES_DEFAULT_PATH
	} //end if
	certifPath = smart.PathAddDirLastSlash(certifPath)
	if(serveSecure == true) {
		if((smart.PathIsSafeValidSafePath(certifPath) != true) || (!smart.PathExists(certifPath)) || (!smart.PathIsDir(certifPath))) {
			log.Println("[ERROR]", "Web Server: Certificates Path does not Exists or Is Not a Valid Directory:", certifPath)
			return 1203
		} //end if
	} //end if

	//-- web dir public path: relative only + safety constraints

	if(servePublicPath == true) {
		if(WebDirIsValid(WEB_PUBLIC_RELATIVE_ROOT_PATH) != true) {
			log.Println("[ERROR]", "Web Server: WebPublic Root Path is Invalid:", WEB_PUBLIC_RELATIVE_ROOT_PATH)
			return 1301
		} //end if
		if(WebDirExists(WEB_PUBLIC_RELATIVE_ROOT_PATH) != true) {
			log.Println("[ERROR]", "Web Server: WebPublic Path does not Exists or Is Not a Valid Directory:", WEB_PUBLIC_RELATIVE_ROOT_PATH)
			return 1302
		} //end if
	} //end if

	//-- webdav dir

	if(webdavOptions == nil) {
		webdavOptions = &WebdavRunOptions{Enabled:false, SharedMode:false, SmartSafePaths:false} // safe pointer, webdav options must be used overall
	} //end if

	if(webdavOptions.Enabled == true) {
		if(isAuthActive == true) {
			if(webdavOptions.SharedMode == true) {
				log.Println("[WARNING]", "Web Server: WebDav Service will run as PRIVATE (authentication is Enabled), but using Shared Storage for all users, as set")
			} //end if
		} else {
			log.Println("[WARNING]", "Web Server: WebDav Service will run as PUBLIC, NO AUTHENTICATION has been Set")
			webdavOptions.SharedMode = true // this is the only possibility if no auth is enabled !
			if((!smart.PathExists(DAV_PUBLIC_SAFETY_FILE)) || (!smart.PathIsFile(DAV_PUBLIC_SAFETY_FILE))) {
				log.Println("[ERROR]", "To allow Running a WebDAV Service as PUBLIC with NO AUTHENTICATION, create this file to confirm: `" + DAV_PUBLIC_SAFETY_FILE + "`")
				return 1400
			} //end if
		} //end if
		if(smart.PathIsWebSafeValidSafePath(DAV_STORAGE_RELATIVE_ROOT_PATH) != true) { // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-STORAGE-PATH}}} ; test with smart.PathIsWebSafeValidSafePath() instead of WebDirIsValid() because have no trailing slash
			log.Println("[ERROR]", "Web Server: WebDav Root Path is Invalid:", DAV_STORAGE_RELATIVE_ROOT_PATH)
			return 1401
		} //end if
		if(WebDirExists(DAV_STORAGE_RELATIVE_ROOT_PATH) != true) {
			log.Println("[ERROR]", "Web Server: WebDav Root Path does not Exists or Is Not a Valid Directory:", DAV_STORAGE_RELATIVE_ROOT_PATH)
			return 1402
		} //end if
		log.Println("[META]", "Web Server: WebDav Service is ENABLED ::", "SharedMode:", webdavOptions.SharedMode, ";", "SmartSafePaths:", webdavOptions.SmartSafePaths)
		log.Println("[INFO]", "Web Server WebDAV Serving Path: `" + webDavUrlPath() + "` as: `" + smart.PathGetAbsoluteFromRelative(DAV_STORAGE_RELATIVE_ROOT_PATH) + "`")
		webDavInitLockSysCache()
	} //end if

	//-- signature: console

	if(serveSecure != true) {
		log.Println("Starting Web Server: http://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + " @ HTTPS/Mux/Insecure # " + VERSION)
	} else {
		log.Println("Starting Web Server: https://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + " @ HTTPS/Mux/TLS # " + VERSION)
		log.Println("[META]", "Web Server Certificates Path:", certifPath)
	} //end if else

	if(servePublicPath == true) {
		log.Println("[INFO] Web Server Public Serving Path: `" + WEB_PUBLIC_RELATIVE_ROOT_PATH + "` as: `" + smart.PathGetAbsoluteFromRelative(WEB_PUBLIC_RELATIVE_ROOT_PATH) + "`")
	} else {
		log.Println("[INFO] Web Server Public Serving Path is Disabled")
	} //end if else

	//-- server + mux

	mux, srv := smarthttputils.HttpMuxServer(httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort), timeoutSeconds, !SERVE_HTTP2, false, "[Web Server]") // force HTTP/1 ; disallow large headers, the purpose of this service is public web mostly

	//-- rate limit decision

	var useRateLimit bool = ((rateLimit > 0) && (rateBurst > 0))
	if(useRateLimit) { // RATE LIMIT
		log.Println("[META]", "Web Server: HTTP/S Rate Limiter # Limit:", rateLimit, "Burst:", rateBurst)
	} //end if

	//-- http master / root handler: will manage all the rest of sub-handlers

	//--
	// HARDCODED LIMITS:
	// 		* Max Path Characters: 1024 	(safe for FileSystem access, as path, cross-platform) 			; {{{SYNC-HTTP-WEBSRV-MAX-PATH-LENGTH}}}
	// 		* Max Path Segments:    128 	(safe for FileSystem access, as dir structure, cross-platform) 	; {{{SYNC-HTTP-WEBSRV-MAX-PATH-SEGMENTS}}}
	//--

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//-- panic recovery
		defer smart.PanicHandler() // safe recovery handler
		//-- get remote address IP without port
		rAddrCli, _ := smart.GetHttpRemoteAddrIpAndPortFromRequest(r) // this is using r.RemoteAddr
		//-- get real client IP
		_, realClientIp := GetVisitorRealIpAddr(r)
		//-- validate remote address IP without port
		rAddrCli = smart.StrTrimWhitespaces(rAddrCli) // trim, just in case
		if((rAddrCli == "") || (smart.IsNetValidIpAddr(rAddrCli) != true)) {
			log.Printf("[ERROR] Web Server: IP Detection FAILED in RemoteAddress/Client :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s] ; Detected: `%s`\n", "500", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp, rAddrCli)
			smarthttputils.HttpStatus500(w, r, "IP Detection FAILED for IP Address", true)
			return
		} //end if
		//-- validate real client IP
		realClientIp = smart.StrTrimWhitespaces(realClientIp) // trim, just in case
		if((realClientIp == "") || (smart.IsNetValidIpAddr(realClientIp) != true)) {
			log.Printf("[ERROR] Web Server: IP Detection FAILED in RealClientIP :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s] ; Detected: `%s`\n", "500", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp, realClientIp)
			smarthttputils.HttpStatus500(w, r, "IP Detection FAILED for Client IP", true)
			return
		} //end if
		//-- if No Auth Enabled but an IP Restrict List have been set apply IP Restriction List to any request ; otherwise will be applied just on authentication
		if(isAuthActive != true) {
			if(allowedIPs != "") {
				if(!smart.StrContains(allowedIPs, "<"+rAddrCli+">")) { // {{{SYNC-VALIDATE-IP-IN-A-LIST}}} ; validate Remote Address
					log.Printf("[SRV] Web Server: IP Restriction Detected in RemoteAddress/Client (No:Auth) :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "423", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
					smarthttputils.HttpStatus423(w, r, "The access to this service is disabled. The IP: `" + rAddrCli + "` is not allowed by current IP Address list", true)
					return
				} //end if
				if((realClientIp == "") || (!smart.StrContains(allowedIPs, "<"+realClientIp+">"))) { // {{{SYNC-VALIDATE-IP-IN-A-LIST}}} ; validate realClientIp address, which may be the same as above but also may be different if behind proxy
					log.Printf("[SRV] Web Server: IP Restriction Detected in RealClientIP (No:Auth) :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "423", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
					smarthttputils.HttpStatus423(w, r, "The access to this service is disabled. The Client IP: `" + realClientIp + "` is not allowed by current IP Address list", true)
					return
				} //end if
			} //end if
		} //end if
		//--
		//== rate limit interceptor (must be first)
		if(useRateLimit) { // RATE LIMIT
			var isRateLimited bool = smarthttputils.HttpServerIsIpRateLimited(r, rateLimit, rateBurst)
			if(isRateLimited) { // if the current request/ip is rate limited
				log.Printf("[SRV] Web Server: Rate Limit :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "429", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus429(w, r, "Rate Limit: Your IP Address have submitted too many requests in a short period of time and have exceeded the number of allowed requests. Try again in few minutes.", true, false) // do not display captcha
				return
			} //end if
		} //end if
		//== #end rate limit
		//--
		var urlPath string = GetCurrentPath(r)
		if(urlPath == "") {
			urlPath = "/"
		} //end if
		if(len(urlPath) > 1024) { // {{{SYNC-HTTP-WEBSRV-MAX-PATH-LENGTH}}} ; max supported path is 1024 characters, as this is the common safe FileSystem max path length on many OSes, ex: OpenBSD or MacOS
			log.Printf("[SRV] Web Server: Oversized Request Path Detected :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "400", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus400(w, r, "Oversized Request Path Detected [Rule:DENY]: `" + GetCurrentPath(r) + "`", true)
			return
		} //end if
		//--
		//== webDAV (manages authentication internally, identical with the below auth implementation)
		if(webdavOptions.Enabled == true) {
			if((urlPath == webDavUrlPath()) || (smart.StrStartsWith(urlPath, webDavUrlPath()+"/"))) { // {{{SYNC-WEBSRV-ROUTE-WEBDAV}}}
				webDavHttpHandler(w, r, webdavOptions.SharedMode, webdavOptions.SmartSafePaths, isAuthActive, allowedIPs, authUser, authPass, authToken, customAuthCheck)
				return
			} //end if
		} //end if
		//--
		//== serving area (in order): assets (public) ; routes (depends how a route is set by urlHandlersSkipAuth) ; public files (public or n/a, depends if public files serving is enabled or not)
		//-- uuid
		manageSessUUIDCookie(w, r) // manage session UUID Cookie
		//-- shiftPath
		headPath, tailPaths := getUrlPathSegments(urlPath) // head path or tail paths must not contain slashes !!
		if(len(tailPaths) > 128) { // {{{SYNC-HTTP-WEBSRV-MAX-PATH-SEGMENTS}}} ; max supported path segments: 128
			log.Printf("[SRV] Web Server: Oversized Request Path Segments Detected :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "400", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus400(w, r, "Oversized Request Path Segments Detected [Rule:DENY]: `" + GetCurrentPath(r) + "`", true)
		} //end if
		//-- {{{SYNC-PATH-FROM-SLASH-REDIRECT}}} ; apache like fix but inversed: if path has / suffix remove and redirect ; this fix is needed because of tails implementation (shiftPath)
		if(smart.StrTrimWhitespaces(smart.StrTrim(urlPath, " /")) != "") { // avoid if root slash, will enter infinite cycle !
			if(smart.StrEndsWith(urlPath, "/")) {
				var fixedRoute string = smart.StrTrimWhitespaces(smart.StrTrim(urlPath, " /")) // trim on both sides, needs to add prefix below (Base Path)
				if(fixedRoute != "") {
					//--
					fixedRoute = GetBaseBrowserPath() + fixedRoute
					//--
					// MUST NOT Allow Handlers for paths that end with a slash / to avoid infinite cycle in net/http internally: redirectToPathSlash
					// also must be sure that there is a registered handler for the redirecting URL here
					//--
					log.Printf("[SRV] Web Server: Fix Route for [/%s] :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", headPath, "301", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
					smarthttputils.HttpStatus301(w, r, fixedRoute, true) // use 301 redirection for redirect from/to PathSlash as standard in net/http or Apache
					return
				} //end if
			} //end if
		} //end if
		//-- check route safety
		if((!WebUrlRouteIsValid(urlPath)) || (!WebUrlRouteIsValid("/"+headPath))) {
			log.Printf("[SRV] Web Server: Unsafe Request Path Detected :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "400", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus400(w, r, "Unsafe Request Path Detected [Rule:DENY]: `" + GetCurrentPath(r) + "`", true)
			return
		} //end if
		//-- serve assets first
	//	if(smart.StrStartsWith(urlPath, "/lib/")) {
		if(headPath == "lib") {
			if(r.Method == "OPTIONS") {
				log.Printf("[SRV] Web Server: OPTIONS Request Method for Assets :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "200", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus200(w, r, "", "options.txt", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, map[string]string{"Allow":"OPTIONS, GET, HEAD"})
				return
			} //end if
			if((r.Method != "GET") && (r.Method != "HEAD")) {
				log.Printf("[SRV] Web Server: Invalid Request Method for Assets :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "405", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus405(w, r, "Invalid Request Method (" + r.Method + ") for Assets [Rule:DENY]: `" + GetCurrentPath(r) + "`", true)
				return
			} //end if
			aCode := srvassets.WebAssetsHttpHandler(w, r, "cache:default") // default cache mode ; it is most common than public or private cache ...
			log.Printf("[SRV] Web Server Asset :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertUInt16ToStr(aCode), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			return
		} //end if else
		//-- manage handlers

		var sr smartRoute = smartRoute{}
		var okInternalRoute bool = false
		var testPath string = ""
		var cycles uint64 = 0
		testPaths := tailPaths
		for {
			testPath = "/" + headPath
			if(len(testPaths) <= 0) { // if no more segments, test the 1st and stop
				sr, okInternalRoute = urlHandlersMap[testPath] // last test
				break
			} //end if
			testPath += "/" + smart.Implode("/", testPaths)
			sr, okInternalRoute = urlHandlersMap[testPath]
			if(okInternalRoute == true) { // if found, stop
				break
			} //end if
			testPaths = testPaths[:len(testPaths)-1] // pop out last segment
			if(cycles > 128) { // {{{SYNC-HTTP-WEBSRV-MAX-PATH-SEGMENTS}}}
				break
			} //end if
			cycles++
		} //end for
	//	sr, okInternalRoute := urlHandlersMap["/"+headPath] // previous, original code, replaced with the above
		//-- serve public routes (no authentication) ; if the current route is not inside the internal ones, try ...
		if(okInternalRoute != true) { // if not an internal route, try to see if it is an existing web public path, if not, exit with 404
			if(r.Method == "OPTIONS") {
				log.Printf("[SRV] Web Server: OPTIONS Request Method :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "200", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus200(w, r, "", "options.txt", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, map[string]string{"Allow":"OPTIONS, GET, HEAD"})
				return
			} //end if
			if((r.Method != "GET") && (r.Method != "HEAD")) {
				log.Printf("[SRV] Web Server: Invalid Request Method :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "405", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus405(w, r, "Invalid Request Method (" + r.Method + ") [Rule:DENY]: `" + GetCurrentPath(r) + "`", true)
				return
			} //end if
			if((servePublicPath == true) && ((urlPath == "/") || (WebUrlPathIsValid(urlPath) == true))) {
				if(((urlPath == "/") || (smart.PathExists(WEB_PUBLIC_RELATIVE_ROOT_PATH + smart.StrTrimLeft(urlPath, "/")) == true))) {
					pCode := webPublicHttpHandler(w, r)
					log.Printf("[SRV] Web Server: Public File :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertUInt16ToStr(pCode), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
					return
				} //end if
			} //end if
			log.Printf("[SRV] Web Server: Invalid Route :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "404", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus404(w, r, "Web Resource Not Found: `" + GetCurrentPath(r) + "`", true)
			return
		} //end if
		//-- serve internal routes
		if((sr.MaxTailSegments >= 0) && (len(tailPaths) > sr.MaxTailSegments)) { // if sr.MaxTailSegments is -1, pass to controller
			log.Printf("[SRV] Web Server: Invalid Internal Route for [/%s] (Max Tail is %d) :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", headPath, sr.MaxTailSegments, "404", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus404(w, r, "Web Resource Not Found: `" + GetCurrentPath(r) + "`", true)
			return
		} //end if
		if(r.Method == "OPTIONS") {
			log.Printf("[SRV] Web Server: OPTIONS Request Method for Internal Route :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "200", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus200(w, r, "", "options.txt", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, map[string]string{"Allow":listMethods(sr.AllowedMethods)})
			return
		} //end if
		if(!smart.InListArr(r.Method, sr.AllowedMethods)) {
			log.Printf("[SRV] Web Server: Invalid Request Method for Internal Route :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "405", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus405(w, r, "Invalid Request Method (" + r.Method + ") for Internal Route [Rule:DENY]: `" + GetCurrentPath(r) + "`", true)
			return
		} //end if
		//-- auth check (if auth is active and not explicit skip auth by route)
		var authErr error = nil
		var authData smart.AuthDataStruct
		if(sr.AuthSkip != true) { // this check must be before executing fx below
			if(isAuthActive == true) {
				authErr, authData = smarthttputils.HttpAuthCheck(w, r, httpAuthRealm, authUser, authPass, authToken, allowedIPs, customAuthCheck, true) // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-URL-PATH}}} ; if not success, outputs HTML 4xx-5xx and must stop (return) immediately after checks from this method
				if((authErr != nil) || (authData.OK != true) || (authData.ErrMsg != "")) {
					log.Println("[LOG]", "Web Server: Authentication Failed:", "authData: OK [", authData.OK, "] ; ErrMsg: `" + authData.ErrMsg + "` ; UserName: `" + authData.UserName + "` ; Error:", authErr)
					// MUST NOT WRITE ANY ANSWER HERE ON FAIL: smarthttputils.HttpStatusXXX() as 401, 403, 429 because the smarthttputils.HttpAuthCheck() method manages 4xx-5xx codes directly if not success
					return
				} //end if
			} else {
				log.Printf("[LOG] Web Server: Authentication is Disabled, ACCESS DENY for a Route that requires Authentication :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "403", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus403(w, r, "Web Server: Authentication is Disabled, ACCESS DENY: `" + GetCurrentPath(r) + "`", true)
				return
			} //end if else
		} //end if
		//-- #end auth check
		timerStart := time.Now()
		response := sr.FxHandler(r, headPath, tailPaths, authData)
		timerDuration := time.Since(timerStart)
		//-- controller cookie registration
		numCookies := smarthttputils.HttpRequestSetCookies(w, r, response.Cookies)
		if(numCookies > 0) {
			log.Println("[NOTICE]", "Web Server: Controller Cookie Registration: #", numCookies)
		} //end if
		//-- custom log
		response.LogMessage = smart.StrTrimWhitespaces(response.LogMessage)
		if(response.LogMessage != "") {
			log.Println("[LOG]", "Web Server: Controller Route:", "`" + urlPath + "` :: RemoteAddress/Client [" + r.RemoteAddr + "] # RealClientIP [" + realClientIp + "]:", response.LogMessage)
		} //end if
		//-- fixes for default params
		if(response.CacheExpiration <= 0) { // for easing the development if response.CacheExpiration is not specified the default value is zero but actually for no-cache -1 is needed ; this fix is needed because in http utils cache zero means at least 60 seconds ... and -1 is no cache !
			response.CacheExpiration = -1 // if response.CacheExpiration is not explicit set to a value greater than zero in controller consider is no-cache
			response.CacheLastModified = "" // mandatory for no cache, cannot be otherwise ...
			response.CacheControl = smarthttputils.CACHE_CONTROL_NOCACHE // mandatory for no cache, cannot be otherwise ...
		} else { // if cache is set and no explicit
			switch(response.CacheControl) {
				case smarthttputils.CACHE_CONTROL_PRIVATE:
					break
				case smarthttputils.CACHE_CONTROL_PUBLIC:
					break
				case smarthttputils.CACHE_CONTROL_DEFAULT:
					break
				default:
					response.CacheControl = smarthttputils.CACHE_CONTROL_DEFAULT // if no explicit value is set, set to default
			} //end switch
		} //end if
		response.ContentFileName = smart.StrTrimWhitespaces(response.ContentFileName)
		if(!smart.PathIsSafeValidSafeFileName(response.ContentFileName)) {
			response.ContentFileName = ""
		} //end if
		response.ContentDisposition = smart.StrToLower(smart.StrTrimWhitespaces(response.ContentDisposition))
		if((response.ContentDisposition != smarthttputils.DISP_TYPE_INLINE) && (response.ContentDisposition != smarthttputils.DISP_TYPE_ATTACHMENT)) {
			response.ContentDisposition = ""
		} //end if
		//--
		memStats := smart.MemoryStats()
		//--
		log.Println("[META]", "Web Server Metrics [Peak System Memory: " + smart.ConvertUInt64ToStr(smart.BytesToMegaBytes(memStats.Sys)) + "MB / Allocated: " + smart.PrettyPrintBytes(memStats.Alloc) + "] :: Handler Execution Time:", timerDuration, "# Route: `" + urlPath + "`")
		log.Printf("[SRV] Web Server: Internal Route :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertIntToStr(int(response.StatusCode)), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
		//--
		if(response.StatusCode == 0) {
			response.StatusCode = 200 // this is default, if not explicit set in handler
		} //end if
		//--
		if(response.ContentStream != nil) {
			smarthttputils.HttpStreamContent(w, r, response.StatusCode, response.ContentStream, response.ContentFileName, response.ContentDisposition, response.Headers)
			return
		} //end if
		//--
		var fExt string = ""
		if((response.ContentFileName != "") && (!smart.StrContains(response.ContentFileName, "://"))) {
			fExt = smart.StrTrimLeft(smart.StrToLower(smart.PathBaseExtension(response.ContentFileName)), ".")
		} //end if
		//--
		var isHtmlAnswer bool = false
		if((fExt == "") || (fExt == "html") || (fExt == "htm")) {
			isHtmlAnswer = true
		} //end if
		//--
		if(isHtmlAnswer == true) { // only if HTML, but this can be rewritten by accept headers that client send, add below extra conditions
			if((response.StatusCode >= 200) && (response.StatusCode < 300)) { // only for 2xx status codes
				if((fExt == "html") || (fExt == "htm")) { // only if explicit html/htm extensions, ommit if empty extension, can be something different
					if(smart.StrContains(response.ContentBody, "</html>")) { // detect html end tag, case sensitive, for speed
						response.ContentBody += `<!-- Server-Side Metrics:  ` + smart.EscapeHtml(smart.StrPad2LenRight("Total Execution Time = " + timerDuration.String(), " ", 38)) + `  -->` + "\n"
					} //end if
				} //end if
			} //end if
		} //end if
		//-- notice of content type served
		log.Println("[NOTICE]", smart.CurrentFunctionName() + ": Serving Internal Route: `" + urlPath + "` ; Content: `" + response.ContentFileName + "` ; ContentDisposition: `" + response.ContentDisposition + "` ; StatusCode:", response.StatusCode, "; ClientIP:", realClientIp)
		//-- from this point the HTTP Writer will begin to write the response, no reads are safe and guaranteed
		switch(response.StatusCode) {
			//-- ok status codes
			case 200:
				smarthttputils.HttpStatus200(w, r, response.ContentBody, response.ContentFileName, response.ContentDisposition, response.CacheExpiration, response.CacheLastModified, response.CacheControl, response.Headers)
				break
			case 201:
				smarthttputils.HttpStatus201(w, r, response.ContentBody, response.ContentFileName, response.ContentDisposition, response.CacheExpiration, response.CacheLastModified, response.CacheControl, response.Headers)
				break
			case 202:
				smarthttputils.HttpStatus202(w, r, response.ContentBody, response.ContentFileName, response.ContentDisposition, response.CacheExpiration, response.CacheLastModified, response.CacheControl, response.Headers)
				break
			case 203:
				smarthttputils.HttpStatus203(w, r, response.ContentBody, response.ContentFileName, response.ContentDisposition, response.CacheExpiration, response.CacheLastModified, response.CacheControl, response.Headers)
				break
			case 204:
				smarthttputils.HttpStatus204(w, r, response.ContentBody, response.ContentFileName, response.ContentDisposition, response.CacheExpiration, response.CacheLastModified, response.CacheControl, response.Headers)
				break
			case 208:
				smarthttputils.HttpStatus208(w, r, response.ContentBody, response.ContentFileName, response.ContentDisposition, response.CacheExpiration, response.CacheLastModified, response.CacheControl, response.Headers)
				break
			//-- redirect 3xx statuses
			case 301:
				smarthttputils.HttpStatus301(w, r, response.ContentBody, isHtmlAnswer) // for 3xx the content is the redirect URL
				break
			case 302:
				smarthttputils.HttpStatus302(w, r, response.ContentBody, isHtmlAnswer) // for 3xx the content is the redirect URL
				break
			// case 304 canno be handled here, this is a special case
			//-- client errors
			case 400:
				smarthttputils.HttpStatus400(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 401:
				if(response.ContentFileName == "@401.html") { // if the content filename is this, will reply with a custom HTML 401 Html Page ; ex: this is used for logout
					smarthttputils.HttpHeaderAuthBasic(w, httpAuthRealm)
					smarthttputils.HttpStatus401(w, r, response.ContentBody, isHtmlAnswer, true) // custom 401.html
				} else {
					smarthttputils.HttpStatus401(w, r, response.ContentBody, isHtmlAnswer, false)
				} //end if else
				break
			case 402:
				smarthttputils.HttpStatus402(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 403:
				smarthttputils.HttpStatus403(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 404:
				smarthttputils.HttpStatus404(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 405:
				smarthttputils.HttpStatus405(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 406:
				smarthttputils.HttpStatus406(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 408:
				smarthttputils.HttpStatus408(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 409:
				smarthttputils.HttpStatus409(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 410:
				smarthttputils.HttpStatus410(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 415:
				smarthttputils.HttpStatus415(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 422:
				smarthttputils.HttpStatus422(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 423:
				smarthttputils.HttpStatus423(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 424:
				smarthttputils.HttpStatus424(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 429:
				smarthttputils.HttpStatus429(w, r, response.ContentBody, isHtmlAnswer, false) // do not display captcha
				break
			//-- server errors
			case 500:
				smarthttputils.HttpStatus500(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 501:
				smarthttputils.HttpStatus501(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 502:
				smarthttputils.HttpStatus502(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 503:
				smarthttputils.HttpStatus503(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 504:
				smarthttputils.HttpStatus504(w, r, response.ContentBody, isHtmlAnswer)
				break
			case 507:
				smarthttputils.HttpStatus507(w, r, response.ContentBody, isHtmlAnswer)
				break
			//--
			default: // fallback to 500
				log.Println("[ERROR]", "Web Server: Invalid Application Level Status Code for the URL Path [" + urlPath + "]:", response.StatusCode)
				smarthttputils.HttpStatus500(w, r, "Invalid Application Level Status Code: `" + smart.ConvertIntToStr(int(response.StatusCode)) + "` for the URL Path: `" + GetCurrentPath(r) + "`", isHtmlAnswer)
		} //end switch
		//--
	//	// Depending on the HTTP protocol version and the client, calling Write or WriteHeader may prevent future reads on the Request
	//	// For HTTP/1.x requests, handlers should read any needed request body data before writing the response
	//	// the below commented code may work but only in certain circumstances and is intended just for Development / Debugging
	//	if(DEBUG) {
	//		hdrCType := w.Header().Get(smarthttputils.HTTP_HEADER_CONTENT_TYPE)
	//		mType, mCharSet := smarthttputils.MimeAndCharsetGetFromMimeType(hdrCType)
	//		log.Println("[DEBUG]", "Web Server Mux Handler Response Content Type:", "MimeType = `" + mType + "` / Charset = `" + mCharSet + "` / Header [" + smarthttputils.HTTP_HEADER_CONTENT_TYPE + "] Raw Value is: `" + hdrCType + "`")
	//	} //end if
		//--
	})

	//-- serve logic: is better to manage outside the async calls because extra monitoring logic can be implemented !

	if(serveSecure == true) { // serve HTTPS
		var theTlsCertPath string = certifPath + CERTIFICATE_PEM_CRT
		var theTlsKeyPath  string = certifPath + CERTIFICATE_PEM_KEY
		if(!smart.PathIsFile(theTlsCertPath)) {
			log.Println("[ERROR]", "Web Server: INIT TLS: No certificate crt found in current directory. Please provide a valid cert:", theTlsCertPath)
			return 2101
		} //end if
		if(!smart.PathIsFile(theTlsKeyPath)) {
			log.Println("[ERROR]", "Web Server: INIT TLS: No certificate key found in current directory. Please provide a valid cert:", theTlsKeyPath)
			return 2102
		} //end if
		log.Println("[OK]", "Web Server is Ready for Serving HTTPS/TLS at", httpAddr, "on port", httpPort)
		errServeTls := srv.ListenAndServeTLS(theTlsCertPath, theTlsKeyPath)
		if(errServeTls != nil) {
			log.Println("[ERROR]", "Web Server (HTTPS/TLS): Fatal Service Init Error:", errServeTls)
			return 3001
		} //end if
	} else { // serve HTTP
		log.Println("[OK]", "Web Server is Ready for Serving HTTP at", httpAddr, "on port", httpPort)
		errServe := srv.ListenAndServe()
		if(errServe != nil) {
			log.Println("[ERROR]", "Web Server: Fatal Service Init Error:", errServe)
			return 3002
		} //end if
	} //end if

	//--
	return 0
	//--

} //END FUNCTION


// #END
