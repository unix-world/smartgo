
// GO Lang :: SmartGo / Web Server :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240930.1531 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"fmt"
	"sync"
	"time"

	"net/http"

	smart 			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web/assets/web-assets"
	srvassets 		"github.com/unix-world/smartgo/web/assets/srv-assets"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)

const (
	VERSION string = "r.20240930.1531"
	SIGNATURE string = "(c) 2020-2024 unix-world.org"

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

	HTTP_AUTH_REALM string = "Smart.Web Server: Auth Area"

	REAL_IP_HEADER_KEY = "" // if used behind a proxy, can be set as: X-REAL-IP, X-FORWARDED-FOR, HTTP-X-CLIENT-IP, ... or any other trusted proxy header ; if no proxy is used, set as an empty string

	DEBUG bool = false
)

const TheStrSignature string = "SmartGO Web Server " + VERSION

type versionStruct struct {
	Version   string `json:"version"`
	Copyright string `json:"copyright"`
}

type HttpHandlerFunc func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (code uint16, content string, contentFileName string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string)
type smartRoute struct {
	AuthSkip 		bool 				// if Auth is Enabled: all routes are enforced to authenticate, so to skip a particluar route (w/o tails) from authentication set this to TRUE ; if Auth is not enabled this setting has no effect
	AllowedMethods  []string 			// "OPTIONS" is handled separately (not allowed to be selected here) ; if is nil will (default) allow "HEAD", "GET", "POST" ; otherwise if explicit must be one or many of the: "HEAD", "GET", "POST", "PUT", "PATCH", "DELETE"
	MaxTailSegments int 				// if is zero, will allow no tails ; if is -1 will allow any number of tails and will pass them to controller ; if is 1 will alow one tail ; if is 2 will allow 2 tails, and so on ...
	FxHandler  		HttpHandlerFunc 	// see UrlHandlerRegisterRoute()
}
var AllowedMethods []string = []string{ "HEAD", "GET", "POST", "PUT", "PATCH", "DELETE" }
var urlHandlersMap = map[string]smartRoute{}
var handlersWriteMutex sync.Mutex
var handlersAreLocked bool = false // after server boot process no more handlers are allowed to be registered, by setting this flag to TRUE
const msgErrHandlersLocked string = "Web Server Handlers are Locked after starting the server. Operation Disallowed."

type WebdavRunOptions struct {
	Enabled        bool
	SharedMode     bool
	SmartSafePaths bool
}


// IMPORTANT: If using Proxy with different PROXY_HTTP_BASE_PATH than "/" (ex: "/api/") the Proxy MUST strip back PROXY_HTTP_BASE_PATH to "/" for this backend
func WebServerRun(servePublicPath bool, webdavOptions *WebdavRunOptions, serveSecure bool, certifPath string, httpAddr string, httpPort uint16, timeoutSeconds uint32, allowedIPs string, authUser string, authPass string, customAuthCheck smarthttputils.HttpAuthCheckFunc, rateLimit int, rateBurst int) int16 {

	//--
	// this method should return (error codes) just int16 positive values and zero if ok ; negative values are reserved for outsite managers
	//--

	defer smart.PanicHandler()

	//-- lock routes
	handlersAreLocked = true
	//-- todo: check if there is at leat one handler and for /
	if(urlHandlersMap == nil) {
		log.Println("[ERROR] Web Server: Internal Error, Handlers are NULL")
		return 1001
	} //en dif
	//--

	//-- auth user / pass

	var isAuthActive bool = false
	authUser = smart.StrTrimWhitespaces(authUser)
	if(authUser != "") {
		isAuthActive = true
		if(smart.StrTrimWhitespaces(authPass) == "") {
			log.Println("[ERROR] Web Server: Empty Auth Password when a UserName is Set")
			return 1100
		} //end if
		if(customAuthCheck != nil) {
			log.Println("[ERROR] Web Server: Auth User / Pass is set but also a custom Auth Handler")
			return 1101
		} //end if
	} else if(customAuthCheck != nil) {
		isAuthActive = true
		if((smart.StrTrimWhitespaces(authUser) != "") && (smart.StrTrimWhitespaces(authPass) != "")) {
			log.Println("[ERROR] Web Server: Custom Auth Handler is Set but also Auth User / Pass")
			return 1102
		} //end if
	} //end if

	if(isAuthActive) {
		//--
		authProviders := listActiveWebAuthProviders()
		//--
		if(len(authProviders) > 0) {
			log.Println("[OK]", "Web Server: Authentication is ENABLED using these Auth Providers:", authProviders)
		} else {
			log.Println("[ERROR]", "Web Server: Authentication is ENABLED but there are no active Auth Providers")
			return 1103
		} //end if else
		//--
		var skipAuthRoutes []string = listAuthSkipRoutes()
		if(len(skipAuthRoutes) <= 0) {
			log.Println("[OK]", "Web Server: Authentication is ENABLED for All Routes")
		} else {
			log.Println("[WARNING]", "Web Server: Authentication is DISABLED for some Routes:", skipAuthRoutes)
		} //end if else
		//--
	} else {
		//--
		log.Println("[WARNING]", "Web Server: Authentication is NOT ENABLED")
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

	if(!smart.IsNetValidPortNum(int64(httpPort))) {
		log.Println("[WARNING]", "Web Server: Invalid Server Address (Port):", httpPort, "using the default port:", SERVER_PORT)
		httpPort = SERVER_PORT
	} //end if

	//-- certif path (can be absolute)
	if(serveSecure == true) {
		if(webDirIsValid(CERTIFICATES_DEFAULT_PATH) != true) {
			log.Println("[ERROR]", "Web Server: Certificates Default Path is Invalid:", CERTIFICATES_DEFAULT_PATH)
			return 1201
		} //end if
		if(webDirExists(CERTIFICATES_DEFAULT_PATH) != true) {
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
		if(webDirIsValid(WEB_PUBLIC_RELATIVE_ROOT_PATH) != true) {
			log.Println("[ERROR]", "Web Server: WebPublic Root Path is Invalid:", WEB_PUBLIC_RELATIVE_ROOT_PATH)
			return 1301
		} //end if
		if(webDirExists(WEB_PUBLIC_RELATIVE_ROOT_PATH) != true) {
			log.Println("[ERROR]", "Web Server: WebPublic Path does not Exists or Is Not a Valid Directory:", WEB_PUBLIC_RELATIVE_ROOT_PATH)
			return 1302
		} //end if
	} //end if

	//-- webdav dir

	if(webdavOptions == nil) {
		webdavOptions = &WebdavRunOptions{Enabled:false, SharedMode:false, SmartSafePaths:false}
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
		if(webPathIsValid(DAV_STORAGE_RELATIVE_ROOT_PATH) != true) { // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-STORAGE-PATH}}} ; tesh with webPathIsValid() instead of webDirIsValid() because have no trailing slash
			log.Println("[ERROR]", "Web Server: WebDav Root Path is Invalid:", DAV_STORAGE_RELATIVE_ROOT_PATH)
			return 1401
		} //end if
		if(webDirExists(DAV_STORAGE_RELATIVE_ROOT_PATH) != true) {
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

	mux, srv := smarthttputils.HttpMuxServer(httpAddr + fmt.Sprintf(":%d", httpPort), timeoutSeconds, true, false, "[Web Server]") // force HTTP/1 ; disallow large headers, the purpose of this service is public web mostly

	//-- rate limit decision

	var useRateLimit bool = ((rateLimit > 0) && (rateBurst > 0))
	if(useRateLimit) { // RATE LIMIT
		log.Println("[META]", "Web Server: HTTP/S Rate Limiter # Limit:", rateLimit, "Burst:", rateBurst)
	} //end if

	//-- http master / root handler: will manage all the rest of sub-handlers

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//-- panic recovery
		defer smart.PanicHandler() // safe recovery handler
		//-- get real client IP
		realClientIp := getVisitorRealIpAddr(r)
		//--
		//== rate limit interceptor (must be first)
		if(useRateLimit) { // RATE LIMIT
			var isRateLimited bool = smarthttputils.HttpServerIsIpRateLimited(r, rateLimit, rateBurst)
			if(isRateLimited) { // if the current request/ip is rate limited
				log.Printf("[SRV] Web Server: Rate Limit :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "429", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus429(w, r, "Rate Limit: Your IP Address have submitted too many requests in a short period of time and have exceeded the number of allowed requests. Try again in few minutes.", true)
				return
			} //end if
		} //end if
		//== #end rate limit
		//--
		var urlPath string = smart.GetHttpPathFromRequest(r)
		if(urlPath == "") {
			urlPath = "/"
		} //end if
		//--
		//== webDAV
		if(webdavOptions.Enabled == true) {
			if((urlPath == webDavUrlPath()) || (smart.StrStartsWith(urlPath, webDavUrlPath()+"/"))) { // {{{SYNC-WEBSRV-ROUTE-WEBDAV}}}
				webDavHttpHandler(w, r, webdavOptions.SharedMode, webdavOptions.SmartSafePaths, isAuthActive, allowedIPs, authUser, authPass, customAuthCheck)
				return
			} //end if
		} //end if
		//--
		//== serving area (in order): assets (public) ; routes (depends how a route is set by urlHandlersSkipAuth) ; public files (public or n/a, depends if public files serving is enabled or not)
		//-- uuid
		manageSessUUIDCookie(w, r) // manage session UUID Cookie
		//-- shiftPath
		headPath, tailPaths := getUrlPathSegments(urlPath) // head path or tail paths must not contain slashes !!
		//-- {{{SYNC-PATH-FROM-SLASH-REDIRECT}}} ; apache like fix but inversed: if path has / suffix remove and redirect ; this fix is needed because of tails implementation (shiftPath)
		if(smart.StrTrimWhitespaces(smart.StrTrim(urlPath, " /")) != "") { // avoid if root slash, will enter infinite cycle !
			if(smart.StrEndsWith(urlPath, "/")) {
				var fixedRoute string = smart.StrTrimWhitespaces(smart.StrTrim(urlPath, " /")) // trim on both sides, needs to add prefix below (Base Path)
				if(fixedRoute != "") {
					//--
					fixedRoute = smart.GetHttpProxyBasePath() + fixedRoute
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
		if((!webUrlRouteIsValid(urlPath)) || (!webUrlRouteIsValid("/"+headPath))) {
			log.Printf("[SRV] Web Server: Unsafe Request Path Detected :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "400", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus400(w, r, "Unsafe Request Path Detected [Rule:DENY]: `" + smart.GetHttpPathFromRequest(r) + "`", true)
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
				smarthttputils.HttpStatus405(w, r, "Invalid Request Method (" + r.Method + ") for Assets [Rule:DENY]: `" + smart.GetHttpPathFromRequest(r) + "`", true)
				return
			} //end if
			aCode := srvassets.WebAssetsHttpHandler(w, r, "cache:default") // default cache mode ; it is most common than public or private cache ...
			log.Printf("[SRV] Web Server Asset :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertUInt16ToStr(aCode), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			return
		} //end if else
		//-- manage handlers
		sr, okPath := urlHandlersMap["/"+headPath]
		if(okPath != true) {
			if(r.Method == "OPTIONS") {
				log.Printf("[SRV] Web Server: OPTIONS Request Method :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "200", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus200(w, r, "", "options.txt", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, map[string]string{"Allow":"OPTIONS, GET, HEAD"})
				return
			} //end if
			if((r.Method != "GET") && (r.Method != "HEAD")) {
				log.Printf("[SRV] Web Server: Invalid Request Method :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "405", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
				smarthttputils.HttpStatus405(w, r, "Invalid Request Method (" + r.Method + ") [Rule:DENY]: `" + smart.GetHttpPathFromRequest(r) + "`", true)
				return
			} //end if
			if((servePublicPath == true) && ((urlPath == "/") || (webUrlPathIsValid(urlPath) == true))) {
				if(((urlPath == "/") || (smart.PathExists(WEB_PUBLIC_RELATIVE_ROOT_PATH + smart.StrTrimLeft(urlPath, "/")) == true))) {
					pCode := webPublicHttpHandler(w, r)
					log.Printf("[SRV] Web Server: Public File :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertUInt16ToStr(pCode), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
					return
				} //end if
			} //end if
			log.Printf("[SRV] Web Server: Invalid Route :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "404", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus404(w, r, "Web Resource Not Found: `" + smart.GetHttpPathFromRequest(r) + "`", true)
			return
		} //end if
		if((sr.MaxTailSegments >= 0) && (len(tailPaths) > sr.MaxTailSegments)) { // if sr.MaxTailSegments is -1, pass to controller
			log.Printf("[SRV] Web Server: Invalid Internal Route for [/%s] (Max Tail is %d) :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", headPath, sr.MaxTailSegments, "404", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus404(w, r, "Web Resource Not Found: `" + smart.GetHttpPathFromRequest(r) + "`", true)
			return
		} //end if
		if(r.Method == "OPTIONS") {
			log.Printf("[SRV] Web Server: OPTIONS Request Method for Internal Route :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "200", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus200(w, r, "", "options.txt", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, map[string]string{"Allow":listMethods(sr.AllowedMethods)})
			return
		} //end if
		if(!smart.InListArr(r.Method, sr.AllowedMethods)) {
			log.Printf("[SRV] Web Server: Invalid Request Method for Internal Route :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "405", r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
			smarthttputils.HttpStatus405(w, r, "Invalid Request Method (" + r.Method + ") for Internal Route [Rule:DENY]: `" + smart.GetHttpPathFromRequest(r) + "`", true)
			return
		} //end if
		//-- auth check (if set so)
		var authErr error = nil
		var authData smart.AuthDataStruct
		if((isAuthActive == true) && (sr.AuthSkip != true)) { // this check must be before executing fx below
			authErr, authData = smarthttputils.HttpBasicAuthCheck(w, r, HTTP_AUTH_REALM, authUser, authPass, allowedIPs, customAuthCheck, true) // outputs: HTML
			if((authErr != nil) || (authData.OK != true) || (authData.ErrMsg != "")) {
				log.Println("[WARNING]", "Web Server: Authentication Failed:", "authData.OK:", authData.OK, "authData.ErrMsg:", authData.ErrMsg, "Error:", authErr)
				// MUST NOT USE HERE: smarthttputils.HttpStatus401() ; it is handled directly by smarthttputils.HttpBasicAuthCheck()
				return
			} //end if
		} //end if
		//-- #end auth check
		timerStart := time.Now()
		code, content, contentFileName, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers := sr.FxHandler(r, headPath, tailPaths, authData)
		timerDuration := time.Since(timerStart)
		//-- fixes for default params
		if(cacheExpiration <= 0) { // for easing the development if cacheExpiration is not specified the default value is zero but actually for no-cache -1 is needed ; this fix is needed because in http utils cache zero means at least 60 seconds ... and -1 is no cache !
			cacheExpiration = -1 // if cacheExpiration is not explicit set to a value greater than zero in controller consider is no-cache
			cacheLastModified = "" // mandatory for no cache, cannot be otherwise ...
			cacheControl = smarthttputils.CACHE_CONTROL_NOCACHE // mandatory for no cache, cannot be otherwise ...
		} else { // if cache is set and no explicit
			switch(cacheControl) {
				case smarthttputils.CACHE_CONTROL_PRIVATE:
					break
				case smarthttputils.CACHE_CONTROL_PUBLIC:
					break
				case smarthttputils.CACHE_CONTROL_DEFAULT:
					break
				default:
					cacheControl = smarthttputils.CACHE_CONTROL_DEFAULT // if no explicit value is set, set to default
			} //end switch
		} //end if
		contentFileName = smart.StrTrimWhitespaces(contentFileName)
		if(!smart.PathIsSafeValidSafeFileName(contentFileName)) {
			contentFileName = ""
		} //end if
		contentDisposition = smart.StrToLower(smart.StrTrimWhitespaces(contentDisposition))
		if((contentDisposition != smarthttputils.DISP_TYPE_INLINE) && (contentDisposition != smarthttputils.DISP_TYPE_ATTACHMENT)) {
			contentDisposition = ""
		} //end if
		//--
		log.Println("[META]", "Web Server: Internal Route :: Handler Execution Time:", timerDuration, "# Route: `" + urlPath + "`")
		log.Printf("[SRV] Web Server: Internal Route :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertIntToStr(int(code)), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
		//--
		var fExt string = ""
		if((contentFileName != "") && (!smart.StrContains(contentFileName, "://"))) {
			fExt = smart.StrTrimWhitespaces(smart.StrToLower(smart.PathBaseExtension(contentFileName)))
		} //end if
		//--
		var isHtmlAnswer bool = false
		if((fExt == "") || (fExt == "html") || (fExt == "htm")) {
			isHtmlAnswer = true
		} //end if
		//--
		switch(code) {
			//-- ok status codes
			case 200:
				smarthttputils.HttpStatus200(w, r, content, contentFileName, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			case 202:
				smarthttputils.HttpStatus202(w, r, content, contentFileName, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			case 203:
				smarthttputils.HttpStatus203(w, r, content, contentFileName, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			case 204:
				smarthttputils.HttpStatus204(w, r, content, contentFileName, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			case 208:
				smarthttputils.HttpStatus208(w, r, content, contentFileName, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			//-- redirect 3xx statuses
			case 301:
				smarthttputils.HttpStatus301(w, r, content, isHtmlAnswer) // for 3xx the content is the redirect URL
				break
			case 302:
				smarthttputils.HttpStatus302(w, r, content, isHtmlAnswer) // for 3xx the content is the redirect URL
				break
			//-- client errors
			case 400:
				smarthttputils.HttpStatus400(w, r, content, isHtmlAnswer)
				break
			case 401:
				smarthttputils.HttpStatus401(w, r, content, isHtmlAnswer)
				break
			case 403:
				smarthttputils.HttpStatus403(w, r, content, isHtmlAnswer)
				break
			case 404:
				smarthttputils.HttpStatus404(w, r, content, isHtmlAnswer)
				break
			case 405:
				smarthttputils.HttpStatus405(w, r, content, isHtmlAnswer)
				break
			case 410:
				smarthttputils.HttpStatus410(w, r, content, isHtmlAnswer)
				break
			case 422:
				smarthttputils.HttpStatus422(w, r, content, isHtmlAnswer)
				break
			case 429:
				smarthttputils.HttpStatus429(w, r, content, isHtmlAnswer)
				break
			//-- server errors
			case 500:
				smarthttputils.HttpStatus500(w, r, content, isHtmlAnswer)
				break
			case 501:
				smarthttputils.HttpStatus501(w, r, content, isHtmlAnswer)
				break
			case 502:
				smarthttputils.HttpStatus502(w, r, content, isHtmlAnswer)
				break
			case 503:
				smarthttputils.HttpStatus503(w, r, content, isHtmlAnswer)
				break
			case 504:
				smarthttputils.HttpStatus504(w, r, content, isHtmlAnswer)
				break
			//--
			default: // fallback to 500
				log.Println("[ERROR]", "Web Server: Invalid Application Level Status Code for the URL Path [" + urlPath + "]:", code)
				smarthttputils.HttpStatus500(w, r, "Invalid Application Level Status Code: `" + smart.ConvertIntToStr(int(code)) + "` for the URL Path: `" + smart.GetHttpPathFromRequest(r) + "`", isHtmlAnswer)
		} //end switch
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
