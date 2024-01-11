
// GO Lang :: SmartGo / WebDAV Server :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240111.1742 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package webdavsrv

import (
	"log"
	"fmt"

	"context"
	"bytes"

	"net/http"

	webdav "github.com/unix-world/smartgo/web/webdav" // a modified version of [golang.org / x / net / webdav]: added extra path security checks
	smart "github.com/unix-world/smartgo"
	assets "github.com/unix-world/smartgo/web/assets/web-assets"
	smarthttputils "github.com/unix-world/smartgo/web/httputils"
)

const (
	VERSION string = "r.20240111.1742"
	SIGNATURE string = "(c) 2020-2024 unix-world.org"

	SERVER_ADDR string = "127.0.0.1"
	SERVER_PORT uint16 = 17787

	STORAGE_DIR  string = "./webdav"
	DAV_PATH     string = "webdav"

	CERTIFICATES_DEFAULT_PATH string = "./ssl/"
	CERTIFICATE_PEM_CRT string = "cert.crt"
	CERTIFICATE_PEM_KEY string = "cert.key"

	HTTP_AUTH_REALM string = "Smart.WebDAV Server: Storage Area"
)


// IMPORTANT: If using Proxy with different PROXY_HTTP_BASE_PATH than "/" (ex: "/dav/") the Proxy MUST NOT strip back PROXY_HTTP_BASE_PATH to "/" for this backend
func WebdavServerRun(smartSafeValidPaths bool, sharedStorage bool, storagePath string, serveSecure bool, certifPath string, httpAddr string, httpPort uint16, timeoutSeconds uint32, allowedIPs string, authUser string, authPass string, customAuthCheck smarthttputils.HttpAuthCheckFunc, rateLimit int, rateBurst int) int16 {

	// if smartSafeValidPaths will validate paths using PathIsSafeValidSafePath() otherwise using only PathIsSafeValidPath()

	//--
	// this method should return (error codes) just int16 positive values and zero if ok ; negative values are reserved for outsite managers
	//--

	defer smart.PanicHandler()

	//-- auth user / pass

	var isAuthActive bool = false
	authUser = smart.StrTrimWhitespaces(authUser)
	if(authUser != "") {
		isAuthActive = true
		if(smart.StrTrimWhitespaces(authPass) == "") {
			log.Println("[ERROR] WebDAV Server: Empty Auth Password when a UserName is Set")
			return 1100
		} //end if
		if(customAuthCheck != nil) {
			log.Println("[ERROR] WebDAV Server: Auth User / Pass is set but also a custom Auth Handler")
			return 1101
		} //end if
	} else if(customAuthCheck != nil) {
		isAuthActive = true
		if((smart.StrTrimWhitespaces(authUser) != "") && (smart.StrTrimWhitespaces(authPass) != "")) {
			log.Println("[ERROR] WebDAV Server: Custom Auth Handler is Set but also Auth User / Pass")
			return 1102
		} //end if
	} //end if

	if(isAuthActive) {
		//--
		authProviders := listActiveWebAuthProviders()
		//--
		if(len(authProviders) > 0) {
			log.Println("[OK]", "WebDAV Server: Authentication is ENABLED using these Auth Providers:", authProviders)
		} else {
			log.Println("[ERROR]", "WebDAV Server: Authentication is ENABLED but there are no active Auth Providers")
			return 1103
		} //end if else
		//--
	} else {
		//--
		log.Println("[ERROR]", "WebDAV Server: Authentication is NOT ENABLED")
		return 1104
		//--
	} //end if

	//-- http(s) address and port(s)

	httpAddr = smart.StrTrimWhitespaces(httpAddr)
	if((!smart.IsNetValidIpAddr(httpAddr)) && (!smart.IsNetValidHostName(httpAddr))) {
		log.Println("[WARNING] WebDAV Server: Invalid Server Address (Host):", httpAddr, "using the default host:", SERVER_ADDR)
		httpAddr = SERVER_ADDR
	} //end if
	if(smart.StrContains(httpAddr, ":")) {
		httpAddr = "[" + httpAddr + "]" // {{{SYNC-SMART-SERVER-DOMAIN-IPV6-BRACKETS}}}
	} //end if

	if(!smart.IsNetValidPortNum(int64(httpPort))) {
		log.Println("[WARNING] WebDAV Server: Invalid Server Address (Port):", httpPort, "using the default port:", SERVER_PORT)
		httpPort = SERVER_PORT
	} //end if

	//-- paths

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

	storagePath = smart.StrTrimWhitespaces(storagePath)
	storagePath = smart.SafePathFixSeparator(storagePath)
	if((storagePath == "") || (smart.PathIsSafeValidSafePath(storagePath) != true) || (smart.PathIsBackwardUnsafe(storagePath) == true)) {
		storagePath = STORAGE_DIR
	} //end if
	storagePath = smart.PathGetAbsoluteFromRelative(storagePath)
	if((!smart.PathIsSafeValidPath(storagePath)) || (!smart.PathExists(storagePath)) || (!smart.PathIsDir(storagePath))) {
		log.Println("[ERROR] WebDAV Server: Storage Path does not Exists or Is Not a Valid Directory:", storagePath)
		return 1301
	} //end if
	if(sharedStorage != true) {
		if(!isAuthActive) {
			log.Println("[ERROR] WebDAV Server: Non-Shared Storage Can be used only when Authentication is ON")
			return 1302
		} //end if
	} //end if

	//-- for web

	var theStrSignature string = "SmartGO WebDAV Server " + VERSION

	var serverSignature bytes.Buffer
	serverSignature.WriteString(theStrSignature + "\n")
	serverSignature.WriteString(SIGNATURE + "\n")
	serverSignature.WriteString("\n")

	var realWebPath string = smart.GetHttpProxyBasePath() // this make sense to be different than / only under proxy, otherwise cannot coexist with another web service on the same port, but under proxy on the same port, a path prefix is needed ...
	var realWebDavPath string = realWebPath + DAV_PATH

	if(serveSecure == true) {
		serverSignature.WriteString("<Secure URL> :: https://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + realWebDavPath + "/" + "\n")
	} else {
		serverSignature.WriteString("<URL> :: http://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + realWebDavPath + "/" + "\n")
	} //end if

	//-- for console

	if(serveSecure != true) {
		log.Println("Starting WebDAV Server: http://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + realWebDavPath + "/" + " @ HTTPS/Mux/Insecure # " + VERSION)
	} else {
		log.Println("Starting WebDAV Server: https://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + realWebDavPath + "/" + " @ HTTPS/Mux/TLS # " + VERSION)
		log.Println("[NOTICE] WebDAV Server Certificates Path:", certifPath)
	} //end if else
	log.Println("[INFO] WebDAV Server Storage Path:", storagePath)

	//-- server

	mux, srv := smarthttputils.HttpMuxServer(httpAddr + fmt.Sprintf(":%d", httpPort), timeoutSeconds, true, false, "[WebDAV Server]") // force HTTP/1

	//-- rate limit decision

	var useRateLimit bool = ((rateLimit > 0) && (rateBurst > 0))
	if(useRateLimit) { // RATE LIMIT
		log.Println("[INFO]", "HTTP/S Rate Limiter", smart.CurrentFunctionName(), ":: Limit:", rateLimit, "Burst:", rateBurst)
	} //end if

	//-- webdav handler

	wdav := &webdav.Handler{
		Prefix:     realWebDavPath,
		FileSystem: webdav.Dir(storagePath),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			remoteAddr, remotePort := smart.GetHttpRemoteAddrIpAndPortFromRequest(r)
			_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
			if(err != nil) {
				log.Printf("[WARNING] WebDAV Server :: WEBDAV.ERROR: %s :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", err, "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
			} else {
				log.Printf("[LOG] WebDAV Server :: WEBDAV :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
			} //end if else
		},
	}

	//-- other handlers

	// http root handler : 202 | 404
	mux.HandleFunc(realWebPath, func(w http.ResponseWriter, r *http.Request) {
		//-- rate limit interceptor (must be first)
		if(useRateLimit) { // RATE LIMIT
			var isRateLimited bool = smarthttputils.HttpServerIsIpRateLimited(r, rateLimit, rateBurst)
			if(isRateLimited) { // if the current request/ip is rate limited
				smarthttputils.HttpStatus429(w, r, "Rate Limit: Your IP Address have submitted too many requests in a short period of time and have exceeded the number of allowed requests. Try again in few minutes.", true)
				return
			} //end if
		} //end if
		//-- #end rate limit
		var theUrlPath string = smart.GetHttpPathFromRequest(r)
		//-- method check
		if((r.Method != http.MethodHead) && (r.Method != http.MethodGet)) {
			smarthttputils.HttpStatus405(w, r, "WebDAV Method Disallowed [" + r.Method + "] for this path: `" + theUrlPath + "`", true)
			return
		} //end if
		//-- path check
		if(theUrlPath != realWebPath) { // avoid serve anything else
			smarthttputils.HttpStatus404(w, r, "WebDAV Resource Not Found: `" + theUrlPath + "`", true)
			return
		} //end if
		//--
		_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
		log.Printf("[LOG] WebDAV Server :: DEFAULT :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertIntToStr(202), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
		var headHtml string = "<style>" + "\n" + "div.status { text-align:center; margin:10px; cursor:help; }" + "\n" + "div.signature { background:#778899; color:#FFFFFF; font-size:2rem; font-weight:bold; text-align:center; border-radius:3px; padding:10px; margin:20px; }" + "\n" + "</style>"
		var bodyHtml string = `<div class="status"><img alt="Status: Up and Running ..." title="Status: Up and Running ..." width="64" height="64" src="data:image/svg+xml,` + smart.EscapeHtml(smart.EscapeUrl(assets.ReadWebAsset("lib/framework/img/loading-spin.svg"))) + `"></div>` + "\n" + `<div class="signature">` + "\n" + "<pre>" + "\n" + smart.EscapeHtml(serverSignature.String()) + "</pre>" + "\n" + "</div>"
		smarthttputils.HttpStatus202(w, r, assets.HtmlStandaloneTemplate(theStrSignature, headHtml, bodyHtml), "index.html", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, nil)
		//--
	})

	// http version handler : 203
	mux.HandleFunc(realWebPath + "version", func(w http.ResponseWriter, r *http.Request) {
		//-- rate limit interceptor (must be first)
		if(useRateLimit) { // RATE LIMIT
			var isRateLimited bool = smarthttputils.HttpServerIsIpRateLimited(r, rateLimit, rateBurst)
			if(isRateLimited) { // if the current request/ip is rate limited
				smarthttputils.HttpStatus429(w, r, "Rate Limit: Your IP Address have submitted too many requests in a short period of time and have exceeded the number of allowed requests. Try again in few minutes.", false)
				return
			} //end if
		} //end if
		//-- #end rate limit
		var theUrlPath string = smart.GetHttpPathFromRequest(r)
		//-- method check
		if((r.Method != http.MethodHead) && (r.Method != http.MethodGet)) {
			smarthttputils.HttpStatus405(w, r, "WebDAV Method Disallowed [" + r.Method + "] for this path: `" + theUrlPath + "`", true)
			return
		} //end if
		//-- path check
		if(theUrlPath != realWebPath + "version") { // avoid serve anything else
			smarthttputils.HttpStatus404(w, r, "WebDAV Resource Not Found: `" + theUrlPath + "`", false)
			return
		} //end if
		//--
		_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
		log.Printf("[LOG] WebDAV Server :: VERSION :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertIntToStr(202), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
		smarthttputils.HttpStatus203(w, r, theStrSignature + "\n", "version.txt", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, nil)
		//--
	})

	// webdav handler : all webdav status codes ...
	davHandler := func(w http.ResponseWriter, r *http.Request) {
		//-- rate limit interceptor (must be first)
		if(useRateLimit) { // RATE LIMIT
			var isRateLimited bool = smarthttputils.HttpServerIsIpRateLimited(r, rateLimit, rateBurst)
			if(isRateLimited) { // if the current request/ip is rate limited
				smarthttputils.HttpStatus429(w, r, "Rate Limit: Your IP Address have submitted too many requests in a short period of time and have exceeded the number of allowed requests. Try again in few minutes.", false)
				return
			} //end if
		} //end if
		//-- #end rate limit
		var theUrlPath string = smart.GetHttpPathFromRequest(r)
		//-- auth check
		if(isAuthActive) {
			authErr, authData := smarthttputils.HttpBasicAuthCheck(w, r, HTTP_AUTH_REALM, authUser, authPass, allowedIPs, customAuthCheck, false) // outputs: TEXT
			if((authErr != nil) || (authData.OK != true) || (authData.ErrMsg != "")) {
				log.Println("[WARNING] WebDAV Server / Storage Area :: Authentication Failed:", "authData.OK:", authData.OK, "authData.ErrMsg:", authData.ErrMsg, "Error:", authErr)
				// MUST NOT USE smarthttputils.HttpStatus401() here, is handled directly by smarthttputils.HttpBasicAuthCheck()
				return
			} //end if
			if(sharedStorage != true) {
				if(smart.PathIsSafeValidFileName(authData.UserID) != true) {
					log.Println("[ERROR]", "WebDAV Server", "Invalid User ID (Unsafe): `" + authData.UserID + "`")
					smarthttputils.HttpStatus403(w, r, "WebDAV: Invalid User ID (Unsafe): `" + authData.UserID + "`", true)
					return
				} //end if
				var theUserPath string = smart.PathAddDirLastSlash(storagePath) + authData.UserID
				if((smart.PathIsSafeValidPath(theUserPath) != true) || (smart.PathIsBackwardUnsafe(theUserPath) == true)) {
					log.Println("[ERROR]", "WebDAV Server", "Invalid User Path (Unsafe): `" + theUserPath + "`")
					smarthttputils.HttpStatus403(w, r, "WebDAV: Invalid User Path (Unsafe): `" + theUserPath + "`", true)
					return
				} //end if
				if(smart.PathIsFile(theUserPath)) {
					log.Println("[ERROR]", "WebDAV Server", "Invalid User Path cannot be created (is a file): `" + theUserPath + "`")
					smarthttputils.HttpStatus403(w, r, "WebDAV: User Path cannot be created: `" + theUserPath + "`", true)
					return
				} //end if
				if(!smart.PathExists(theUserPath)) {
					okUserPath, errUserPath := smart.SafePathDirCreate(theUserPath, false, true)
					if(errUserPath != nil) {
						log.Println("[ERROR]", "WebDAV Server", "Error while Creating the User Path:", theUserPath, "Err:", errUserPath)
						smarthttputils.HttpStatus403(w, r, "WebDAV: User Path Cannot be created (Error): `" + theUserPath + "`", true)
						return
					} else if(okUserPath != true) {
						log.Println("[ERROR]", "WebDAV Server", "Failed to Create User Path:", theUserPath)
						smarthttputils.HttpStatus403(w, r, "WebDAV: User Path Cannot be created: `" + theUserPath + "`", true)
						return
					} //end if
				} //end if
				if(!smart.PathExists(theUserPath)) {
					log.Println("[ERROR]", "WebDAV Server", "Invalid User Path is N/A (missing): `" + theUserPath + "`")
					smarthttputils.HttpStatus403(w, r, "WebDAV: User Path is N/A: `" + theUserPath + "`", true)
					return
				} //end if
				wdav.FileSystem = webdav.Dir(theUserPath)
			} //end if // storagePath
		} //end if
		//-- #end auth check
		if(r.Method == http.MethodPost) { // disallow POST method, is dangerous for setting paths out of normal mode, with Non-Shared/Auth dir structure
			smarthttputils.HttpStatus405(w, r, "WebDAV Method Disallowed [" + r.Method + "] for this path: `" + theUrlPath + "`", true)
			return
		} else if(r.Method == http.MethodGet) {
			var wdirPath string = smart.StrSubstr(r.URL.Path, len(realWebDavPath), 0)
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
		log.Println("[DEBUG]", "WebDAV Server", "Method:", r.Method, "Depth:", r.Header.Get("Depth"))
		//--
		wdav.ServeHTTP(w, r, smartSafeValidPaths) // if all ok above (basic auth + credentials ok, serve ...)
		//--
	}
	mux.HandleFunc(realWebDavPath,       davHandler) // serve without "/" suffix # this is a fix to work also with gvfs
	mux.HandleFunc(realWebDavPath + "/", davHandler) // serve classic, with "/" suffix

	// serve logic: is better to manage outside the async calls because extra monitoring logic can be implemented !

	if(serveSecure == true) { // serve HTTPS
		var theTlsCertPath string = certifPath + CERTIFICATE_PEM_CRT
		var theTlsKeyPath  string = certifPath + CERTIFICATE_PEM_KEY
		if(!smart.PathIsFile(theTlsCertPath)) {
			log.Println("[ERROR] WebDAV Server / INIT TLS: No certificate crt found in current directory. Please provide a valid cert:", theTlsCertPath)
			return 2101
		} //end if
		if(!smart.PathIsFile(theTlsKeyPath)) {
			log.Println("[ERROR]: WebDAV Server / INIT TLS No certificate key found in current directory. Please provide a valid cert:", theTlsKeyPath)
			return 2102
		} //end if
		log.Println("[OK] WebDAV Server is Ready for Serving HTTPS/TLS at " + httpAddr + " on port", httpPort)
		errServeTls := srv.ListenAndServeTLS(theTlsCertPath, theTlsKeyPath)
		if(errServeTls != nil) {
			log.Println("[ERROR]", "WebDAV Server: Fatal Service Init Error:", errServeTls)
			return 3001
		} //end if
	} else { // serve HTTP
		log.Println("[OK] WebDAV Server Ready for Serving HTTP at " + httpAddr + " on port", httpPort)
		errServe := srv.ListenAndServe()
		if(errServe != nil) {
			log.Println("[ERROR]", "WebDAV Server: Fatal Service Init Error:", errServe)
			return 3002
		} //end if
	} //end if

	//--
	return 0
	//--

} //END FUNCTION


func listActiveWebAuthProviders() []string {
	//--
	var authProviders []string = []string{}
	if(smart.AuthBasicIsEnabled() == true) {
		authProviders = append(authProviders, "Auth:Basic")
	} //end if
	if(smart.AuthBearerIsEnabled() == true) {
		authProviders = append(authProviders, "Auth:Bearer")
	} //end if
	if(smart.AuthCookieIsEnabled() == true) {
		authProviders = append(authProviders, "Auth:Cookie")
	} //end if
	//--
	return authProviders
	//--
} //END FUNCTION


// #END
