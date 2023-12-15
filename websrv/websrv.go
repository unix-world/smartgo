
// GO Lang :: SmartGo / Web Server :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231215.1336 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"fmt"

	"time"
	"bytes"

	"path/filepath"
	"net/http"

	smart "github.com/unix-world/smartgo"
	assets "github.com/unix-world/smartgo/web-assets"
	srvassets "github.com/unix-world/smartgo/web-srvassets"
	smarthttputils "github.com/unix-world/smartgo/web-httputils"
)

const (
	VERSION string = "r.20231215.1336"
	SIGNATURE string = "(c) 2020-2023 unix-world.org"

	SERVER_ADDR string = "127.0.0.1"
	SERVER_PORT uint16 = 13788

	WEBROOT_DIR  string = "./public"

	CERTIFICATES_DEFAULT_PATH string = "./ssl"
	CERTIFICATE_PEM_CRT string = "cert.crt"
	CERTIFICATE_PEM_KEY string = "cert.key"

	HTTP_AUTH_REALM string = "Smart.Web Server: Auth Area"

	REAL_IP_HEADER_KEY = "" // if used behind a proxy, can be set as: X-REAL-IP, X-FORWARDED-FOR, HTTP-X-CLIENT-IP, ... or any other trusted proxy header ; if no proxy is used, set as an empty string
)

const TheStrSignature string = "SmartGO Web Server " + VERSION

func WSrvSignature() bytes.Buffer {
	var serverSignature bytes.Buffer
	serverSignature.WriteString(TheStrSignature + "\n")
	serverSignature.WriteString(SIGNATURE + "\n")
	serverSignature.WriteString("\n")
	return serverSignature
}

type versionStruct struct {
	Version string `json:"version"`
}

type HttpHandlerFunc func(r *http.Request, authData smart.AuthDataStruct) (code uint16, content string, contentFnameOrRedirUrl string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string)

// EXTEND THESE
var UrlHandlersSkipAuth = map[string]bool{ // use a separate map for auth, not the handler itself to avoid use any other execution before successful auth if required
	"/": false,
}
var UrlHandlersMap = map[string]HttpHandlerFunc{
	"/": func(r *http.Request, authData smart.AuthDataStruct) (code uint16, content string, contentFnameOrRedirUrl string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
		remoteAddr, remotePort := smart.GetHttpRemoteAddrIpAndPortFromRequest(r)
		_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
		code = 208
		var headHtml string = ""
		var serverSignature bytes.Buffer = WSrvSignature()
		var bodyHtml string = "<h1>" + "Sample Home Page ..." + "</h1>" + "<h4>" + smart.StrNl2Br(smart.EscapeHtml(serverSignature.String())) + "</h4>" + "<hr>Your Real IP / Remote IP : Port # Address is: <b>`" + smart.EscapeHtml(realClientIp + "` / `" + remoteAddr + "`:`" + remotePort + "`") + "</b>"
		content = srvassets.HtmlServerTemplate(TheStrSignature, headHtml, bodyHtml)
		contentFnameOrRedirUrl = "index.html"
		contentDisposition = ""
		cacheExpiration = -1
		cacheLastModified = ""
		cacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
		headers = make(map[string]string)
		headers["Z-Sample-Header"] = "Home Page"
		return
	},
	"/status": func(r *http.Request, authData smart.AuthDataStruct) (code uint16, content string, contentFnameOrRedirUrl string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
		code = 202
		var headHtml string = "<style>" + "\n" + "div.status { text-align:center; margin:10px; cursor:help; }" + "\n" + "div.signature { background:#778899; color:#FFFFFF; font-size:2rem; font-weight:bold; text-align:center; border-radius:3px; padding:10px; margin:20px; }" + "\n" + "</style>"
		var serverSignature bytes.Buffer = WSrvSignature()
		var bodyHtml string = `<div class="status"><img alt="Status: Up and Running ..." title="Status: Up and Running ..." width="64" height="64" src="data:image/svg+xml,` + smart.EscapeHtml(smart.EscapeUrl(assets.ReadWebAsset("lib/framework/img/loading-spin.svg"))) + `"></div>` + "\n" + `<div class="signature">` + "\n" + "<pre>" + "\n" + smart.EscapeHtml(serverSignature.String()) + "</pre>" + "\n" + "</div>"
		content = assets.HtmlStandaloneTemplate(TheStrSignature, headHtml, bodyHtml)
		contentFnameOrRedirUrl = "status.html"
		contentDisposition = ""
		cacheExpiration = -1
		cacheLastModified = ""
		cacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
		headers = nil
		return
	},
	"/version": func(r *http.Request, authData smart.AuthDataStruct) (code uint16, content string, contentFnameOrRedirUrl string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
		code = 203
		ver := versionStruct{}
		ver.Version = TheStrSignature
		content = smart.JsonNoErrChkEncode(ver, false, false)
		contentFnameOrRedirUrl = "version.json"
		contentDisposition = ""
		cacheExpiration = -1
		cacheLastModified = ""
		cacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
		headers = nil
		return
	},
}


func WebServerRun(httpHeaderKeyRealIp string, webRootPath string, serveSecure bool, certifPath string, httpAddr string, httpPort uint16, timeoutSeconds uint32, allowedIPs string, authUser string, authPass string, customAuthCheck smarthttputils.HttpAuthCheckFunc) bool {

	//-- settings

	httpHeaderKeyRealIp = smart.StrToUpper(smart.StrTrimWhitespaces(httpHeaderKeyRealIp))
	if(httpHeaderKeyRealIp != "") { // if no proxy, don't set
		smart.SetSafeRealClientIpHeaderKey(httpHeaderKeyRealIp)
	} //end if

	//-- auth user / pass

	var isAuthActive bool = false
	authUser = smart.StrTrimWhitespaces(authUser)
	if(authUser != "") {
		isAuthActive = true
		if(smart.StrTrimWhitespaces(authPass) == "") {
			log.Println("[ERROR] Web Server: Empty Auth Password when a UserName is Set")
			return false
		} //end if
		if(customAuthCheck != nil) {
			log.Println("[ERROR] Web Server: Auth User / Pass is set but also a custom Auth Handler")
			return false
		} //end if
	} else if(customAuthCheck != nil) {
		isAuthActive = true
		if((smart.StrTrimWhitespaces(authUser) != "") && (smart.StrTrimWhitespaces(authPass) != "")) {
			log.Println("[ERROR] Web Server: Custom Auth Handler is Set but also Auth User / Pass")
			return false
		} //end if
	} //end if

	//-- http(s) address and port(s)

	httpAddr = smart.StrTrimWhitespaces(httpAddr)
	if((!smart.IsNetValidIpAddr(httpAddr)) && (!smart.IsNetValidHostName(httpAddr))) {
		log.Println("[WARNING] Web Server: Invalid Server Address (Host):", httpAddr, "using the default host:", SERVER_ADDR)
		httpAddr = SERVER_ADDR
	} //end if

	if(!smart.IsNetValidPortNum(int64(httpPort))) {
		log.Println("[WARNING] Web Server: Invalid Server Address (Port):", httpPort, "using the default port:", SERVER_PORT)
		httpPort = SERVER_PORT
	} //end if

	//-- paths

	if(serveSecure == true) {
		certifPath = smart.StrTrimWhitespaces(certifPath)
		certifPath = filepath.ToSlash(certifPath)
		if((certifPath == "") || (smart.PathIsBackwardUnsafe(certifPath) == true)) {
			certifPath = CERTIFICATES_DEFAULT_PATH
		} //end if
		certifPath = smart.PathGetAbsoluteFromRelative(certifPath)
		certifPath = smart.PathAddDirLastSlash(certifPath)
	} else {
		certifPath = CERTIFICATES_DEFAULT_PATH
	} //end if

	webRootPath = smart.StrTrimWhitespaces(webRootPath)
	webRootPath = filepath.ToSlash(webRootPath)
	if((webRootPath == "") || (smart.PathIsBackwardUnsafe(webRootPath) == true)) {
		webRootPath = WEBROOT_DIR
	} //end if
	webRootPath = smart.PathGetAbsoluteFromRelative(webRootPath)
	webRootPath = smart.PathAddDirLastSlash(webRootPath)
	if((!smart.PathExists(webRootPath)) || (!smart.PathIsDir(webRootPath))) {
		log.Println("[ERROR] Web Server: WebRoot Path does not Exists or Is Not a Valid Directory:", webRootPath)
		return false
	} //end if

	//-- for web

	var serverSignature bytes.Buffer = WSrvSignature()

	if(serveSecure == true) {
		serverSignature.WriteString("<Secure URL> :: https://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + "/" + "\n")
	} else {
		serverSignature.WriteString("<URL> :: http://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + "/" + "\n")
	} //end if

	//-- for console

	if(serveSecure != true) {
		log.Println("Starting Web Server: http://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + " @ HTTPS/Mux/Insecure # " + VERSION)
	} else {
		log.Println("Starting Web Server: https://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + " @ HTTPS/Mux/TLS # " + VERSION)
		log.Println("[NOTICE] Web Server Certificates Path:", certifPath)
	} //end if else
	log.Println("[INFO] Web Server WebRoot Path:", webRootPath)

	//-- server

	mux, srv := smarthttputils.HttpMuxServer(httpAddr + fmt.Sprintf(":%d", httpPort), timeoutSeconds, true, "[Web Server]") // force HTTP/1

	//-- handlers

	// http root handler : 202 | 404
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		//--
		var theUrlPath string = smart.StrTrimWhitespaces(string(r.URL.Path))
		theUrlPath = smart.StrTrimRight(theUrlPath, "/")
		theUrlPath = smart.StrTrimWhitespaces(theUrlPath)
		if(theUrlPath == "") {
			theUrlPath = "/"
		} //end if
		if(smart.StrStartsWith(theUrlPath, "/lib/")) {
			srvassets.WebAssetsHttpHandler(w, r, "", "cache:private") // use default mime disposition ; private cache mode
			return
		} //end if
		//--
		fx, okPath := UrlHandlersMap[theUrlPath]
		if((okPath != true) || (fx == nil)) {
			smarthttputils.HttpStatus404(w, r, "Web Resource Not Found: `" + r.URL.Path + "`", true)
			return
		} //end if
		//--
		var useAuth bool = true
		if(UrlHandlersSkipAuth != nil) {
			skipAuth, okAuth := UrlHandlersSkipAuth[theUrlPath]
			if((okAuth == true) && (skipAuth == true)) {
				useAuth = false
			} //end if
		} //end if
		var authErr error = nil
		var authData smart.AuthDataStruct
		if((isAuthActive == true) && (useAuth == true)) { // this check must be before executing fx below
			authErr, authData = smarthttputils.HttpBasicAuthCheck(w, r, HTTP_AUTH_REALM, authUser, authPass, allowedIPs, customAuthCheck, true) // outputs: HTML
			if(authErr != nil) {
				log.Println("[WARNING] Web Server: Authentication Failed:", authErr)
				return
			} //end if
		} //end if
		//--
		timerStart := time.Now()
		code, content, contentFnameOrRedirUrl, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers := fx(r, authData)
		timerDuration := time.Since(timerStart)
		//--
		_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
		log.Printf("[OK] Web Server :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertIntToStr(int(code)), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
		//--
		var fExt string = ""
		if((contentFnameOrRedirUrl != "") && (!smart.StrContains(contentFnameOrRedirUrl, "://"))) {
			fExt = smart.StrTrimWhitespaces(smart.StrToLower(smart.PathBaseExtension(contentFnameOrRedirUrl)))
		} //end if
		//--
		var isHtmlAnswer bool = false
		if((fExt == "") || (fExt == "html") || (fExt == "htm")) {
			isHtmlAnswer = true
		} //end if
		//--
		log.Println("Web Server: StatusCode:", code, "# Path: `" + theUrlPath + "`", "# ExecutionTime:", timerDuration)
		switch(code) {
			//-- ok status codes
			case 200:
				smarthttputils.HttpStatus200(w, r, content, contentFnameOrRedirUrl, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			case 202:
				smarthttputils.HttpStatus202(w, r, content, contentFnameOrRedirUrl, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			case 203:
				smarthttputils.HttpStatus203(w, r, content, contentFnameOrRedirUrl, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			case 208:
				smarthttputils.HttpStatus208(w, r, content, contentFnameOrRedirUrl, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
				break
			//-- redirect 3xx statuses
			case 301:
				smarthttputils.HttpStatus301(w, r, content, true) // this must be HTML, is URL not File to get a valid extension (above)
				break
			case 302:
				smarthttputils.HttpStatus302(w, r, content, true) // this must be HTML, is URL not File to get a valid extension (above)
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
			case 410:
				smarthttputils.HttpStatus410(w, r, content, isHtmlAnswer)
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
				log.Println("[ERROR] Web Server: Invalid Application Level Status Code for the URL Path [" + theUrlPath + "]:", code)
				smarthttputils.HttpStatus500(w, r, "Invalid Application Level Status Code: `" + smart.ConvertIntToStr(int(code)) + "` for the URL Path: `" + r.URL.Path + "`", isHtmlAnswer)
		} //end switch
	})

	// serve logic

	if(serveSecure == true) { // serve HTTPS
		var theTlsCertPath string = certifPath + CERTIFICATE_PEM_CRT
		var theTlsKeyPath  string = certifPath + CERTIFICATE_PEM_KEY
		if(!smart.PathIsFile(theTlsCertPath)) {
			log.Println("[ERROR] Web Server / INIT TLS: No certificate crt found in current directory. Please provide a valid cert:", theTlsCertPath)
			return false
		} //end if
		if(!smart.PathIsFile(theTlsKeyPath)) {
			log.Println("[ERROR]: Web Server / INIT TLS No certificate key found in current directory. Please provide a valid cert:", theTlsKeyPath)
			return false
		} //end if
		log.Println("[NOTICE] Web Server is serving HTTPS/TLS at " + httpAddr + " on port", httpPort)
		go srv.ListenAndServeTLS(theTlsCertPath, theTlsKeyPath)
	} else { // serve HTTP
		log.Println("[NOTICE] Web Server serving HTTP at " + httpAddr + " on port", httpPort)
		go srv.ListenAndServe()
	} //end if

	//--
	return true
	//--

} //END FUNCTION


// #END
