
// GO Lang :: SmartGo / Web HTTP Utils :: Smart.Go.Framework
// (c) 2020-2022 unix-world.org
// r.20220415.0128 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package httputils

import (
	"log"
	"time"

	"net/http"
	"crypto/tls"
	"crypto/x509"
	"crypto/subtle"

	smart 		"github.com/unix-world/smartgo"
	smartcache 	"github.com/unix-world/smartgo/simplecache"
	assets 		"github.com/unix-world/smartgo/web-assets"
)


//-----

const (
	VERSION string = "r.20220415.0128"

	DEBUG bool = false
	DEBUG_CACHE bool = false

	DEFAULT_REALM string = "SmartGO Web Server" // must be min 7 chars

	DISP_TYPE_INLINE string = "inline"
	DISP_TYPE_ATTACHMENT string = "attachment"
	MIME_TYPE_DEFAULT string = "application/octet-stream"

	CACHE_CLEANUP_INTERVAL uint32 = 5 // 5 seconds
	CACHE_EXPIRATION uint32 = 300 // 300 seconds = 5 mins

	//--
	HTTP_STATUS_200 string = "200 OK"
	HTTP_STATUS_202 string = "202 Accepted"
	HTTP_STATUS_203 string = "203 Non-Authoritative Information"
	HTTP_STATUS_208 string = "208 Already Reported"
	//--
	HTTP_STATUS_301 string = "301 Moved Permanently"
	HTTP_STATUS_302 string = "302 Found" // "302 Moved Temporarily"
	//--
	HTTP_STATUS_400 string = "400 Bad Request"
	HTTP_STATUS_401 string = "401 Unauthorized"
	HTTP_STATUS_403 string = "403 Forbidden"
	HTTP_STATUS_404 string = "404 Not Found"
	HTTP_STATUS_429 string = "429 Too Many Requests"
	//--
	HTTP_STATUS_500 string = "500 Internal Server Error"
	//--

	//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
	HTTP_HEADER_CONTENT_TYPE string = "content-type"
	HTTP_HEADER_CONTENT_DISP string = "content-disposition"
	HTTP_HEADER_CONTENT_LEN  string = "content-length"
	//--
	HTTP_HEADER_CACHE_CTRL string = "cache-control"
	HTTP_HEADER_CACHE_PGMA string = "pragma"
	HTTP_HEADER_CACHE_EXPS string = "expires"
	HTTP_HEADER_CACHE_LMOD string = "last-modified"
	//--
	HTTP_HEADER_ETAG_SUM  string = "etag"
	HTTP_HEADER_ETAG_IFNM string = "if-none-match"
	//--
	HTTP_HEADER_SERVER_DATE string = "date"
	HTTP_HEADER_SERVER_SIGN string = "server"
	HTTP_HEADER_SERVER_POWERED string = "x-powered-by"
	//-- #end sync
)


//-----

var memAuthCache *smartcache.InMemCache = nil

//-----


func TlsConfigClient(insecureSkipVerify bool, serverPEM string) *tls.Config {
	//--
	cfg := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}
	//--
	if(insecureSkipVerify == true) {
		cfg.InsecureSkipVerify = true
		log.Println("[NOTICE] TlsConfigClient: InsecureSkipVerify was set to TRUE")
	} else {
		cfg.InsecureSkipVerify = false
	} //end if
	//--
	serverPEM = smart.StrTrimWhitespaces(serverPEM)
	if(serverPEM != "") {
		roots := x509.NewCertPool()
		ok := roots.AppendCertsFromPEM([]byte(serverPEM))
		if(ok) {
			cfg.RootCAs = roots
			log.Println("[NOTICE] TlsConfigClient: Appending a custom Server Certificate to the default x509 Root:", len(serverPEM), "bytes")
		} else {
			log.Println("[ERROR] TlsConfigClient: Failed to parse server certificate")
		} //end if
	} //end if
	//--
	return cfg
	//--
} //END FUNCTION


//-----


func TlsConfigServer() *tls.Config {
	//--
	cfg := &tls.Config{
		MinVersion: 		tls.VersionTLS12,
		MaxVersion: 		tls.VersionTLS13,
		CurvePreferences: 	[]tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, // tls1.2
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, // tls1.2
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // tls1.2
			tls.TLS_RSA_WITH_AES_256_CBC_SHA, // tls1.2
			tls.TLS_AES_256_GCM_SHA384, // tls1.3
			tls.TLS_CHACHA20_POLY1305_SHA256, // tls1.3
		},
	}
	//--
	return cfg
	//--
} //END FUNCTION


//-----


func TLSProtoHttpV1Server() map[string]func(*http.Server, *tls.Conn, http.Handler) {
	//--
	return make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0) // disable HTTP/2 on TLS (on non-TLS is always HTTP/1.1)
	//--
} //END FUNCTION


//-----


func HttpMuxServer(srvAddr string, timeoutSec uint32, forceHttpV1 bool) (*http.ServeMux, *http.Server) {
	//--
	mux := http.NewServeMux()
	//--
	srv := &http.Server{
		Addr: 				srvAddr,
		Handler: 			mux,
		TLSConfig: 			TlsConfigServer(),
		ReadTimeout: 		time.Duration(timeoutSec) * time.Second,
		ReadHeaderTimeout: 	0, // if set to zero, the value of ReadTimeout is used
		IdleTimeout:        0, // if set to zero, the value of ReadTimeout is used
		WriteTimeout: 		time.Duration(timeoutSec) * time.Second,
	}
	//--
	if(forceHttpV1 == true) {
		srv.TLSNextProto = TLSProtoHttpV1Server() // disable HTTP/2 on TLS (on non-TLS is always HTTP/1.1)
		log.Println("[NOTICE] HttpMuxServer: HTTP/1.1")
	} //end if
	//--
	return mux, srv
	//--
} //END FUNCTION


//-----


func HttpClientAuthBasicHeader(authUsername string, authPassword string) http.Header {
	//--
	return http.Header{"Authorization": {"Basic " + smart.Base64Encode(authUsername + ":" + authPassword)}}
	//--
} //END FUNCTION


//-----


func httpHeadersCacheControl(w http.ResponseWriter, r *http.Request, expiration int, modified string, control string) (isCachedContent bool) {
	//--
	const TZ_UTC = "UTC"
	//--
	modified = smart.StrTrimWhitespaces(modified)
	//--
	now := time.Now().UTC()
	//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
	w.Header().Set(HTTP_HEADER_SERVER_POWERED, "Smart.Framework.Go :: " + smart.VERSION)
	w.Header().Set(HTTP_HEADER_SERVER_SIGN, DEFAULT_REALM + " / " + VERSION)
	w.Header().Set(HTTP_HEADER_SERVER_DATE, now.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) + " " + TZ_UTC)
	//--
	if((expiration >= 0) && (modified != "")) {
		//--
		if(expiration < 60) {
			expiration = 60
		} //end if
		expdate := now.Add(time.Duration(expiration) * time.Second)
		//--
		if(control != "public") {
			control = "private"
		} //end if
		//--
		dtObjUtc := smart.DateTimeStructUtc(modified)
		if(dtObjUtc.Status == "OK") {
			modified = dtObjUtc.Years + "-" + dtObjUtc.Months + "-" + dtObjUtc.Days + " " + dtObjUtc.Hours + ":" + dtObjUtc.Minutes + ":" + dtObjUtc.Seconds // YYYY-MM-DD HH:II:SS
		} else {
			log.Println("[ERROR] HttpHeadersCacheControl: Invalid Modified Date:", modified)
			modified = now.Format(smart.DATE_TIME_FMT_ISO_STD_GO_EPOCH) // YYYY-MM-DD HH:II:SS
		} //end if
		if(DEBUG == true) {
			log.Println("[DEBUG] HttpHeadersCacheControl: Modified Date:", modified)
		} //end if
		//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
		w.Header().Set(HTTP_HEADER_CACHE_EXPS, expdate.Format(smart.DATE_TIME_FMT_ISO_STD_GO_EPOCH) + " " + TZ_UTC) // HTTP 1.0
		w.Header().Set(HTTP_HEADER_CACHE_PGMA, "cache") // HTTP 1.0 cache
		w.Header().Set(HTTP_HEADER_CACHE_LMOD, modified + " " + TZ_UTC)
		w.Header().Set(HTTP_HEADER_CACHE_CTRL, control + ", max-age=" + smart.ConvertIntToStr(expiration)) // HTTP 1.1 HTTP 1.1 (private will dissalow proxies to cache the content)
		//--
		return true
		//--
	} //end if else
	//-- {{{SYNC-HTTP-NOCACHE-HEADERS}}} ; // default expects ; expiration=-1 ; modified="" ; control=""
	expdate := now.AddDate(-1, 0, 0)
	//--
	control = "no-cache"
	//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
	w.Header().Set(HTTP_HEADER_CACHE_CTRL, "no-cache, must-revalidate") // HTTP 1.1 no-cache, not use their stale copy
	w.Header().Set(HTTP_HEADER_CACHE_PGMA, "no-cache") // HTTP 1.0 no-cache
	w.Header().Set(HTTP_HEADER_CACHE_EXPS, expdate.Format(smart.DATE_TIME_FMT_ISO_STD_GO_EPOCH) + " " + TZ_UTC) // HTTP 1.0 no-cache expires
	w.Header().Set(HTTP_HEADER_CACHE_LMOD, now.Format(smart.DATE_TIME_FMT_ISO_STD_GO_EPOCH) + " " + TZ_UTC)
	//--
	return false // no cache
	//--
} //END FUNCTION


//-----


// valid code: 200 ; 202 ; 203 ; 208
// contentFnameOrPath: file.html (will get extension .html and serve mime type by this extension) ; default, fallback to .txt
// for no cache: 		cacheExpiration = -1 ; cacheLastModified = "" ; cacheControl = "no-cache"
// for using cache: 	cacheExpiration = 3600 (1h) ; cacheLastModified = "2021-03-16 23:57:58" ; cacheControl = "private" | "public"
// headers:
func httpStatusOKX(w http.ResponseWriter, r *http.Request, code uint16, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	switch(code) {
		case 200:
			break
		case 202:
			break
		case 203:
			break
		case 208:
			break
		default:
			log.Println("[ERROR] httpStatusOKX: Invalid Status Code:", code)
			code = 200
	} //end switch
	//--
	contentFnameOrPath = smart.PathBaseName(smart.StrToLower(smart.StrTrimWhitespaces(contentFnameOrPath))) // just file name ; ex: `file.txt` | `file.html` | ...
	if(contentFnameOrPath == "") {
		contentFnameOrPath = "file.txt"
	} //end if
	//--
	mimeType, mimeUseCharset, mimeDisposition := MimeDispositionEval(contentFnameOrPath)
	//--
	contentDisposition = MimeDispositionConformParam(smart.StrToLower(smart.StrTrimWhitespaces(contentDisposition)))
	if(contentDisposition == "") { // {{{SYNC-MIME-DISPOSITION-AUTO}}}
		contentDisposition = mimeDisposition
	} else if(contentDisposition != DISP_TYPE_INLINE) {
		contentDisposition = DISP_TYPE_ATTACHMENT
	} //end if
	if(contentDisposition == DISP_TYPE_ATTACHMENT) {
		contentDisposition += `; filename="` + smart.EscapeUrl(contentFnameOrPath) + `"`
	} //end if
	//--
	if(headers == nil) {
		headers = map[string]string{}
	} //end if
	//--
	var contentType string = mimeType
	if(mimeUseCharset == true) {
		contentType += "; charset=" + smart.CHARSET
	} //end if
	//--
	isCachedContent := httpHeadersCacheControl(w, r, cacheExpiration, cacheLastModified, cacheControl)
	if(isCachedContent == true) { // do not manage eTag if not cached
		var eTag string = ""
		if(len(content) <= 4194304) { // {{{SYNC-SIZE-16Mb}}} / 4 = 4MB ; do not manage eTag for content size > 4MB
			eTag = smart.Md5(content)
		} //end if
		if(eTag != "") {
			w.Header().Set(HTTP_HEADER_ETAG_SUM, eTag)
			var match string = smart.StrTrimWhitespaces(r.Header.Get(HTTP_HEADER_ETAG_IFNM))
			if(DEBUG == true) {
				log.Println("[DEBUG] If None Match (Header):", match)
			} //end if
			if(match != "") {
				if(match == eTag) {
					w.WriteHeader(304) // not modified
					return
				} //end if
			} //end if
		} //end if
	} //end if
	//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
	w.Header().Set(HTTP_HEADER_CONTENT_TYPE, contentType)
	w.Header().Set(HTTP_HEADER_CONTENT_DISP, contentDisposition)
	w.Header().Set(HTTP_HEADER_CONTENT_LEN, smart.ConvertIntToStr(len(content)))
	//--
	for key, val := range headers {
		key = smart.StrToLower(smart.StrTrimWhitespaces(smart.StrNormalizeSpaces(key))) // {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
		val = smart.StrTrimWhitespaces(smart.StrNormalizeSpaces(val))
		switch(key) { // {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
			//-- these headers are managed below
			case HTTP_HEADER_CONTENT_TYPE:
				break
			case HTTP_HEADER_CONTENT_DISP:
				break
			case HTTP_HEADER_CONTENT_LEN:
				break
			//-- these headers are managed by httpHeadersCacheControl()
			case HTTP_HEADER_CACHE_CTRL:
				break
			case HTTP_HEADER_CACHE_PGMA:
				break
			case HTTP_HEADER_CACHE_EXPS:
				break
			case HTTP_HEADER_CACHE_LMOD:
				break
			//-- these headers are special, managed above
			case HTTP_HEADER_ETAG_SUM:
			case HTTP_HEADER_ETAG_IFNM:
			//--
			case HTTP_HEADER_SERVER_DATE:
			case HTTP_HEADER_SERVER_SIGN:
			case HTTP_HEADER_SERVER_POWERED:
			//-- the rest
			default:
				if(key == "") {
					log.Println("[ERROR] httpStatusOKX: Empty Key ; Value:", val)
				} else {
					if(DEBUG == true) {
						log.Println("[DEBUG] httpStatusOKX: Set Header Value:", key, val)
					} //end if
					w.Header().Set(key, val)
				} //end if
		} //end switch
	} //end for
	//--
	w.WriteHeader(int(code)) // status code must be after set headers
	w.Write([]byte(content))
	//--
} //END FUNCTION


//-----


// @params description: see httpStatusOKX()
func HttpStatus200(w http.ResponseWriter, r *http.Request, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	httpStatusOKX(w, r, 200, content, contentFnameOrPath, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
	//--
} //END FUNCTION


// @params description: see httpStatusOKX()
func HttpStatus202(w http.ResponseWriter, r *http.Request, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	httpStatusOKX(w, r, 202, content, contentFnameOrPath, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
	//--
} //END FUNCTION


// @params description: see httpStatusOKX()
func HttpStatus203(w http.ResponseWriter, r *http.Request, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	httpStatusOKX(w, r, 203, content, contentFnameOrPath, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
	//--
} //END FUNCTION


// @params description: see httpStatusOKX()
func HttpStatus208(w http.ResponseWriter, r *http.Request, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	httpStatusOKX(w, r, 208, content, contentFnameOrPath, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
	//--
} //END FUNCTION


//-----


func httpStatusERR(w http.ResponseWriter, r *http.Request, code uint16, messageText string, outputHtml bool) {
	//--
	var title string = ""
	var displayAuthLogo bool = false
	switch(code) {
		case 400:
			title = HTTP_STATUS_400
			break
		case 403:
			title = HTTP_STATUS_403
			displayAuthLogo = true
			break
		case 404:
			title = HTTP_STATUS_404
			break
		case 429:
			title = HTTP_STATUS_429
			displayAuthLogo = true
			break
		case 500:
			title = HTTP_STATUS_500
			break
		default:
			log.Println("[ERROR] httpStatusERR: Invalid Status Code:", code)
			title = HTTP_STATUS_500
			code = 500
	} //end switch
	//--
	var contentType = ""
	if(outputHtml == true) {
		contentType = assets.HTML_CONTENT_HEADER
	} else {
		contentType = assets.TEXT_CONTENT_HEADER
	} //end if
	//--
	messageText = smart.StrTrimWhitespaces(messageText)
	var content string = ""
	if(outputHtml == true) { // html
		content = assets.HtmlErrorPage(title, messageText, displayAuthLogo)
	} else { // text
		content += title
		if(messageText != "") {
			content += "\n\n" + messageText
		} //end if
		content += "\n"
	} //end if else
	//--
	httpHeadersCacheControl(w, r, -1, "", "no-cache")
	//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
	w.Header().Set(HTTP_HEADER_CONTENT_TYPE, contentType)
	w.Header().Set(HTTP_HEADER_CONTENT_DISP, DISP_TYPE_INLINE)
	w.Header().Set(HTTP_HEADER_CONTENT_LEN, smart.ConvertIntToStr(len(content)))
	w.WriteHeader(int(code)) // status code must be after set headers
	w.Write([]byte(content))
	//--
} //END FUNCTION


//-----


func HttpStatus400(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 400, messageText, outputHtml)
	//--
} //END FUNCTION


func HttpStatus403(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 403, messageText, outputHtml)
	//--
} //END FUNCTION


func HttpStatus404(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 404, messageText, outputHtml)
	//--
} //END FUNCTION


func HttpStatus429(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 429, messageText, outputHtml)
	//--
} //END FUNCTION


func HttpStatus500(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 500, messageText, outputHtml)
	//--
} //END FUNCTION


//-----


// if returns a non empty string there is an error ; if error it already outputs the 401 headers and content so there is nothing more to do ...
// it handles 401 or 403 access by IP list
func HttpBasicAuthCheck(w http.ResponseWriter, r *http.Request, authRealm string, authUsername string, authPassword string, allowedIPs string, outputHtml bool) string { // check if HTTP(S) Basic Auth is OK
	//--
	authRealm = smart.StrTrimWhitespaces(smart.StrReplaceAll(authRealm, `"`, `'`))
	authUsername = smart.StrTrimWhitespaces(authUsername)
	// do not trim password !
	allowedIPs = smart.StrTrimWhitespaces(allowedIPs)
	//--
	if((authRealm == "") || (len(authRealm) < 7) || (len(authRealm) > 50) || (!smart.StrRegexMatchString(`^[ _a-zA-Z0-9\-\.@\/\:]+$`, authRealm))) {
		log.Println("[WARNING] HTTP(S) Server :: BASIC.AUTH.FIX :: Invalid Realm `" + authRealm + "` ; The Realm was set to default: `" + DEFAULT_REALM + "`")
		authRealm = DEFAULT_REALM
	} //end if
	//--
	var err string = ""
	//--
	ip, port := smart.GetSafeIpAndPortFromRemoteAddr(r.RemoteAddr)
	if(ip == "") {
		err = "ERROR: Invalid or Empty Client IP: `" + r.RemoteAddr + "`"
		HttpStatus500(w, r, err, outputHtml)
		return err
	} //end if
	if(allowedIPs != "") {
		if((ip == "") || (!smart.StrContains(allowedIPs, "<" + ip + ">"))) {
			err = "The access to this service is disabled. The IP: `" + ip + "` at port `" + port + "` is not allowed by current IP Address list ..."
			HttpStatus403(w, r, err, outputHtml)
			return err
		} //end if
		log.Println("[OK] HTTP(S) Server :: BASIC.AUTH.IP.ALLOW :: Client: `<" + ip + ">` match the IP Addr Allowed List: `" + allowedIPs + "`")
	} //end if
	//--
	if(memAuthCache == nil) { // start cache just on 1st auth ... otherwise all scripts using this library will run the cache in background, but is needed only by this method !
		memAuthCache = smartcache.NewCache("smart.httputils.auth.inMemCache", time.Duration(CACHE_CLEANUP_INTERVAL) * time.Second, DEBUG_CACHE)
	} //end if
	if(DEBUG_CACHE == true) {
		log.Println("[DATA] HttpBasicAuthCheck :: memAuthCache:", memAuthCache)
	} //end if
	cacheExists, cachedObj, cacheExpTime := memAuthCache.Get(ip)
	if(cacheExists == true) {
		if((cachedObj.Id == ip) && (len(cachedObj.Data) >= 10)) { // allow max 10 invalid attempts then lock for 5 mins ... for this IP
			err = "Invalid Login Timeout for IP: `" + ip + "` at port `" + port + "` # Lock Timeout: " + smart.ConvertUInt32ToStr(uint32(CACHE_EXPIRATION)) + " seconds / Try again after: " + time.Unix(cacheExpTime, 0).UTC().Format(smart.DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
			HttpStatus429(w, r, err, outputHtml)
			return err
		} //end if
	} //end if
	//--
	user, pass, ok := r.BasicAuth()
	//--
	if(!ok) {
		err = "Authentication is Required"
	} else if(
		(smart.StrTrimWhitespaces(authUsername) == "") ||
		((len(authUsername) < 5) || (len(authUsername) > 25)) || // {{{SYNC-GO-SMART-AUTH-USER-LEN}}}
		(!smart.StrRegexMatchString(`^[a-z0-9\.]+$`, authUsername)) || // {{{SYNC-SF:REGEX_VALID_USER_NAME}}}
		//--
		(smart.StrTrimWhitespaces(authPassword) == "") ||
		((len(smart.StrTrimWhitespaces(authPassword)) < 7) || (len(authPassword) > 30)) || // {{{SYNC-GO-SMART-AUTH-PASS-LEN}}}
		//--
		(len(user) != len(authUsername)) ||
		(len(pass) != len(authPassword)) ||
		(subtle.ConstantTimeCompare([]byte(user), []byte(authUsername)) != 1) ||
		(subtle.ConstantTimeCompare([]byte(pass), []byte(authPassword)) != 1) ||
		(user != authUsername) || (pass != authPassword)) {
		err = "Username and Password Check Failed: not match or invalid"
	} //end if else
	//--
	if(err != "") {
		//-- write to cache invalid login
		if(cacheExists != true) {
			cachedObj.Id = ip
			cachedObj.Data = "."
		} else {
			cachedObj.Data += "."
		} //end if
		memAuthCache.Set(cachedObj, uint64(CACHE_EXPIRATION))
		log.Println("[NOTICE] HttpBasicAuthCheck: Set-In-Cache: AUTH.FAILED for IP: `" + cachedObj.Id + "` # `" + cachedObj.Data + "` @", len(cachedObj.Data))
		//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
		httpHeadersCacheControl(w, r, -1, "", "no-cache")
		w.Header().Set("www-authenticate", `Basic realm="` + authRealm + `"`) // the safety of characters in authRealm was checked above !
		//--
		if(outputHtml == true) {
			w.Header().Set(HTTP_HEADER_CONTENT_TYPE, assets.HTML_CONTENT_HEADER) // {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
		} else {
			w.Header().Set(HTTP_HEADER_CONTENT_TYPE, assets.TEXT_CONTENT_HEADER) // {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
		} //end if
		//--
		w.WriteHeader(401) // status code must be after set headers
		//--
		if(outputHtml == true) {
			w.Write([]byte(assets.HtmlErrorPage(HTTP_STATUS_401, "Access to this area requires Authentication", true)))
		} else {
			w.Write([]byte(HTTP_STATUS_401 + "\n"))
		} //end if else
		//--
		log.Printf("[WARNING] HTTP(S) Server :: BASIC.AUTH.FAILED :: UserName: `" + user + "` # [%s %s %s] %s [%s] for client %s\n", r.Method, r.URL, r.Proto, "401", r.Host, r.RemoteAddr)
		//--
		return err
		//--
	} //end if
	//--
	if(cacheExists == true) {
		memAuthCache.Unset(ip) // unset on 1st successful login
	} //end if
	//--
	log.Println("[OK] HTTP(S) Server :: BASIC.AUTH.SUCCESS :: UserName: `" + user + "` # From IPAddress: `" + ip + "` on Port: `" + port + "`")
	//--
	return ""
	//--
} //END FUNCTION


//-----


func MimeDispositionConformParam(mimeDisposition string) string {
	//--
	switch(mimeDisposition) {
		case DISP_TYPE_INLINE:
			mimeDisposition = DISP_TYPE_INLINE
			break
		case DISP_TYPE_ATTACHMENT:
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "": fallthrough // {{{SYNC-MIME-DISPOSITION-AUTO}}}
		default:
			mimeDisposition = ""
	} //end switch
	//--
	return mimeDisposition
	//--
} //END FUNCTION


//-----


func MimeDispositionEval(fpath string) (mimType string, mimUseCharset bool, mimDisposition string) {
	//--
	var mimeType string = ""
	var mimeUseCharset bool = false
	var mimeDisposition string = ""
	//--
	var file string = smart.PathBaseName(smart.StrTrimWhitespaces(fpath))
	var lfile string = smart.StrToLower(file)
	//--
	var extension string = smart.StrTrimLeft(smart.PathBaseExtension(lfile), ".")
	//--
	switch(extension) {
		//-------------- text : must be default inline
		case "txt":
			mimeType = "text/plain"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- html : must be default inline
		case "html":
			mimeType = "text/html"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- css
		case "css":
			mimeType = "text/css"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- javascript
		case "js":
			mimeType = "application/javascript"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "json":
			mimeType = "application/json"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- web images
		case "svg":
			mimeType = "image/svg+xml"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "png":
			mimeType = "image/png"
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "gif":
			mimeType = "image/gif"
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "jpeg": fallthrough
		case "jpe": fallthrough
		case "jpg":
			mimeType = "image/jpeg"
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "webp":
			mimeType = "image/webp"
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- fonts
		case "woff2":
			mimeType = "application/x-font-woff2"
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "woff":
			mimeType = "application/x-font-woff"
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "ttf":
			mimeType = "application/x-font-ttf"
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- xml
		case "xml":
			mimeType = "application/xml"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- html: tpl
		case "mtpl": fallthrough // marker tpl templating
		case "tpl": fallthrough // tpl templating
		case "twist": fallthrough // tpl twist
		case "twig": fallthrough // twig templating
		case "t3fluid": fallthrough // typo3 fluid templating
		case "django": fallthrough // django templating
		case "htm":
			mimeType = "text/html"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- php
		case "php":
			mimeType = "application/x-php"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- plain text and development
		case "log": fallthrough // log file
		case "sql": fallthrough // sql file
		case "sh": fallthrough // shell script
		case "bash": fallthrough // bash (shell) script
		case "diff": fallthrough // Diff File
		case "patch": fallthrough // Diff Patch
		case "tcl": fallthrough // TCL
		case "tk": fallthrough // Tk
		case "lua": fallthrough // Lua
		case "gjs": fallthrough // gnome js
		case "toml": fallthrough // Tom's Obvious, Minimal Language (used with Cargo / Rust definitions)
		case "rs": fallthrough // Rust Language
		case "go": fallthrough // Go Lang
		case "pl": fallthrough // perl
		case "py": fallthrough // python
		case "phps": fallthrough // php source, assign text/plain !
		case "swift": fallthrough // apple swift language
		case "vala": fallthrough // vala language
		case "java": fallthrough // java source code
		case "pas": fallthrough // Delphi / Pascal
		case "inc": fallthrough // include file
		case "ini": fallthrough // ini file
		case "yml": fallthrough // yaml file
		case "yaml": fallthrough // yaml file
		case "md": fallthrough // markdown
		case "markdown": fallthrough // markdown
		case "pem": fallthrough // PEM Certificate File
		case "crl": fallthrough // Certificate Revocation List
		case "crt": fallthrough // Certificate File
		case "cer": fallthrough // Certificate File
		case "key": // Certificate Key File
			mimeType = "text/plain"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- email / calendar / addressbook
		case "eml":
			mimeType = "message/rfc822"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "ics":
			mimeType = "text/calendar"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "vcf":
			mimeType = "text/x-vcard"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "vcs":
			mimeType = "text/x-vcalendar"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- data
		case "csv": fallthrough // csv comma
		case "tab": // csv tab
			mimeType = "text/csv"
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- portable documents
		case "pdf":
			mimeType = "application/pdf"
			mimeDisposition = DISP_TYPE_INLINE // DISP_TYPE_ATTACHMENT
			break
		//-------------- specials
		case "asc": fallthrough
		case "sig":
			mimeType = "application/pgp-signature"
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- theora
		case "ogg": fallthrough // theora audio
		case "oga":
			mimeType = "audio/ogg"
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "ogv": // theora video
			mimeType = "video/ogg"
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- webm
		case "webm": // google vp8
			mimeType = "video/webm"
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- mp3 / mp4
		case "mp4": fallthrough // mp4 video (it can be also mp4 audio, but cast it as video by default)
		case "m4v": // mp4 video
			mimeType = "video/mpeg"
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "mp3": fallthrough // mp3 audio
		case "mp4a": // mp4 audio
			mimeType = "audio/mpeg"
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- default
		default: // others
			mimeUseCharset = false
			mimeType = smart.MimeTypeByFilePath(lfile)
			mimeDisposition = DISP_TYPE_ATTACHMENT
			if(smart.StrContains(mimeType, ";")) {
				mArrType := smart.Explode(";", mimeType)
				if(len(mArrType) > 1) {
					mimeType = smart.StrTrimWhitespaces(mArrType[0])
					if(smart.StrIStartsWith(smart.StrTrimWhitespaces(mArrType[1]), "charset=" + smart.CHARSET)) {
						mimeUseCharset = true
					} //end if
				} //end if
			} //end if
			if(DEBUG == true) {
				log.Println("[DEBUG] FallBack on MimeType:", mimeType)
			} //end if
		//--------------
	} //end switch
	//--
	if(mimeDisposition == "") {
		mimeUseCharset = false
		mimeDisposition = DISP_TYPE_ATTACHMENT
	} //end if
	//--
	if(mimeType == "") {
		mimeUseCharset = false
		mimeType = MIME_TYPE_DEFAULT
		mimeDisposition = DISP_TYPE_ATTACHMENT
	} //end if
	//--
	return mimeType, mimeUseCharset, mimeDisposition
	//--
} //END FUNCTION


//-----


// #END
