
// GO Lang :: SmartGo / WebDAV Server :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231205.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package webdavsrv

import (
	"log"
	"fmt"

	"context"
	"bytes"
	"net/http"

	"golang.org/x/net/webdav"

	smart "github.com/unix-world/smartgo"
	assets "github.com/unix-world/smartgo/web-assets"
	smarthttputils "github.com/unix-world/smartgo/web-httputils"
)

const (
	VERSION string = "r.20231205.2358"
	SIGNATURE string = "(c) 2020-2023 unix-world.org"

	SERVER_ADDR string = "127.0.0.1"
	SERVER_PORT uint16 = 13787

	STORAGE_DIR  string = "./webdav"
	DAV_PATH     string = "/webdav"

	CERTIFICATES_DEFAULT_PATH string = "./ssl"
	CERTIFICATE_PEM_CRT string = "cert.crt"
	CERTIFICATE_PEM_KEY string = "cert.key"

	HTTP_AUTH_REALM string = "Smart.WebDAV Server: Storage Area"
)


func WebdavServerRun(httpHeaderKeyRealIp string, storagePath string, serveSecure bool, certifPath string, httpAddr string, httpPort uint16, timeoutSeconds uint32, allowedIPs string, authUser string, authPass string, customAuthCheck smarthttputils.HttpAuthCheckFunc) bool {

	//-- settings

	httpHeaderKeyRealIp = smart.StrToUpper(smart.StrTrimWhitespaces(httpHeaderKeyRealIp))
	if(httpHeaderKeyRealIp != "") { // if no proxy, don't set
		smart.SetSafeRealClientIpHeaderKey(httpHeaderKeyRealIp)
	} //end if

	//-- auth user / pass

	authUser = smart.StrTrimWhitespaces(authUser)
	if((authUser == "") && (smart.StrTrimWhitespaces(authPass) == "") && (customAuthCheck == nil)) { // do not trim authPass !
		log.Println("[ERROR] WebDAV Server: Empty Auth Providers: Auth User / Pass or Auth Handler")
		return false
	} //end if

	//-- http(s) address and port(s)

	httpAddr = smart.StrTrimWhitespaces(httpAddr)
	if((!smart.IsNetValidIpAddr(httpAddr)) && (!smart.IsNetValidHostName(httpAddr))) {
		log.Println("[WARNING] WebDAV Server: Invalid Server Address (Host):", httpAddr, "using the default host:", SERVER_ADDR)
		httpAddr = SERVER_ADDR
	} //end if

	if(!smart.IsNetValidPortNum(int64(httpPort))) {
		log.Println("[WARNING] WebDAV Server: Invalid Server Address (Port):", httpPort, "using the default port:", SERVER_PORT)
		httpPort = SERVER_PORT
	} //end if

	//-- paths

	if(serveSecure == true) {
		certifPath = smart.StrTrimWhitespaces(certifPath)
		if((certifPath == "") || (smart.PathIsBackwardUnsafe(certifPath) == true)) {
			certifPath = CERTIFICATES_DEFAULT_PATH
		} //end if
		certifPath = smart.PathGetAbsoluteFromRelative(certifPath)
		certifPath = smart.PathAddDirLastSlash(certifPath)
	} else {
		certifPath = CERTIFICATES_DEFAULT_PATH
	} //end if

	storagePath = smart.StrTrimWhitespaces(storagePath)
	if((storagePath == "") || (smart.PathIsBackwardUnsafe(storagePath) == true)) {
		storagePath = STORAGE_DIR
	} //end if
	storagePath = smart.PathGetAbsoluteFromRelative(storagePath)
	storagePath = smart.PathAddDirLastSlash(storagePath)
	if((!smart.PathExists(storagePath)) || (!smart.PathIsDir(storagePath))) {
		log.Println("[ERROR] WebDAV Server: Storage Path does not Exists or Is Not a Valid Directory:", storagePath)
		return false
	} //end if

	//-- for web

	var theStrSignature string = "SmartGO WebDAV Server " + VERSION

	var serverSignature bytes.Buffer
	serverSignature.WriteString(theStrSignature + "\n")
	serverSignature.WriteString(SIGNATURE + "\n")
	serverSignature.WriteString("\n")

	if(serveSecure == true) {
		serverSignature.WriteString("<Secure URL> :: https://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + DAV_PATH + "/" + "\n")
	} else {
		serverSignature.WriteString("<URL> :: http://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + DAV_PATH + "/" + "\n")
	} //end if

	//-- for console

	if(serveSecure != true) {
		log.Println("Starting WebDAV Server: http://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + DAV_PATH + " @ HTTPS/Mux/Insecure # " + VERSION)
	} else {
		log.Println("Starting WebDAV Server: https://" + httpAddr + ":" + smart.ConvertUInt16ToStr(httpPort) + DAV_PATH + " @ HTTPS/Mux/TLS # " + VERSION)
		log.Println("[NOTICE] WebDAV Server Certificates Path:", certifPath)
	} //end if else
	log.Println("[INFO] WebDAV Server Storage Path:", storagePath)

	//-- server

	mux, srv := smarthttputils.HttpMuxServer(httpAddr + fmt.Sprintf(":%d", httpPort), timeoutSeconds, true, "[WebDAV Server]") // force HTTP/1

	//-- webdav handler

	wdav := &webdav.Handler{
		Prefix:     DAV_PATH,
		FileSystem: webdav.Dir(STORAGE_DIR),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			remoteAddr, remotePort := smart.GetHttpRemoteAddrIpAndPortFromRequest(r)
			_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
			if(err != nil) {
				log.Printf("[WARNING] WebDAV Server :: WEBDAV.ERROR: %s :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", err, "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
			} else {
				log.Printf("[OK] WebDAV Server :: WEBDAV :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
			} //end if else
		},
	}

	//-- other handlers

	// http root handler : 202 | 404
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if(r.URL.Path != "/") {
			smarthttputils.HttpStatus404(w, r, "WebDAV Resource Not Found: `" + r.URL.Path + "`", false)
			return
		} //end if
		_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
		log.Printf("[OK] WebDAV Server :: DEFAULT :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertIntToStr(202), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
		var headHtml string = "<style>" + "\n" + "div.status { text-align:center; margin:10px; cursor:help; }" + "\n" + "div.signature { background:#778899; color:#FFFFFF; font-size:2rem; font-weight:bold; text-align:center; border-radius:3px; padding:10px; margin:20px; }" + "\n" + "</style>"
		var bodyHtml string = `<div class="status"><img alt="Status: Up and Running ..." title="Status: Up and Running ..." width="64" height="64" src="data:image/svg+xml,` + smart.EscapeHtml(smart.EscapeUrl(assets.ReadWebAsset("lib/framework/img/loading-spin.svg"))) + `"></div>` + "\n" + `<div class="signature">` + "\n" + "<pre>" + "\n" + smart.EscapeHtml(serverSignature.String()) + "</pre>" + "\n" + "</div>"
		smarthttputils.HttpStatus202(w, r, assets.HtmlStandaloneTemplate(theStrSignature, headHtml, bodyHtml), "index.html", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, nil)
	})

	// http version handler : 203
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
		log.Printf("[OK] WebDAV Server :: VERSION :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", smart.ConvertIntToStr(202), r.Method, r.URL, r.Proto, r.Host, r.RemoteAddr, realClientIp)
		smarthttputils.HttpStatus203(w, r, theStrSignature + "\n", "version.txt", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, nil)
	})

	// webdav handler : all webdav status codes ...
	davHandler := func(w http.ResponseWriter, r *http.Request) {
		authErr, _ := smarthttputils.HttpBasicAuthCheck(w, r, HTTP_AUTH_REALM, authUser, authPass, allowedIPs, customAuthCheck, false) // outputs: TEXT
		if(authErr != nil) {
			log.Println("[WARNING] WebDAV Server / Storage Area :: Authentication Failed:", authErr)
			return
		} //end if

		if(r.Method == http.MethodGet) {
			var wdirPath string = smart.StrSubstr(r.URL.Path, len(DAV_PATH), 0)
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
		log.Println("[DEBUG", "WebDAV Server", "Method:", r.Method, "Depth:", r.Header.Get("Depth"))

		wdav.ServeHTTP(w, r) // if all ok above (basic auth + credentials ok, serve ...)
	}
	mux.HandleFunc(DAV_PATH, davHandler) // serve without "/" suffix # this is a fix to work also with gvfs
	mux.HandleFunc(DAV_PATH + "/", davHandler) // serve classic, with "/" suffix

	// serve logic

	if(serveSecure == true) { // serve HTTPS
		var theTlsCertPath string = certifPath + CERTIFICATE_PEM_CRT
		var theTlsKeyPath  string = certifPath + CERTIFICATE_PEM_KEY
		if(!smart.PathIsFile(theTlsCertPath)) {
			log.Println("[ERROR] WebDAV Server / INIT TLS: No certificate crt found in current directory. Please provide a valid cert:", theTlsCertPath)
			return false
		} //end if
		if(!smart.PathIsFile(theTlsKeyPath)) {
			log.Println("[ERROR]: WebDAV Server / INIT TLS No certificate key found in current directory. Please provide a valid cert:", theTlsKeyPath)
			return false
		} //end if
		log.Println("[NOTICE] WebDAV Server is serving HTTPS/TLS at " + httpAddr + " on port", httpPort)
		go srv.ListenAndServeTLS(theTlsCertPath, theTlsKeyPath)
	} else { // serve HTTP
		log.Println("[NOTICE] WebDAV Server serving HTTP at " + httpAddr + " on port", httpPort)
		go srv.ListenAndServe()
	} //end if

	//--
	return true
	//--

} //END FUNCTION


// #END
