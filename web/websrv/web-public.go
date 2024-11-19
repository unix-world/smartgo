
// GO Lang :: SmartGo / Web Server / Web-Public :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241116.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"time"
	"net/http"

	"os"
	"io"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)


func webPublicHttpHandler(w http.ResponseWriter, r *http.Request) uint16 { // serves the Public Files for a HTTP(S) server under the path: `/web-public/*`
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if((r.Method != "GET") && (r.Method != "HEAD")) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "HTTP Status 405 :: Invalid Web Public Request Method: `" + r.Method + "`")
		smarthttputils.HttpStatus405(w, r, "Invalid WP Request Method", true)
		return 405
	} //end if
	//--
	if(!webDirIsValid(WEB_PUBLIC_RELATIVE_ROOT_PATH)) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "HTTP Status 500 :: Invalid Web Public Root Path: `" + WEB_PUBLIC_RELATIVE_ROOT_PATH + "`")
		smarthttputils.HttpStatus500(w, r, "Invalid WP Root Path", true)
		return 500
	} //end if
	if(!webDirExists(WEB_PUBLIC_RELATIVE_ROOT_PATH)) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "HTTP Status 500 :: Missing Web Public Root Path: `" + WEB_PUBLIC_RELATIVE_ROOT_PATH + "`")
		smarthttputils.HttpStatus500(w, r, "WP Root Path is Unavailable", true)
		return 500
	} //end if
	//--
	var urlPath string = GetCurrentPath(r)
	if(urlPath == "") {
		urlPath = "/" // required for validation
	} //end if
	if(!webUrlPathIsValid(urlPath)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "HTTP Status 400 :: Invalid Web Public URL Path: `" + urlPath + "`")
		smarthttputils.HttpStatus400(w, r, "Invalid WP Request URL Path", true)
		return 400
	} //end if
	//--
	urlPath = smart.StrTrimWhitespaces(smart.StrTrimLeft(urlPath, " /"))
	var path string = WEB_PUBLIC_RELATIVE_ROOT_PATH + urlPath
	//--
	if(!webPathIsValid(path)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "HTTP Status 400 :: Invalid Web Public Path: `" + path + "`")
		smarthttputils.HttpStatus400(w, r, "Invalid WP Request Path", true)
		return 400
	} //end if
	if(!webPathExists(path)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "HTTP Status 404 :: Web Public Path Not Found: `" + path + "`")
		smarthttputils.HttpStatus404(w, r, "WP Request Path Not Found", true)
		return 404
	} //end if
	if((webDirIsValid(smart.PathAddDirLastSlash(path)) == true) && (webDirExists(path) == true)) {
		path = smart.PathAddDirLastSlash(path) + DEFAULT_DIRECTORY_INDEX_HTML
	} //end if
	if((webPathIsValid(path) != true) || (webFileExists(path) != true)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "HTTP Status 404 :: Web Public File Path Not Found Or Is Invalid: `" + path + "`")
		smarthttputils.HttpStatus404(w, r, "WP Request File Path N/A", true)
		return 404
	} //end if
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "Trying to Serve Public File: `" + path + "`")
	} //end if
	//--
	var fileSize int64 = -2
	fSize, errFSize := smart.SafePathFileGetSize(path, false) // deny absolute paths
	if(errFSize != nil) {
		fileSize = -1
	} else {
		fileSize = fSize
	} //end if else
	//--
	var fileMTime int64 = 0
	if(fileSize >= 0) { // if file really exists, otherwise fSize is negative: -1 or -2
		mTime, errMTime := smart.SafePathGetMTime(path, false) // deny absolute paths
		if(errMTime == nil) {
			fileMTime = mTime
		} //end if
	} //end if
	//--
	if(fileSize < 0) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "HTTP Status 404 :: Web Public File is Not Accessible: `" + path + "`")
		smarthttputils.HttpStatus404(w, r, "WP Request File is Not Accessible", true)
		return 404
	} //end if
	//--
	t := time.Unix(fileMTime, 0)
	//--
	var cExp int = int(CACHED_EXP_TIME_SECONDS)
	var cMod string = t.Format(smart.DATE_TIME_FMT_ISO_STD_GO_EPOCH)
	var cCtl string = smarthttputils.CACHE_CONTROL_DEFAULT
	//--
	var fName string = smart.PathBaseName(smart.StrToLower(smart.StrTrimWhitespaces(path))) // just file name ; ex: `file.txt` | `file.html` | ...
	if(fName == "") {
		fName = "file.txt"
	} //end if
	mimeType, mimeUseCharset, mimeDisposition := smarthttputils.MimeDispositionEval(fName)
	var contentDisposition string = mimeDisposition
	if(contentDisposition == smarthttputils.DISP_TYPE_ATTACHMENT) {
		contentDisposition += `; filename="` + smart.EscapeUrl(fName) + `"`
	} //end if
	var contentType string = mimeType
	if(mimeUseCharset == true) {
		contentType += "; charset=" + smart.CHARSET
	} //end if
	//--
	if(r.Method == "HEAD") { // {{{SYNC-HTTP-HEAD-DO-NOT-SEND-BODY}}} ; for 2xx codes if the method is HEAD don't send body
		smarthttputils.HttpHeadersCacheControl(w, r, cExp, cMod, cCtl)
		w.Header().Set(smarthttputils.HTTP_HEADER_CONTENT_TYPE, contentType)
		w.Header().Set(smarthttputils.HTTP_HEADER_CONTENT_DISP, contentDisposition)
		w.Header().Set(smarthttputils.HTTP_HEADER_CONTENT_LEN, smart.ConvertInt64ToStr(fileSize))
		w.WriteHeader(200) // status code must be after set headers
		return 200
	} //end if
	//--
	if(fileSize <= smarthttputils.MAX_SIZE_ETAG) { // {{{SYNC-SIZE-MAX-ETAG}}} ; manage eTag only for content size <= 4MB ; for larger file serve stream, below
		log.Println("[NOTICE]", smart.CurrentFunctionName() + ": Serving Small Public File: `" + path + "` ; Size:", fileSize, "bytes")
		var fileContent string = ""
		var errRead error = nil
		if(fileSize > 0) {
			fileContent, errRead = smart.SafePathFileRead(path, false)
		} //end if
		if(errRead != nil) {
			log.Println("[ERROR]", smart.CurrentFunctionName(), "HTTP Status 410 :: Web Public Small File is Unavailable for Serving: `" + path + "` ; Error:", errRead)
			smarthttputils.HttpStatus410(w, r, "WP Request File is Unavailable for Serving", true)
			return 410
		} //end if
		smarthttputils.HttpStatus200(w, r, fileContent, path, "", cExp, cMod, cCtl, nil)
		return 200
	} //end if
	//--
	streamBytes, errStream := os.Open(path)
	if(errStream != nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "HTTP Status 410 :: Web Public Stream File is Unavailable for Serving: `" + path + "` ; Error:", errStream)
		smarthttputils.HttpStatus410(w, r, "WP Request File is Unavailable for Serving", true)
		return 410
	} //end if
	defer streamBytes.Close()
	log.Println("[NOTICE]", smart.CurrentFunctionName() + ": Serving Stream Public File: `" + path + "` ; Size:", fileSize, "bytes")
	//--
	smarthttputils.HttpHeadersCacheControl(w, r, cExp, cMod, cCtl)
	w.Header().Set(smarthttputils.HTTP_HEADER_CONTENT_TYPE, contentType)
	w.Header().Set(smarthttputils.HTTP_HEADER_CONTENT_DISP, contentDisposition)
	w.Header().Set(smarthttputils.HTTP_HEADER_CONTENT_LEN, smart.ConvertInt64ToStr(fileSize))
	//--
	w.WriteHeader(200) // status code must be after set headers
	io.Copy(w, streamBytes) // transfer stream to web socket
	//--
	return 200
	//--
} //END FUNCTION


// #END
