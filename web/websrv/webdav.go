
// GO Lang :: SmartGo / Web Server / WebDAV :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20251216.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"time"

	"os"
	"io"
	"context"

	"net/http"

	uid 			"github.com/unix-world/smartgo/crypto/uuid"
	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
	smartcache 		"github.com/unix-world/smartgo/data-structs/simplecache"
	webdav 			"github.com/unix-world/smartgo/web/webdav" // a modified version of [golang.org / x / net / webdav]: added extra path security checks
)


const webdavLockTimeSeconds uint16 = 300 // orphan locks will be cleared after this time
var webdavLockCache *smartcache.InMemCache = nil

func webDavInitLockSysCache() {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	webdavLockCache = smartcache.NewCache("smart.websrv.webdav.locking.inMemCache", time.Duration(webdavLockTimeSeconds) * time.Second, webdav.DEBUG)
	//--
} //END FUNCTION

func webdavLockExternalGetTokenHash(token string) string {
	//--
	token = smart.StrTrimWhitespaces(token)
	if(token == "") {
		return ""
	} //end if
	if(smart.StrContains(token, ":")) { // ex: urn:uuid:00000000-0000-0000-0000-000000000000
		arr := smart.ExplodeWithLimit(":", token, 3)
		token = smart.StrTrimWhitespaces(arr[len(arr)-1]) // get last part
	} //end if
	//--
	return token
	//--
} //END FUNCTION

func webdavLockExternalIsValid(token string) bool {
	//--
	if(token != smart.StrTrimWhitespaces(token)) {
		return false
	} //end if
	if(len(token) != 36) {
		return false
	} //end if
	if(len(smart.StrReplaceAll(token, "-", "")) != 32) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION

func webdavLockingLOCK(internal bool, path string) (token string, err error) {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if(webdavLockCache == nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDav LockSys Cache Structure is NIL")
		return "", smart.NewError("WebDav LockSys is N/A")
	} //end if
	//--
	token = ""
	err = nil
	//--
	if(!internal) {
	//	token = webdav.FakeLockToken
		token = uid.UuidUrn()
	} else {
		token = smart.Base64ToBase64s(smart.Sh3a512B64(path))
	} //end if else
	//--
	if(webdav.DEBUG) {
		log.Println("[DEBUG]", "WEBDAV:LOCKING:LOCK", "Internal:", internal, "Path: `" + path + "`", "Token: `" + token + "`", smart.CurrentFunctionName())
	} //end if
	//--
	if(!internal) {
		token = webdavLockExternalGetTokenHash(token)
		if(!webdavLockExternalIsValid(token)) {
			log.Println("[ERROR]", smart.CurrentFunctionName(), "External Token format should be URN")
			return "",  smart.NewError("Invalid Token: format should be: URN")
		} //end if
		return token, nil // STOP Here, external locking on web systems is unrealistic ; only internal locking is implemented !
	} //end if
	//--
	cacheExists, cachedObj, cacheExpTime := webdavLockCache.Get(token)
	if(cacheExists) {
		if(cacheExpTime <= 0) {
			okFix := webdavLockCache.SetExpiration(token, int64(webdavLockTimeSeconds)) // fix
			if(!okFix) {
				log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDav:LockSys", "Fix Expiration Failed for Path: `" + path + "` ; Token: `" + token + "`")
				err = smart.NewError("Failed to Fix WebDAV LockSys Object Expiration")
			} //end if
		} //end if
		if(cachedObj.Id != token) {
			log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDav:LockSys", "Invalid Cached Object for Path: `" + path + "` ; Token: `" + token + "`")
			err = smart.NewError("WebDAV LockSys Object mismatch")
		} //end if
		return "", err // locked
	} //end if
	cachedObj.Id = token
	cachedObj.Data = path
	cachedObj.Obj = smart.TimeNowUnix()
	okSet := webdavLockCache.Set(cachedObj, int64(webdavLockTimeSeconds))
	if(!okSet) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDav:LockSys", "Set Cache Object Failed for Path: `" + path + "` ; Token: `" + token + "`")
		err = smart.NewError("Failed to Set WebDAV LockSys Object")
		token = ""
	} //end if
	//--
	return token, nil
	//--
} //END FUNCTION

func webdavLockingUNLOCK(internal bool, token string) (success bool, err error) {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if(webdavLockCache == nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDav LockSys Cache Structure is NIL")
		return true, smart.NewError("WebDav LockSys is N/A")
	} //end if
	//--
	if(webdav.DEBUG) {
		log.Println("[DEBUG]", "WEBDAV:LOCKING:UNLOCK", "Internal:", internal, "Token: `" + token + "`", smart.CurrentFunctionName())
	} //end if
	//--
	token = smart.StrTrimWhitespaces(token)
	if(token == "") {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Empty Token")
		return true, nil
	} //end if
	//--
	if(!internal) {
		token = webdavLockExternalGetTokenHash(token)
		if(!webdavLockExternalIsValid(token)) {
			return false, smart.NewError("Invalid Token: expects format: URN")
		} //end if
		return true, nil // STOP Here, external locking on web systems is unrealistic ; only internal locking is implemented !
	} //end if
	//--
	return webdavLockCache.Unset(token), nil
	//--
} //END FUNCTION

func webdavLockingEXISTS(internal bool, token string) bool {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if(webdavLockCache == nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDav LockSys Cache Structure is NIL")
		return false
	} //end if
	//--
	if(webdav.DEBUG) {
		log.Println("[DEBUG]", "WEBDAV:LOCKING:EXISTS", "Internal:", internal, "Token: `" + token + "`", smart.CurrentFunctionName())
	} //end if
	//--
	token = smart.StrTrimWhitespaces(token)
	if(token == "") {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Empty Token")
		return false
	} //end if
	//--
	if(!internal) {
		token = webdavLockExternalGetTokenHash(token)
		if(!webdavLockExternalIsValid(token)) {
			log.Println("[WARNING]", smart.CurrentFunctionName(), "Invalid Lock Token: expect format: URN", token)
			return false
		} //end if
		return true // STOP Here, external locking on web systems is unrealistic ; only internal locking is implemented !
	} //end if
	//--
	cacheExists, _, _ := webdavLockCache.Get(token)
	//--
	return cacheExists
	//--
} //END FUNCTION

func webdavLockSys() *webdav.LockSys {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if(webdavLockCache == nil) {
		return nil
	} //end if
	//--
	ls := webdav.LockSys{
		Lock:   webdavLockingLOCK,
		Unlock: webdavLockingUNLOCK,
		Exists: webdavLockingEXISTS,
	}
	//--
	return &ls
	//--
} //END FUNCTION


func webDavUrlPath() string {
	//--
	return GetBaseBrowserPath() + DAV_URL_PATH // {{{SYNC-WEBSRV-ROUTE-WEBDAV}}}
	//--
} //END FUNCTION


func webDavLogger(r *http.Request, err error) {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	remoteAddr, remotePort := GetVisitorRemoteIpAddrAndPort(r)
	_, realClientIp := GetVisitorRealIpAddr(r)
	//--
	if(err != nil) {
		if(os.IsNotExist(err)) {
			log.Printf("[NOTICE] WebDAV Service :: WEBDAV.NOTFOUND: %s :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", err, "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
		} else {
			log.Printf("[WARNING] WebDAV Service :: WEBDAV.ERROR: %s :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", err, "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
		} //end if
	} else {
		log.Printf("[LOG] WebDAV Service :: WEBDAV :: %s [%s `%s` %s] :: Host [%s] :: RemoteAddress/Client [%s] # RealClientIP [%s]\n", "*", r.Method, r.URL, r.Proto, r.Host, remoteAddr+":"+remotePort, realClientIp)
	} //end if else
	//--
} //END FUNCTION


func webDavHttpHandler(w http.ResponseWriter, r *http.Request, webdavSharedStorage bool, webDavUseSmartSafeValidPaths bool, isAuthActive bool, allowedIPs string, authUser string, authPass string, authToken string, customAuthCheck smarthttputils.HttpAuthCheckFunc) { // serves the WebDAV Handler the path: `/webdav/*`
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	// {{{SYNC-VALIDATE-IP-LIST-BEFORE-VERIFY-IP}}} ; no need to validate the allowedIPs ; it is not used directly by this method, only passed later to other method that will validate it
	//--
	if(!smart.PathIsWebSafeValidSafePath(DAV_STORAGE_RELATIVE_ROOT_PATH)) { // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-STORAGE-PATH}}}
		log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service Initialization Error, WebDAV Storage Path is Invalid: `" + DAV_STORAGE_RELATIVE_ROOT_PATH + "`")
		smarthttputils.HttpStatus500(w, r, "WebDAV Service Internal Error", true)
		return
	} //end if
	//--
	var webDavRealUrlPath string = smart.StrTrimWhitespaces(webDavUrlPath())
	if((webDavRealUrlPath == "") || (!smart.StrStartsWith(webDavRealUrlPath, "/")) || (!WebUrlRouteIsValid(webDavRealUrlPath))) { // {{{SYNC-VALIDATE-WEBSRV-WEBDAV-URL-PATH}}}
		log.Println("[ERROR]", smart.CurrentFunctionName(), "WebDAV Service Initialization Error, WebDAV Route is Invalid: `" + webDavRealUrlPath + "`")
		smarthttputils.HttpStatus500(w, r, "WebDAV Service cannot handle this Path: `" + GetCurrentPath(r) + "`", true)
		return
	} //end if
	//--
	var webDavStorageRootPath string = DAV_STORAGE_RELATIVE_ROOT_PATH
	//-- auth check (if auth is active)
	if(isAuthActive != true) {
		log.Println("[NOTICE]", smart.CurrentFunctionName(), "WebDAV Service: Auth is NOT Enabled, Serving WebDAV as Public")
	} else {
		var auth401IsHtml bool = false
		var crrRoute string = GetCurrentPath(r)
		if((crrRoute == webDavUrlPath()) || (crrRoute == webDavUrlPath()+"/")) {
			auth401IsHtml = true // outputs HTML just for the entry route on WebDAV, otherwise outputs Text
		} //end if
		authErr, authData := smarthttputils.HttpAuthCheck(w, r, httpAuthRealm, authUser, authPass, authToken, allowedIPs, customAuthCheck, auth401IsHtml) // {{{SMARTGO-WEB-SERVER-AUTH-SYNC}}} ; if not success, outputs HTML 4xx-5xx and must stop (return) immediately after checks from this method
		if((authErr != nil) || (authData.OK != true) || (authData.ErrMsg != "")) {
			log.Println("[WARNING]", smart.CurrentFunctionName(), "WebDAV Service / Storage Area :: Authentication Failed:", "authData.OK:", authData.OK, "authData.ErrMsg:", authData.ErrMsg, "Error:", authErr)
			// MUST NOT WRITE ANY ANSWER HERE ON FAIL: smarthttputils.HttpStatusXXX() as 401, 403, 429 because the smarthttputils.HttpAuthCheck() method manages 4xx-5xx codes directly if not success
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
			//--
			webDavStorageRootPath = theUserPath // set WebDAV Root Storage to User Dir
			//--
		} else {
			log.Println("[NOTICE]", smart.CurrentFunctionName(), "WebDAV + Auth is using Shared Dir Space: `" + DAV_STORAGE_RELATIVE_ROOT_PATH + "`")
		} //end if // storagePath
	} //end if
	//--
	ls := webdavLockSys()
	//--
	wdav := webdav.Handler{
		Prefix:     	webDavRealUrlPath,
		FileSystem: 	webdav.Dir(webDavStorageRootPath),
		LockSys: 		ls,
		Logger:     	webDavLogger,
	}
	//-- #end auth check
	if((r.Method == http.MethodHead) || (r.Method == http.MethodGet) || (r.Method == http.MethodPost)) { // all 3 methods are handles by a single webdav internal method handleGetHeadPost()
		var wdirPath string = smart.StrSubstr(r.URL.Path, len(webDavRealUrlPath), 0)
		if(smart.StrTrimWhitespaces(wdirPath) == "") {
			wdirPath = "/"
		} //end if
		info, err := wdav.FileSystem.Stat(context.TODO(), wdirPath)
		if(err == nil) {
			if(info.IsDir()) {
				if(r.Method == http.MethodPost) { // POST
					wdvAction := smart.StrToLower(smart.StrTrimWhitespaces(GetPostVar(r, "webdav_action")))
					if(wdvAction != "upf") {
						smarthttputils.HttpStatus405(w, r, "Invalid POST Data [Rule:WEBDAV:POST:PARAM:ACTION]: `" + GetCurrentPath(r) + "`", true)
						webDavLogger(r, smart.NewError("Invalid WebDAV POST Data")) // important to log also this because return premature
						return
					} //end if
					realPath, errRealPath := wdav.FileSystem.GetRealPath(context.TODO(), wdirPath)
					if(errRealPath != nil) {
						smarthttputils.HttpStatus406(w, r, "Invalid POST Path [Rule:WEBDAV:POST:PATH]: `" + GetCurrentPath(r) + "`", true)
						webDavLogger(r, smart.NewError("Invalid WebDAV POST Path")) // important to log also this because return premature
						return
					} //end if
					if(!smart.StrStartsWith("./"+realPath, DAV_STORAGE_RELATIVE_ROOT_PATH)) {
						smarthttputils.HttpStatus423(w, r, "Unsafe POST Path [Rule:WEBDAV:POST:PATH]: `" + GetCurrentPath(r) + "`", true)
						webDavLogger(r, smart.NewError("Unsafe WebDAV POST Path")) // important to log also this because return premature
						return
					} //end if
					errUpload := webDavUploadHandler(r, realPath, webDavUseSmartSafeValidPaths, "file", ls)
					if(errUpload != nil) {
						smarthttputils.HttpStatus422(w, r, "POST File Save Failed [Rule:WEBDAV:POST:FILES:FILE]: `" + GetCurrentPath(r) + "`", true)
						webDavLogger(r, smart.NewError("WebDAV POST File Save Failed: " + errUpload.Error())) // important to log also this because return premature
						log.Println("[WARNING]", "WebDAV POST File(s) Error:", errUpload)
						return
					} //end if
					smarthttputils.HttpStatus201(w, r, "201 Created", "201.txt", "", -1, "", "", nil)
					webDavLogger(r, nil)
					return
				} else { // HEAD, GET
					r.Method = "PROPFIND" // this is a mapping for a directory from GET to PROPFIND ; TODO: it can be later supplied as a HTML Page listing all entries ; by mapping to PROPFIND will serve an XML
					if(r.Header == nil) { // fix for null
						r.Header = http.Header{}
					} //end if
					r.Header.Set("Depth", "1") // fix: ignore depth infinity, to avoid overload the file system
				} //end if else
			} //end if
		} //end if
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "WebDAV Service", "Method:", r.Method, "Depth:", smarthttputils.HttpRequestGetHeaderStr(r, "Depth"))
	} //end if
	//-- use no locks: first because many clients are buggy and can lock infinite a resource ; 2nd because on per-user instance the locking system is reset on each request
	wdav.ServeHTTP(w, r, webDavUseSmartSafeValidPaths) // if all ok above (basic auth + credentials ok, serve ...)
	//--
} //END FUNCTION


func webDavUploadHandler(r *http.Request, realPath string, useSmartSafeValidPaths bool, formFieldName string, ls *webdav.LockSys) error {
	//--
	// this is mosty a general upload handler, but written with WebDAV POST Upload in mind
	// outside WebDAV context the ls (lock sys) can be Null
	//--
//	log.Println("[DEBUG]", "realPath", realPath)
	//--
	if(smart.StrTrimWhitespaces(realPath) == "") {
		return smart.NewError("Upload Path is Empty")
	} //end if
	//--
	if(useSmartSafeValidPaths == true) {
		if(smart.PathIsWebSafeValidSafePath(realPath) != true) {
			return smart.NewError("Upload Path is Not Safe")
		} //end if
	} else {
		if(smart.PathIsWebSafeValidPath(realPath) != true) {
			return smart.NewError("Upload Path is Unsafe")
		} //end if
	} //end if else
	//--
	formFieldName = smart.StrTrimWhitespaces(formFieldName)
	if((formFieldName == "") || (!smart.StrRegexMatch(smarthttputils.REGEX_SAFE_HTTP_FORM_VAR_NAME, formFieldName))) {
		return smart.NewError("Upload Form Field Name is Empty or Unsafe: `" + formFieldName + "`")
	} //end if
	//--
	wdvFiles, errPostFiles := GetPostFiles(r, formFieldName)
	if(errPostFiles != nil) {
		return smart.NewError("Upload Files ERR: " + errPostFiles.Error())
	} //end if
	if(len(wdvFiles) <= 0) {
		return smart.NewError("No Upload Files found")
	} //end if
	//--
	for uf:=0; uf<len(wdvFiles); uf++ {
		//--
		upf := wdvFiles[uf]
		//--
		if((upf.Error != nil) || (upf.Header == nil) || (upf.File == nil)) {
			return smart.NewError("Upload File Failed #" + smart.ConvertIntToStr(uf))
		} //end if
		//--
		upfName := smart.StrTrimWhitespaces(upf.Header.Filename)
		if(upfName == "") {
			return smart.NewError("Upload File has an Empty File Name #" + smart.ConvertIntToStr(uf))
		} //end if
		//--
		upfPath := smart.PathAddDirLastSlash(realPath) + upfName
		//--
		if(ls != nil) {
			lToken, errLToken := ls.Lock(false, upfPath)
			if(errLToken != nil) {
				return smart.NewError("Failed to Lock Upload File #" + smart.ConvertIntToStr(uf) + ", ERR: " + errLToken.Error())
			} //end if
			if(smart.StrTrimWhitespaces(lToken) == "") {
				return smart.NewError("Failed to Lock Upload File #" + smart.ConvertIntToStr(uf) + ", Token is Empty")
			} //end if
			if(ls.Exists(false, lToken) != true) {
				return smart.NewError("Failed to Lock Upload File #" + smart.ConvertIntToStr(uf) + ", Lock Token Not Found")
			} //end if
			defer ls.Unlock(false, lToken)
		} //end if
		//--
		//== start: single file upload standalone code
		//--
		if(useSmartSafeValidPaths == true) {
			if(smart.PathIsSafeValidSafeFileName(upfName) != true) {
				return smart.NewError("Upload File Name is Not Safe #" + smart.ConvertIntToStr(uf))
			} //end if
		} else {
			if(smart.PathIsSafeValidFileName(upfName) != true) {
				return smart.NewError("Upload File Name is Unsafe #" + smart.ConvertIntToStr(uf))
			} //end if
		} //end if else
		//--
		if(useSmartSafeValidPaths == true) {
			if(smart.PathIsWebSafeValidSafePath(upfPath) != true) {
				return smart.NewError("Upload File Path is Not Safe #" + smart.ConvertIntToStr(uf))
			} //end if
		} else {
			if(smart.PathIsWebSafeValidPath(upfPath) != true) {
				return smart.NewError("Upload File Path is Unsafe #" + smart.ConvertIntToStr(uf))
			} //end if
		} //end if else
		//--
		var isOkSave bool = true
		fUpRes, fUpErrRes := os.OpenFile(upfPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, smart.CHOWN_FILES)
		if(fUpErrRes != nil) {
			isOkSave = false
		} else {
			_, errUplCopy := io.Copy(fUpRes, upf.File)
			if(errUplCopy != nil) {
				isOkSave = false
			} //end if
		} //end if
		errUplClose := fUpRes.Close()
		if(errUplClose != nil) {
			return smart.NewError("Failed to Save/Close Upload File #" + smart.ConvertIntToStr(uf))
		} //end if
		fUpRes = nil // force close
		if(isOkSave != true) {
			return smart.NewError("Failed to Save Upload File #" + smart.ConvertIntToStr(uf))
		} //end if
		//--
		//== end: single file upload standalone code #
		//--
	} //end for
	//--
	return nil
	//--
} //END FUNCTION


// #END
