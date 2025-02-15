
// GO Lang :: SmartGo / Web Server / Utils :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250214.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"time"
	"net/url"
	"net/http"
	"mime/multipart"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)


func IsAjaxRequest(r *http.Request) bool {
	//--
	return smarthttputils.IsAjaxRequest(r)
	//--
} //END FUNCTION


func GetVisitorRemoteIpAddrAndPort(r *http.Request) (string, string) { // returns: remoteAddr, remotePort
	//--
	// returns the zero level client IP address and Port ; to get real client IP use: GetVisitorRealIpAddr() ; the current method may return wrong results if the web server is behind a proxy, in this case the proxy IP and Port will be returned
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	return smart.GetHttpRemoteAddrIpAndPortFromRequest(r)
	//--
} //END FUNCTION


func GetVisitorRealIpAddr(r *http.Request) (bool, string) { // returns: isOk, clientRealIp
	//--
	// this is the real IP address of the user that should be used ; if the server is behind a proxy it will be different than remote IP which in this case is the proxy IP
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	isOk, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
	//--
	return isOk, realClientIp
	//--
} //END FUNCTION


func GetCookie(r *http.Request, name string) string {
	//--
	return smarthttputils.HttpRequestGetCookie(r, name)
	//--
} //END FUNCTION


func RequestHaveQueryString(r *http.Request) bool {
	//--
	defer smart.PanicHandler()
	//--
	return (len(GetUrlRawQuery(r)) > 0)
	//--
} //END FUNCTION


func GetUrlRawQuery(r *http.Request) string { // get the url raw query as string from request, except the ? ; ex: from `?a=b&c=d` will get `a=b&c=d`
	//--
	return r.URL.RawQuery
	//--
} //END FUNCTION


func ParseUrlRawQuery(urlQuery string) map[string][]string {
	//--
	defer smart.PanicHandler()
	//--
	urlQuery = smart.StrTrimWhitespaces(urlQuery)
	if(urlQuery == "") {
		return nil
	} //end if
	//--
	vals, err := url.ParseQuery(urlQuery)
	if(err != nil) {
		return nil
	} //end if
	//--
	return vals
	//--
} //END FUNCTION


func GetUrlQueryVar(r *http.Request, key string) string { // get an url param string from request
	//--
	defer smart.PanicHandler()
	//--
	key = smart.StrTrimWhitespaces(key)
	if(key == "") {
		return ""
	} //end if
	//--
	return r.URL.Query().Get(key)
	//--
} //END FUNCTION


func GetUrlQueryVars(r *http.Request, key string) []string { // get an url param array from request
	//--
	defer smart.PanicHandler()
	//--
	key = smart.StrTrimWhitespaces(key)
	if(key == "") {
		return nil
	} //end if
	//--
	return r.URL.Query()[key]
	//--
} //END FUNCTION


func GetAllUrlQueryVars(r *http.Request) map[string][]string { // get all url params from request
	//--
	defer smart.PanicHandler()
	//--
	return r.URL.Query()
	//--
} //END FUNCTION


func GetPostVar(r *http.Request, key string) string { // get a post param string from request
	//--
	defer smart.PanicHandler()
	//--
	if(r.PostForm == nil) {
		ParseForm(r)
	} //end if
	if(r.MultipartForm == nil) {
		ParseMultipartForm(r)
	} //end if
	//--
	key = smart.StrTrimWhitespaces(key)
	if(key == "") {
		return ""
	} //end if
	//--
	return r.PostFormValue(key)
	//--
} //END FUNCTION


func GetPostVars(r *http.Request, key string) []string { // get a post param array from request
	//--
	defer smart.PanicHandler()
	//--
	if(r.PostForm == nil) {
		ParseForm(r)
	} //end if
	if(r.MultipartForm == nil) {
		ParseMultipartForm(r)
	} //end if
	//--
	key = smart.StrTrimWhitespaces(key)
	if(key == "") {
		return nil
	} //end if
	//--
	return r.PostForm[key]
	//--
} //END FUNCTION


func GetAllPostVars(r *http.Request) map[string][]string { // get all post params from request
	//--
	defer smart.PanicHandler()
	//--
	if(r.PostForm == nil) {
		ParseForm(r)
	} //end if
	if(r.MultipartForm == nil) {
		ParseMultipartForm(r)
	} //end if
	//--
	return r.PostForm
	//--
} //END FUNCTION


func GetRequestVar(r *http.Request, key string) string { // get an url or post (mixed) param string from request
	//--
	defer smart.PanicHandler()
	//--
	// The precedence order:
	//  1. application/x-www-form-urlencoded form body (POST, PUT, PATCH only)
	//  2. query parameters (always)
	//  3. multipart/form-data form body (always)
	//--
	if(r.PostForm == nil) {
		ParseForm(r)
	} //end if
	if(r.MultipartForm == nil) {
		ParseMultipartForm(r)
	} //end if
	//--
	key = smart.StrTrimWhitespaces(key)
	if(key == "") {
		return ""
	} //end if
	//--
	return r.FormValue(key)
	//--
} //END FUNCTION


func GetRequestVars(r *http.Request, key string) []string { // get an url or post (mixed) param array from request
	//--
	defer smart.PanicHandler()
	//--
	// The precedence order:
	//  1. application/x-www-form-urlencoded form body (POST, PUT, PATCH only)
	//  2. query parameters (always)
	//  3. multipart/form-data form body (always)
	//--
	if(r.PostForm == nil) {
		ParseForm(r)
	} //end if
	if(r.MultipartForm == nil) {
		ParseMultipartForm(r)
	} //end if
	//--
	key = smart.StrTrimWhitespaces(key)
	if(key == "") {
		return nil
	} //end if
	//--
	return r.Form[key]
	//--
} //END FUNCTION


func GetAllRequestVars(r *http.Request) map[string][]string { // get all url and post (mixed) params from request
	//--
	defer smart.PanicHandler()
	//--
	// The precedence order:
	//  1. application/x-www-form-urlencoded form body (POST, PUT, PATCH only)
	//  2. query parameters (always)
	//  3. multipart/form-data form body (always)
	//--
	if(r.PostForm == nil) {
		ParseForm(r)
	} //end if
	if(r.MultipartForm == nil) {
		ParseMultipartForm(r)
	} //end if
	//--
	return r.Form
	//--
} //END FUNCTION


type MultiPartPostFile struct {
	Error  error
	Header *multipart.FileHeader
	File   multipart.File
	Key    string
}


func GetPostFile(r *http.Request, key string) MultiPartPostFile {
	//--
	defer smart.PanicHandler()
	//--
	if(r.PostForm == nil) {
		ParseForm(r)
	} //end if
	if(r.MultipartForm == nil) {
		ParseMultipartForm(r)
	} //end if
	//--
	theFile := MultiPartPostFile{}
	//--
	key = smart.StrTrimWhitespaces(key)
	if(key == "") {
		theFile.Error = smart.NewError("GetPostFile: The Key is Empty")
		return theFile
	} //end if
	//--
	f, h, err := r.FormFile(key)
	if(err != nil) {
		theFile.Error = err
		return theFile
	} //end if
	theFile.Header = h
	theFile.File = f
	theFile.Key = key
	//--
	return theFile
	//--
} //END FUNCTION


func GetPostFiles(r *http.Request, key string) ([]MultiPartPostFile, error) {
	//--
	defer smart.PanicHandler()
	//--
	if(r.MultipartForm == nil) {
		errMultiPart := ParseMultipartForm(r)
		if(errMultiPart != nil) {
			return nil, errMultiPart
		} //end if
	} //end if
	//--
	if((r.MultipartForm == nil) || (r.MultipartForm.File == nil)) {
		return nil, http.ErrMissingFile
	} //end if
	//--
	var theFiles []MultiPartPostFile = []MultiPartPostFile{}
	//--
	fhs := r.MultipartForm.File[key]
	if(len(fhs) <= 0) {
		return theFiles, nil
	} //end if
	for i:=0; i<len(fhs); i++ {
		f, err := fhs[i].Open()
		theFile := MultiPartPostFile{}
		if(err != nil) {
			theFile.Error = err
		} else {
			theFile.Header = fhs[i]
			theFile.File = f
			theFile.Key = key
		} //end if
		theFiles = append(theFiles, theFile)
	} //end for
	//--
	return theFiles, nil
	//--
} //END FUNCTION


func GetAllPostFiles(r *http.Request) map[string][]MultiPartPostFile {
	//--
	defer smart.PanicHandler()
	//--
	if(r.MultipartForm == nil) {
		ParseMultipartForm(r)
	} //end if
	//--
	var allFiles map[string][]MultiPartPostFile = map[string][]MultiPartPostFile{}
	//--
	if((r.MultipartForm == nil) || (r.MultipartForm.File == nil)) {
		return allFiles
	} //end if
	//--
	fhs := r.MultipartForm.File
	if(len(fhs) <= 0) {
		return allFiles
	} //end if
	for k, _ := range fhs {
		theFiles, _ := GetPostFiles(r, k)
		allFiles[k] = theFiles
	} //end for
	//--
	return allFiles
	//--
} //END FUNCTION


func ParseForm(r *http.Request) error {
	//--
	defer smart.PanicHandler()
	//--
	// For all requests, ParseForm parses the raw query from the URL and updates r.Form.
	// Request body parameters take precedence over URL query string values in r.Form.
	// For POST, PUT, and PATCH requests, it also reads the request body, parses it as a form and puts the results into both r.PostForm and r.Form.
	// For other HTTP methods, or when the Content-Type is not application/x-www-form-urlencoded, the request Body is not read, and r.PostForm is initialized to a non-nil, empty value.
	// ParseForm is idempotent (subsequent calls have no effect).
	//--
	return r.ParseForm()
	//--
} //END FUNCTION


func ParseMultipartForm(r *http.Request) error {
	//--
	defer smart.PanicHandler()
	//--
	// ParseMultipartForm will call internally the ParseForm if necessary
	// If ParseForm returns an error, ParseMultipartForm returns it but also continues parsing the request body.
	// After one call to ParseMultipartForm, subsequent calls have no effect.
	//--
	return r.ParseMultipartForm(int64(maxPostSize))
	//--
} //END FUNCTION


func HttpRequestGetHeaderStr(r *http.Request, hdrKey string) string {
	//--
	defer smart.PanicHandler()
	//--
	return smarthttputils.HttpRequestGetHeaderStr(r, hdrKey)
	//--
} //END FUNCTION


func GetClientMimeAcceptHeaders(r *http.Request) []string {
	//--
	defer smart.PanicHandler()
	//--
	arrAccepts := smarthttputils.ParseClientMimeAcceptHeader(smarthttputils.HttpRequestGetHeaderStr(r, smarthttputils.HTTP_HEADER_ACCEPT_MIMETYPE)) // {{{SYNC-SMARTGO-HTTP-ACCEPT-HEADER}}} ; accept headers can be many, just get the prefered one
	if(arrAccepts == nil) {
		arrAccepts = []string{}
	} //end if
	//--
	return arrAccepts
	//--
} //END FUNCTION


func GetBaseDomainDomainPort(r *http.Request) (string, string, string, error) {
	//--
	// returns: basedom, dom, port, errDomPort
	//--
	defer smart.PanicHandler()
	//--
	dom, port, errDomPort := smart.GetHttpDomainAndPortFromRequest(r)
	if(errDomPort != nil) {
		return "", "", "", errDomPort
	} //end if
	if(smart.StrTrimWhitespaces(dom) == "") {
		return "", "", "", smart.NewError("Domain is Empty")
	} //end if
	if(smart.StrTrimWhitespaces(port) == "") {
		return "", "", "", smart.NewError("Port is Empty")
	} //end if
	baseDom, errBaseDom := smart.GetBaseDomainFromDomain(dom)
	if(errBaseDom != nil) {
		return "", "", "", errBaseDom
	} //end if
	if(smart.StrTrimWhitespaces(baseDom) == "") {
		return "", "", "", smart.NewError("Base Domain is Empty")
	} //end if
	//--
	return baseDom, dom, port, nil
	//--
} //END FUNCTION


func GetBasePath() string { // this is the internal (non-proxy mode) base path which is always `/`
	//--
	return "/"
	//--
} //END FUNCTION


func GetBaseBrowserPath() string { // includes proxy prefix if any ; includes trailing slashes
	//--
	defer smart.PanicHandler()
	//--
	return smart.GetHttpProxyBasePath() // if no proxy, this is: `/` ; but under proxy may be the same or as: `/custom-path/`
	//--
} //END FUNCTION


func GetCurrentPath(r *http.Request) string { // this does not include the proxy prefix, it is the internal path
	//--
	defer smart.PanicHandler()
	//--
	return smart.GetHttpPathFromRequest(r)
	//--
} //END FUNCTION


func GetCurrentBrowserPath(r *http.Request) string { // this includes the proxy prefix
	//--
	defer smart.PanicHandler()
	//--
	return smart.GetHttpBrowserPathFromRequest(r)
	//--
} //END FUNCTION


func GetCurrentBaseUrl(r *http.Request) string { // this does not include the proxy prefix/domain/port, it is the internal url
	//--
	defer smart.PanicHandler()
	//--
	dom := httpServerAddr
	port := httpServerPort
	//--
	return GetCurrentProtocol(r) + dom + ":" + port + GetBasePath()
	//--
} //END FUNCTION


func GetCurrentBrowserBaseUrl(r *http.Request) string { // this includes the proxy prefix/domain/port, it is the browser external url as seen in browser
	//--
	defer smart.PanicHandler()
	//--
	return smart.GetHttpBaseUrlFromRequest(r)
	//--
} //END FUNCTION


func GetCurrentUrl(r *http.Request, withUrlQuery bool) string { // this does not include the proxy prefix/domain/port, it is the internal url
	//--
	defer smart.PanicHandler()
	//--
	var urlQuery = ""
	if(withUrlQuery) {
		if(RequestHaveQueryString(r)) {
			urlQuery = "?" + GetUrlRawQuery(r)
		} //end if
	} //end if
	//--
	dom := httpServerAddr
	port := httpServerPort
	//--
	return GetCurrentProtocol(r) + dom + ":" + port + GetCurrentPath(r) + urlQuery
	//--
} //END FUNCTION


func GetCurrentBrowserUrl(r *http.Request, withUrlQuery bool) string { // this includes the proxy prefix/domain/port, it is the browser external url as seen in browser
	//--
	defer smart.PanicHandler()
	//--
	return smart.GetHttpUrlFromRequest(r, withUrlQuery)
	//--
} //END FUNCTION


func GetCurrentProtocol(r *http.Request) string { // this is the internal server protocol
	//--
	if(httpServeSecure == true) {
		return "https://"
	} //end if
	//--
	return "http://"
	//--
} //END FUNCTION


func GetCurrentBrowserProtocol(r *http.Request) string { // if proxy this is the proxy protocol, otherwise the internal server protocol
	//--
	defer smart.PanicHandler()
	//--
	return smart.GetHttpProtocolFromRequest(r)
	//--
} //END FUNCTION


func GetCurrentYear() string {
	//--
	return smart.ConvertIntToStr(time.Now().UTC().Year())
	//--
} //END FUNCTION


func GetAuthRealm() string {
	//--
	return httpAuthRealm
	//--
} //END FUNCTION


func EncryptUrlValue(val string) string {
	//--
	defer smart.PanicHandler()
	//--
	if(val == "") {
		return ""
	} //end if
	//--
	sKey, errSKey := smart.AppGetSecurityKey()
	if(errSKey != nil) {
		return "" // app security key error
	} //end if
	//--
	sKey = smart.StrTrimWhitespaces(sKey)
	if(sKey == "") {
		return "" // app security key is empty
	} //end if
	//--
	sKey = smart.StrTrimWhitespaces(smart.BaseEncode([]byte(sKey), "b85")) // security: for the URLs use a derivation as B85 to avoid rainbow like security key reflections in other sensitive encrypted data with the same app key
	if(sKey == "") {
		return "" // app security key derivation is empty
	} //end if
	//--
	val = smart.StrTrimWhitespaces(smart.TwofishEncryptBlowfishCBC(val, sKey, true)) // randomize ; trim, should be the b64u data ; use a combination of 2F+BF to make exponential changes on string when a single byte was changed, make it harder to any guess
	if(val == "") {
		return "" // encrypted value is empty
	} //end if
	//--
	val = smart.StrSubstr(val, len(smart.SIGNATURE_2FISH_V1_BF_DEFAULT), 0)
	//--
	return val
	//--
} //END FUNCTION


func DecryptUrlValue(val string) string {
	//--
	defer smart.PanicHandler()
	//--
	val = smart.StrTrimWhitespaces(val)
	if(val == "") {
		return ""
	} //end if
	val = smart.SIGNATURE_2FISH_V1_BF_DEFAULT + val
	//--
	sKey, errSKey := smart.AppGetSecurityKey()
	if(errSKey != nil) {
		return "" // app security key error
	} //end if
	//--
	sKey = smart.StrTrimWhitespaces(sKey)
	if(sKey == "") {
		return "" // app security key is empty
	} //end if
	//--
	sKey = smart.StrTrimWhitespaces(smart.BaseEncode([]byte(sKey), "b85")) // security: for the URLs use a derivation as B85 to avoid rainbow like security key reflections in other sensitive encrypted data with the same app key
	if(sKey == "") {
		return "" // app security key derivation is empty
	} //end if
	//--
	return smart.TwofishDecryptBlowfishCBC(val, sKey)
	//--
} //END FUNCTION


// #END
