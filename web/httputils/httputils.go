
// GO Lang :: SmartGo / Web HTTP Utils :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250214.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package httputils

import (
	"fmt"
	"log"
	"time"

	"os"
	"sync"

	"io"
	"bytes"

	"mime"
	"mime/multipart"

	"net/http"
	"net/http/httputil"

	"crypto/tls"
	"crypto/x509"

//	"golang.org/x/time/rate"
	"github.com/unix-world/smartgo/utils/time-rate"

	smart 		 "github.com/unix-world/smartgo"
	smartcache 	 "github.com/unix-world/smartgo/data-structs/simplecache"
	assets 		 "github.com/unix-world/smartgo/web/assets/web-assets"
	smartcaptcha "github.com/unix-world/smartgo/web/captcha"
	filelock 	 "github.com/unix-world/smartgo/utils/filelock"
	pbar 		 "github.com/unix-world/smartgo/ui/progressbar"
)


//-----

const (
	VERSION string = "r.20250214.2358"

	//--
	DEFAULT_CLIENT_UA string = smart.DEFAULT_BROWSER_UA
	//--
	HTTP_CLI_DEF_BODY_READ_SIZE uint64 = smart.SIZE_BYTES_16M 		//  16MB
//	HTTP_CLI_MAX_BODY_READ_SIZE uint64 = smart.SIZE_BYTES_16M * 32 	// 512MB
	HTTP_CLI_MAX_BODY_READ_SIZE uint64 = smart.SIZE_BYTES_16M * 48 	// 768MB ; allow to download ~ the size of a CD by max default
	//--
	HTTP_CLI_MAX_POST_VAL_SIZE  uint64 = smart.SIZE_BYTES_16M 		//  16MB
	HTTP_CLI_MAX_POST_FILE_SIZE uint64 = smart.SIZE_BYTES_16M * 16 	// 256MB
	HTTP_CLI_MAX_POST_DATA_SIZE uint64 = smart.SIZE_BYTES_16M * 24 	// 384MB
	//--
	HTTP_CLI_MAX_REDIRECTS uint8 = 25
	//--
	HTTP_CLI_MIN_TIMEOUT uint32 =     5 // 5 seconds
	HTTP_CLI_DEF_TIMEOUT uint32 =   720 // 12 minutes
	HTTP_CLI_MAX_TIMEOUT uint32 = 86400 // 24 hours
	//--
	HTTP_CLI_TLS_TIMEOUT uint32 =    15 // 15 seconds (default is 10 seconds, as defined in the net library)
	//--
	HTTP_MAX_SIZE_SAFE_COOKIE uint16 = 4096 // max safe raw size is 4096, which includes also the variable name
	HTTP_MAX_SIZE_SAFE_URL    uint16 = 4096
	//--

	//--
	DEFAULT_REALM string = "SmartGO Web Server" // must be min 7 chars
	//--
	HTTP_SRV_IDLE_TIMEOUT uint32 = 60 // standard, as Apache
	//--
	DISP_TYPE_INLINE string 	= "inline"
	DISP_TYPE_ATTACHMENT string = "attachment"
	//--
	MIME_TYPE_ANY string 		= "*/*" // reserved just for request accept header, never use for responses
	MIME_TYPE_DEFAULT string 	= "application/octet-stream"
	MIME_TYPE_TEXT string 		= "text/plain"
	MIME_TYPE_HTML string 		= "text/html"
	MIME_TYPE_CSS string 		= "text/css"
	MIME_TYPE_JS string 		= "application/javascript"
	MIME_TYPE_JSON string 		= "application/json"
	MIME_TYPE_XML string 		= "application/xml"
	MIME_TYPE_SVG string 		= "image/svg+xml"
	MIME_TYPE_PNG string 		= "image/png"
	MIME_TYPE_GIF string 		= "image/gif"
	MIME_TYPE_JPEG string 		= "image/jpeg"
	MIME_TYPE_WEBP string 		= "image/webp"
	MIME_TYPE_CSV string 		= "text/csv"
	MIME_TYPE_EMAIL_MSG string 	= "message/rfc822"
	MIME_TYPE_ICALENDAR string 	= "text/calendar"
	MIME_TYPE_VCARD string 		= "text/x-vcard"
	MIME_TYPE_SIG_GPG string 	= "application/pgp-signature"
	MIME_TYPE_PDF string 		= "application/pdf"
	MIME_TYPE_AUDIO_OGG string 	= "audio/ogg"
	MIME_TYPE_VIDEO_OGV string 	= "video/ogg"
	MIME_TYPE_VIDEO_WEBM string = "video/webm"
	MIME_TYPE_AUDIO_MPEG string = "audio/mpeg"
	MIME_TYPE_VIDEO_MPEG string = "video/mpeg"
	MIME_TYPE_WOFF2 string 		= "application/x-font-woff2"
	MIME_TYPE_WOFF1 string 		= "application/x-font-woff"
	MIME_TYPE_TTF string 		= "application/x-font-ttf"
	MIME_TYPE_FAVICON string 	= "image/vnd.microsoft.icon"
	//--
	ICACHEM_CLEANUP_INTERVAL uint32 =   5 // 5 seconds
	ICACHEM_EXPIRATION       uint32 = 300 // 300 seconds = 5 mins ; cache unsuccessful logins for 5 mins
	ICACHEM_FAILS_NUM        uint8  = 5*2 // max fail attempts before lock 5 mins (300 sec) ; use x2 because most of the time in browsers each unauth request will generate double requests
	//--
	CACHE_CONTROL_NOCACHE string = "no-cache"
	CACHE_CONTROL_PRIVATE string = "private"
	CACHE_CONTROL_PUBLIC  string = "public"
	CACHE_CONTROL_DEFAULT string = "default"
	//--
	MAX_SIZE_ETAG int64 = 1048576 // 1MB 1048576 bytes ; 100% of assets match this criteria ; for the rest (ex: public files), Weak ETag is not worth ...
	//--
	REGEX_SAFE_HTTP_FORM_VAR_NAME string = `^[a-zA-Z0-9_\-\.\:\#]+$` // original: `^[a-zA-Z0-9_\-]+$` ; allow extended as PHP supports
	//--

	//--
	HTTP_STATUS_200 string = "200 OK"
	HTTP_STATUS_201 string = "201 Created"
	HTTP_STATUS_202 string = "202 Accepted"
	HTTP_STATUS_203 string = "203 Non-Authoritative Information"
	HTTP_STATUS_204 string = "204 No Content"
	HTTP_STATUS_208 string = "208 Already Reported"
	//--
	HTTP_STATUS_301 string = "301 Moved Permanently"
	HTTP_STATUS_302 string = "302 Found" // "302 Moved Temporarily"
	HTTP_STATUS_304 string = "304 Not Modified"
	//--
	HTTP_STATUS_400 string = "400 Bad Request"
	HTTP_STATUS_401 string = "401 Unauthorized"
	HTTP_STATUS_402 string = "402 Subscription Required" // 402 Payment Required
	HTTP_STATUS_403 string = "403 Forbidden"
	HTTP_STATUS_404 string = "404 Not Found"
	HTTP_STATUS_405 string = "405 Method Not Allowed"
	HTTP_STATUS_406 string = "406 Not Acceptable"
	HTTP_STATUS_408 string = "408 Request Timeout"
	HTTP_STATUS_409 string = "409 Conflict" // example: conflicts occur if a request to create collection /a/b/c/d/ is made, and /a/b/c/ does not exist
	HTTP_STATUS_410 string = "410 Gone" // a more permanent 404 like status, ex: if a page was available just for a period of time
	HTTP_STATUS_415 string = "415 Unsupported Media Type"
	HTTP_STATUS_422 string = "422 Unprocessable Content" // 422 Unprocessable Entity
	HTTP_STATUS_423 string = "423 Locked"
	HTTP_STATUS_424 string = "424 Dependency Failed" // 424 Failed Dependency ; the request failed because it depended on another request
	HTTP_STATUS_429 string = "429 Too Many Requests"
	//--
	HTTP_STATUS_500 string = "500 Internal Server Error"
	HTTP_STATUS_501 string = "501 Not Implemented"
	HTTP_STATUS_502 string = "502 Bad Gateway"
	HTTP_STATUS_503 string = "503 Service Unavailable"
	HTTP_STATUS_504 string = "504 Gateway Timeout"
	HTTP_STATUS_507 string = "507 Insufficient Storage"
	//--

	//--
	HTTP_AJAX_REQUEST_SIGNATURE string = "xmlhttprequest"
	//--

	//--
	HTTP_HEADER_CONTENT_X_REQUESTED_WITH string = "x-requested-with"
	//--
	HTTP_HEADER_ACCEPT_MIMETYPE string = "accept"
	//--
	HTTP_HEADER_CONTENT_TYPE string = "content-type"
	HTTP_HEADER_CONTENT_DISP string = "content-disposition"
	HTTP_HEADER_CONTENT_LEN  string = "content-length"
	//--
	HTTP_HEADER_CACHE_CTRL string = "cache-control"
	HTTP_HEADER_CACHE_PGMA string = "pragma"
	HTTP_HEADER_CACHE_EXPS string = "expires"
	HTTP_HEADER_CACHE_LMOD string = "last-modified"
	//--
	HTTP_HEADER_RETRY_AFTER string = "retry-after"
	HTTP_HEADER_ALLOW string = "allow"
	//--
	HTTP_HEADER_ETAG_SUM  string = "etag"
	HTTP_HEADER_ETAG_IFNM string = "if-none-match"
	//--
	HTTP_HEADER_SERVER_DATE string = "date"
	HTTP_HEADER_SERVER_SIGN string = "server"
	HTTP_HEADER_SERVER_POWERED string = "x-powered-by"
	//--
	HTTP_HEADER_REDIRECT_LOCATION string = "location"
	//--
	HTTP_HEADER_DISABLE_AUTH_PROMPT string = "w-no-auth-prompt" // {{{SYNC-HTTP-UTILS-CLI-HDR-NO-AUTH-PROMPT-TRUE}}} ; if client send this header with a value of `true` will disable auth prompt
	//--
	HTTP_HEADER_AUTH_AUTHENTICATE string = "www-authenticate"
	HTTP_HEADER_AUTH_AUTHORIZATION string = "authorization"
	HTTP_HEADER_VALUE_AUTH_TYPE_BASIC string = "Basic" // keep camel case
	HTTP_HEADER_VALUE_AUTH_TYPE_TOKEN string = "Token" // keep camel case
	HTTP_HEADER_VALUE_AUTH_TYPE_BEARER string = "Bearer" // keep camel case
	HTTP_HEADER_VALUE_AUTH_TYPE_APIKEY string = "ApiKey" // keep camel case
	//--
	HTTP_HEADER_DAV_DESTINATION string = "destination"
	HTTP_HEADER_DAV_OVERWRITE string = "overwrite"
	//--
	HTTP_HEADER_USER_AGENT string = "user-agent"
	//--
	HTTP_HEADER_INVALID_EMPTY_KEY string = "z-empty-key" // custom error
	//--
)

var (
	DEBUG bool = smart.DEBUG
	DEBUG_CACHE bool = smart.DEBUG
)


//-----

var memAuthMutex sync.Mutex
var memAuthCache *smartcache.InMemCache = nil

//-----

var memRateLimitMutex sync.Mutex
var memRateLimitCache *smartcache.InMemCache = nil

type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

//-----


func TlsConfigClient(insecureSkipVerify bool, serverPEM string) tls.Config {
	//--
	defer smart.PanicHandler()
	//--
	cfg := tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}
	//--
	if(insecureSkipVerify == true) {
		cfg.InsecureSkipVerify = true
		log.Println("[NOTICE] " + smart.CurrentFunctionName() + ": InsecureSkipVerify was set to TRUE")
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
			log.Println("[NOTICE] " + smart.CurrentFunctionName() + ": Appending a custom Server Certificate to the default x509 Root:", len(serverPEM), "bytes")
		} else {
			log.Println("[ERROR] " + smart.CurrentFunctionName() + ": Failed to parse server certificate")
		} //end if
	} //end if
	//--
	return cfg
	//--
} //END FUNCTION


//-----


type HttpClientRequest struct {
	Errors                string            `json:"errors"`
	UserAgent             string            `json:"userAgent"`
	ConnTimeout           uint32            `json:"connTimeout,string"`
	MaxDownloadSize       uint64            `json:"maxDownloadSize,string"`
	HttpMethod            string            `json:"httpMethod"`
	AuthUserName          string            `json:"authUserName"`
	Uri                   string            `json:"uri"`
	RedirectLocation      string            `json:"redirectLocation"`
	MaxRedirects          uint8             `json:"maxRedirects,string"`
	NumRedirects          uint8             `json:"numRedirects,string"`
	RedirUris             []string          `json:"redirUris"`
	LastUri               string            `json:"lastUri"`
	UploadLocalFile       string            `json:"uploadLocalFile"` // PUT
	UploadFileName        string            `json:"uploadFileName"` // PUT
	UploadDataSize        int64             `json:"uploadDataSize,string"` // POST | PUT
	HttpStatus            int               `json:"httpStatus,string"`
	HeadData              string            `json:"headData"`
	HeadDataSize          uint64            `json:"headDataSize,string"`
	Cookies               map[string]string `json:"cookies"`
	AllowMethods          string            `json:"allowMethods"` // OPTIONS
	LastModified          string            `json:"lastModified"`
	Expires               string            `json:"expires"`
	RetryAfter            string            `json:"retryAfter"`
	MimeType              string            `json:"mimeType"`
	MimeCharSet           string            `json:"mimeCharSet"`
	MimeDisp              string            `json:"mimeDisp"`
	MimeFileName          string            `json:"mimeFileName"`
	ContentLength         int64             `json:"contentLength,string"`
	BodyData              string            `json:"bodyData"`
	BodyDataSize          uint64            `json:"bodyDataSize,string"` // unencoded
	BodyDataEncoding      string            `json:"bodyDataEncoding"` // plain | base64 | log
	DownloadLocalDir      string            `json:"downloadLocalDir"`
	DownloadLocalFileName string            `json:"downloadLocalFileName"`
}


//-----


func HttpClientDoRequestHEAD(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "HEAD"
	var reqArr map[string][]string = nil
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


// IMPORTANT: will not rewrite the download file if exists ... must be previous deleted !
// can handle: GET or POST
func HttpClientDoRequestDownloadFile(downloadLocalDirPath string, method string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, reqArr map[string][]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var upldLocalFilePath string = ""
	//--
	downloadLocalDirPath = smart.StrTrimWhitespaces(downloadLocalDirPath)
	downloadLocalDirPath = smart.SafePathFixSeparator(downloadLocalDirPath)
	if(downloadLocalDirPath == "") {
		downloadLocalDirPath = "./downloads/" // dissalow empty directory ; for downloads a directory is mandatory ; dissalow download in the same dir as executable is, there is a risk to rewrite the executable !!!
	} //end if
	//--
	method = smart.StrToUpper(smart.StrTrimWhitespaces(method))
	if(method != "POST") {
		method = "GET"
	} //end if
	if(reqArr == nil) {
		method = "GET"
	} //end if
	//--
	var maxBytesRead uint64 = 0 // there is no limit when saving to a file ...
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestGET(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxBytesRead uint64, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "GET"
	var reqArr map[string][]string = nil
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	//--
	if(maxBytesRead <= 0) {
		maxBytesRead = HTTP_CLI_MAX_BODY_READ_SIZE
	} //end if
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPOST(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, reqArr map[string][]string, timeoutSec uint32, maxBytesRead uint64, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "POST"
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	//--
	if(maxBytesRead <= 0) {
		maxBytesRead = HTTP_CLI_DEF_BODY_READ_SIZE
	} //end if
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPOSTBody(postMime string, postBody string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "PUT"
	var reqArr map[string][]string = map[string][]string{
		"@put:data":   { postBody },
		"@put:method": { "POST" },
		"@put:ctype":  { postMime },
	}
	postBody = "" // free mem
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPUTFile(upldLocalFilePath string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "PUT"
	var reqArr map[string][]string = nil
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPUT(putData string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "PUT"
	var reqArr map[string][]string = map[string][]string{
		"@put:data": { putData },
	}
	putData = "" // free mem
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPATCH(patchData string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "PATCH"
	var reqArr map[string][]string = map[string][]string{
		"@patch:data": { patchData },
	}
	patchData = "" // free mem
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestMKCOL(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "MKCOL"
	var reqArr map[string][]string = nil
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestDELETE(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "DELETE"
	var reqArr map[string][]string = nil
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestCOPY(destinationUri string, overwrite bool, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "COPY"
	var strOverwrite string = "F"
	if(overwrite == true) {
		strOverwrite = "T"
	} //end if
	var reqArr map[string][]string = map[string][]string{
		"@copy:destination": { destinationUri },
		"@copy:overwrite":   { strOverwrite },
	}
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestMOVE(destinationUri string, overwrite bool, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "MOVE"
	var strOverwrite string = "F"
	if(overwrite == true) {
		strOverwrite = "T"
	} //end if
	var reqArr map[string][]string = map[string][]string{
		"@move:destination": { destinationUri },
		"@move:overwrite":   { strOverwrite },
	}
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPROPFIND(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "PROPFIND"
	var reqArr map[string][]string = nil
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestOPTIONS(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) HttpClientRequest {
	//--
	var method string = "OPTIONS"
	var reqArr map[string][]string = nil
	var upldLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, upldLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


//-----


func reqArrToHttpFormData(reqArr map[string][]string) (err string, formData *bytes.Buffer, multipartType string) {
	//--
	defer smart.PanicHandler()
	//--
	// This will create the form data or multi/part form data by reading all files in memory
	//--
	postData  := bytes.Buffer{}
	//--
	if(reqArr == nil) {
		return "", nil, ""
	} //end if
	//--
	w := multipart.NewWriter(&postData)
	defer w.Close()
	//--
	var validPostVarsOrFiles int = 0
	//--
	for key, val := range reqArr {
		key = smart.StrTrimWhitespaces(key)
		if(key != "") {
			if(smart.StrRegexMatch(REGEX_SAFE_HTTP_FORM_VAR_NAME, key)) { // form field
				for z:=0; z<len(val); z++ {
					if(int64(len(val[z])) > int64(HTTP_CLI_MAX_POST_VAL_SIZE)) {
						return "ERR: FAILED to Add Post Form Variable: `" + key + "`: `" + smart.ConvertIntToStr(len(val[z])) + "` bytes ; Oversized #" + smart.ConvertIntToStr(z), nil, ""
					} //end if
					v, ev := w.CreateFormField(key)
					if(ev != nil) {
						return "ERR: FAILED to Add Post Form Variable: `" + key + "`: `" + val[z] + "` #" + smart.ConvertIntToStr(z) + ": " + ev.Error(), nil, ""
					} //end if
					v.Write([]byte(val[z]))
					validPostVarsOrFiles++
					if(DEBUG == true) {
						log.Println("[DEBUG] " + smart.CurrentFunctionName() + ": Post Form Variable Add: `" + key + "`: `" + val[z] + "` #", z)
					} //end if
				} //end for
			} else if(smart.StrStartsWith(key, "@")) { // form file, similar with CURL
				fkey := smart.StrTrimWhitespaces(smart.StrTrimLeft(key, "@"))
				if(smart.StrRegexMatch(REGEX_SAFE_HTTP_FORM_VAR_NAME, fkey)) {
					for z:=0; z<len(val); z++ {
						var uploadFilePath string = val[z]
						if(!smart.PathIsSafeValidPath(uploadFilePath)) {
							return "ERR: The POST File Path is Invalid or Unsafe: `" + uploadFilePath + "`", nil, ""
						} //end if
						if(smart.PathIsEmptyOrRoot(uploadFilePath)) {
							return "ERR: The POST File Path is Empty or is Root: `" + uploadFilePath + "`", nil, ""
						} //end if
						if(smart.PathIsAbsolute(uploadFilePath)) {
							return "ERR: The POST File Path is Absolute, must be Relative: `" + uploadFilePath + "`", nil, ""
						} //end if
						if(smart.PathIsBackwardUnsafe(uploadFilePath)) {
							return "ERR: The POST File Path is Backward Unsafe: `" + uploadFilePath + "`", nil, ""
						} //end if
						if(!smart.PathExists(uploadFilePath)) {
							return "ERR: The POST File Path does NOT Exists: `" + uploadFilePath + "`", nil, ""
						} //end if
						if(smart.PathIsDir(uploadFilePath)) {
							return "ERR: The POST File Path is a Directory: `" + uploadFilePath + "`", nil, ""
						} //end if
						if(!smart.PathIsFile(uploadFilePath)) {
							return "ERR: The POST File Path is NOT a File: `" + uploadFilePath + "`", nil, ""
						} //end if
						var fName string = smart.StrTrimWhitespaces(smart.PathBaseName(uploadFilePath))
						if((fName == "") || (!smart.PathIsSafeValidFileName(fName))) {
							return "ERR: FAILED to detect the File Name from the POST File Path: `" + uploadFilePath + "`", nil, ""
						} //end if
						f, ef := w.CreateFormFile(fkey, fName)
						if(ef != nil) {
							return "ERR: FAILED to add the POST File Path: `" + uploadFilePath + "`: " + ef.Error(), nil, ""
						} //end if
						stat, errStat := os.Stat(uploadFilePath)
						if(errStat != nil) {
							return "ERR: FAILED to stat the POST File Path: `" + uploadFilePath + "`: " + errStat.Error(), nil, ""
						} //end if
						if(stat.Size() > int64(HTTP_CLI_MAX_POST_FILE_SIZE)) {
							return "ERR: FAILED to read the POST File Path: `" + uploadFilePath + "`: File is Oversized: " + smart.ConvertInt64ToStr(stat.Size()), nil, ""
						} //end if
						file, errOpen := os.Open(uploadFilePath)
						if(errOpen != nil) {
							return "ERR: FAILED to open for read the POST File Path: `" + uploadFilePath + "`: " + errOpen.Error(), nil, ""
						} //end if
						_, errCopy := io.Copy(f, file)
						file.Close()
						if(errCopy != nil) {
							return "ERR: FAILED to read the POST File Path: `" + uploadFilePath + "`: " + errCopy.Error(), nil, ""
						} //end if
						validPostVarsOrFiles++
						if(DEBUG == true) {
							log.Println("[DEBUG] " + smart.CurrentFunctionName() + ": Post File Add: `" + uploadFilePath + "` @ Size:", stat.Size() ,"bytes #", z)
						} //end if
					} //end for
				} else {
					return "ERR: Invalid File Key in Request Arr Data: `" + key + "` as `" + fkey + "`", nil, ""
				} //end if else
			} else {
				return "ERR: Invalid Key in Request Arr Data: `" + key + "`", nil, ""
			} //end if else
		} else {
			return "ERR: Empty Key in Request Arr Data", nil, ""
		} //end if
		if(int64(len(postData.Bytes())) > int64(HTTP_CLI_MAX_POST_DATA_SIZE)) {
			return "ERR: POST Data is Oversized,Max Limit is: " + smart.ConvertUInt64ToStr(HTTP_CLI_MAX_POST_DATA_SIZE) + " bytes", nil, ""
		} //end if
	} //end for
	//--
	if(validPostVarsOrFiles <= 0) {
		return "ERR: No Valid POST Data found", nil, ""
	} //end if
	//--
	return "", &postData, w.FormDataContentType()
	//--
} //END FUNCTION


// If Auth User/Pass is set will dissalow redirects, by auto-setting maxRedirects=0 !
// Min Read Limit is 10MB (set maxBytesRead=0 as default) ; Max Read Limit is 1GB (because is in memory !)
func httpClientDoRequest(method string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, reqArr map[string][]string, upldLocalFilePath string, downloadLocalDirPath string, timeoutSec uint32, maxBytesRead uint64, maxRedirects uint8, authUsername string, authPassword string) (httpResult HttpClientRequest) {
	//--
	defer smart.PanicHandler()
	//--
	upldLocalFilePath = smart.StrTrimWhitespaces(upldLocalFilePath)
	upldLocalFilePath = smart.SafePathFixSeparator(upldLocalFilePath)
	//--
	downloadLocalDirPath = smart.StrTrimWhitespaces(downloadLocalDirPath)
	downloadLocalDirPath = smart.SafePathFixSeparator(downloadLocalDirPath)
	//--
	var uaSignature string = DEFAULT_CLIENT_UA + " " + "HttpUtils/" + VERSION + " (" + "GoLang/" + smart.CurrentRuntimeVersion() + "; " + smart.CurrentOSName() + "/" + smart.CurrentOSArch() + ")"
	//--
	method = smart.StrToUpper(smart.StrTrimWhitespaces(method))
	//--
	httpResult = HttpClientRequest {
		Errors: "?",
		UserAgent: uaSignature,
		ConnTimeout: timeoutSec,
		MaxDownloadSize: maxBytesRead,
		HttpMethod: method,
		AuthUserName: authUsername,
		Uri: uri,
		RedirectLocation: "",
		MaxRedirects: maxRedirects,
		NumRedirects: 0,
		RedirUris: []string{},
		LastUri: uri,
		UploadLocalFile: upldLocalFilePath,
		UploadFileName: "",
		UploadDataSize: 0,
		HttpStatus: -555,
		HeadData: "",
		HeadDataSize: 0,
		Cookies: map[string]string{},
		AllowMethods: "",
		LastModified: "",
		Expires: "",
		RetryAfter: "",
		MimeType: "",
		MimeCharSet: "",
		MimeDisp: "",
		MimeFileName: "",
		ContentLength: 0,
		BodyData: "",
		BodyDataSize: 0,
		BodyDataEncoding: "plain",
		DownloadLocalDir: downloadLocalDirPath,
		DownloadLocalFileName: "",
	}
	//--
	cliTlsCfg := TlsConfigClient(tlsInsecureSkipVerify, tlsServerPEM)
	//--
	transport := http.Transport{
		TLSClientConfig: &cliTlsCfg,
		TLSHandshakeTimeout: time.Duration(HTTP_CLI_TLS_TIMEOUT) * time.Second, // fix for TLS handshake error ; default is 10 seconds
		DisableKeepAlives: true, // fix ; {{{SYNC-GO-ERR-HTTP-CLI-TOO-MANY-OPEN-FILES}}} : this is a fix for too many open files # this is requires as well as resp.Body.Close() which is handled below
	}
	//--
	uri = smart.StrTrimWhitespaces(uri)
	if((uri == "") || (len(uri) > int(HTTP_MAX_SIZE_SAFE_URL))) {
		httpResult.Uri = ""
		httpResult.Errors = "ERR: URL is Empty or Too Long"
		httpResult.HttpStatus = -100
		return
	} //end if
	httpResult.Uri = uri
	//--
	var isHead bool = false
	var isGet bool = false
	var isPost bool = false
	var isPut bool = false
	var isFilePut bool = false
	var isPatch bool = false
	var isMkCol bool = false
	var isDelete bool = false
	var isCopy bool = false
	var isMove bool = false
	var isPropFind bool = false
	var isOptions bool = false
	//--
	switch(method) {
		case "HEAD":
			isHead = true
			break
		case "GET":
			isGet = true
			break
		case "POST":
			if(reqArr != nil) {
				isPost = true
			} else { // if no POST data, fallback to GET method
				method = "GET"
				isGet = true
			} //end if else
			break
		case "PUT":
			upldLocalFilePath = smart.StrTrimWhitespaces(upldLocalFilePath)
			if(upldLocalFilePath != "") {
				isFilePut = true
				if(!smart.PathIsSafeValidPath(upldLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is Invalid or Unsafe: `" + upldLocalFilePath + "`"
					httpResult.HttpStatus = -701
					return
				} //end if
				if(smart.PathIsEmptyOrRoot(upldLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is Empty or is Root: `" + upldLocalFilePath + "`"
					httpResult.HttpStatus = -702
					return
				} //end if
				if(smart.PathIsAbsolute(upldLocalFilePath)) { // {{{SYNC-HTTPCLI-UPLOAD-PATH-ALLOW-ABSOLUTE}}}
					httpResult.Errors = "ERR: The PUT File Path is Absolute, must be Relative: `" + upldLocalFilePath + "`"
					httpResult.HttpStatus = -703
					return
				} //end if
				if(smart.PathIsBackwardUnsafe(upldLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is Backward Unsafe: `" + upldLocalFilePath + "`"
					httpResult.HttpStatus = -704
					return
				} //end if
				if(!smart.PathExists(upldLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path does NOT Exists: `" + upldLocalFilePath + "`"
					httpResult.HttpStatus = -705
					return
				} //end if
				if(smart.PathIsDir(upldLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is a Directory: `" + upldLocalFilePath + "`"
					httpResult.HttpStatus = -706
					return
				} //end if
				if(!smart.PathIsFile(upldLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is NOT a File: `" + upldLocalFilePath + "`"
					httpResult.HttpStatus = -707
					return
				} //end if
				var fName string = smart.StrTrimWhitespaces(smart.PathBaseName(upldLocalFilePath))
				if((fName == "") || (!smart.PathIsSafeValidFileName(fName))) {
					httpResult.Errors = "ERR: FAILED to detect a valid File Name from the PUT File Path: `" + upldLocalFilePath + "` as `" + fName + "`"
					httpResult.HttpStatus = -708
					return
				} //end if
				putFSize, putFSizeErr := smart.SafePathFileGetSize(upldLocalFilePath, false) // {{{SYNC-HTTPCLI-UPLOAD-PATH-ALLOW-ABSOLUTE}}}
				if(putFSizeErr != nil) {
					httpResult.Errors = "ERR: FAILED to determine a valid File Size from the PUT File Path: `" + upldLocalFilePath + "` # " + putFSizeErr.Error()
					httpResult.HttpStatus = -709
					return
				} //end if
				if(putFSize <= 0) {
					httpResult.Errors = "ERR: The File Size of the PUT File Path: `" + upldLocalFilePath + "` Must be Greater than Zero"
					httpResult.HttpStatus = -710
					return
				} //end if
				uri = smart.StrTrimRight(uri, "/") + "/" + smart.EscapeUrl(fName)
				httpResult.Uri = uri
				httpResult.UploadFileName = fName
				httpResult.UploadDataSize = putFSize
			} else { // put body
				if(reqArr == nil) {
					httpResult.Errors = "ERR: Empty PUT data"
					httpResult.HttpStatus = -711
					return
				} //end if
				if(len(reqArr["@put:data"]) != 1) {
					httpResult.Errors = "ERR: Invalid PUT data structure ... It must contain only one value"
					httpResult.HttpStatus = -712
					return
				} //end if
				var lenPutData int = len(reqArr["@put:data"][0])
				if(lenPutData <= 0) { // DO NOT TRIM ! If non-empty need to be sent as is
					httpResult.Errors = "ERR: The Body Size of the PUT data must be Greater than Zero"
					httpResult.HttpStatus = -713
					return
				} else if(int64(lenPutData) > int64(HTTP_CLI_MAX_POST_DATA_SIZE)) {
					httpResult.Errors = "ERR: The Body Size of the PUT data must be lower than: " + smart.ConvertUInt64ToStr(HTTP_CLI_MAX_POST_DATA_SIZE)
					httpResult.HttpStatus = -714
					return
				} //end if
			} //end if else
			isPut = true
			break
		case "PATCH": // patch: body only, no file implementation ...
			if(reqArr == nil) {
				httpResult.Errors = "ERR: Empty PATCH data"
				httpResult.HttpStatus = -711
				return
			} //end if
			if(len(reqArr["@patch:data"]) != 1) {
				httpResult.Errors = "ERR: Invalid PATCH data structure ... It must contain only one value"
				httpResult.HttpStatus = -712
				return
			} //end if
			var lenPatchData int = len(reqArr["@patch:data"][0])
			if(lenPatchData <= 0) { // DO NOT TRIM ! If non-empty need to be sent as is
				httpResult.Errors = "ERR: The Body Size of the PATCH data must be Greater than Zero"
				httpResult.HttpStatus = -713
				return
			} else if(int64(lenPatchData) > int64(HTTP_CLI_MAX_POST_DATA_SIZE)) {
				httpResult.Errors = "ERR: The Body Size of the PATCH data must be lower than: " + smart.ConvertUInt64ToStr(HTTP_CLI_MAX_POST_DATA_SIZE)
				httpResult.HttpStatus = -714
				return
			} //end if
			isPatch = true
			break
		case "MKCOL":
			isMkCol = true
			break
		case "DELETE":
			isDelete = true
			break
		case "COPY":
			if(reqArr == nil) {
				httpResult.Errors = "ERR: Empty COPY data"
				httpResult.HttpStatus = -601
				return
			} //end if
			if(len(reqArr["@copy:destination"]) != 1) {
				httpResult.Errors = "ERR: Invalid COPY destination structure ... It must contain only one value"
				httpResult.HttpStatus = -602
				return
			} //end if
			reqArr["@copy:destination"][0] = smart.StrTrimWhitespaces(reqArr["@copy:destination"][0])
			var lenCopyData int = len(reqArr["@copy:destination"][0])
			if(lenCopyData <= 0) { // DO NOT TRIM ! If non-empty need to be sent as is
				httpResult.Errors = "ERR: The String Size of the COPY destination must be Greater than Zero"
				httpResult.HttpStatus = -603
				return
			} else if(int64(lenCopyData) > int64(HTTP_MAX_SIZE_SAFE_URL)) {
				httpResult.Errors = "ERR: The String Size of the COPY destination must be lower than: " + smart.ConvertUInt16ToStr(HTTP_MAX_SIZE_SAFE_URL)
				httpResult.HttpStatus = -604
				return
			} //end if
			if(len(reqArr["@copy:overwrite"]) != 1) {
				httpResult.Errors = "ERR: Invalid COPY overwrite structure ... It must contain only one value"
				httpResult.HttpStatus = -605
				return
			} //end if
			reqArr["@copy:overwrite"][0] = smart.StrToUpper(smart.StrTrimWhitespaces(reqArr["@copy:overwrite"][0]))
			if((reqArr["@copy:overwrite"][0] != "T") && (reqArr["@copy:overwrite"][0] != "F")) { // T = true ; F = false
				httpResult.Errors = "ERR: Invalid COPY overwrite value ... It must be `T` as true or `F` as false"
				httpResult.HttpStatus = -606
				return
			} //end if
			isCopy = true
			break
		case "MOVE":
			if(reqArr == nil) {
				httpResult.Errors = "ERR: Empty MOVE data"
				httpResult.HttpStatus = -611
				return
			} //end if
			if(len(reqArr["@move:destination"]) != 1) {
				httpResult.Errors = "ERR: Invalid MOVE destination structure ... It must contain only one value"
				httpResult.HttpStatus = -612
				return
			} //end if
			reqArr["@move:destination"][0] = smart.StrTrimWhitespaces(reqArr["@move:destination"][0])
			var lenMoveData int = len(reqArr["@move:destination"][0])
			if(lenMoveData <= 0) { // DO NOT TRIM ! If non-empty need to be sent as is
				httpResult.Errors = "ERR: The String Size of the MOVE destination must be Greater than Zero"
				httpResult.HttpStatus = -613
				return
			} else if(int64(lenMoveData) > int64(HTTP_MAX_SIZE_SAFE_URL)) {
				httpResult.Errors = "ERR: The String Size of the MOVE destination must be lower than: " + smart.ConvertUInt16ToStr(HTTP_MAX_SIZE_SAFE_URL)
				httpResult.HttpStatus = -614
				return
			} //end if
			if(len(reqArr["@move:overwrite"]) != 1) {
				httpResult.Errors = "ERR: Invalid MOVE overwrite structure ... It must contain only one value"
				httpResult.HttpStatus = -615
				return
			} //end if
			reqArr["@move:overwrite"][0] = smart.StrToUpper(smart.StrTrimWhitespaces(reqArr["@move:overwrite"][0]))
			if((reqArr["@move:overwrite"][0] != "T") && (reqArr["@move:overwrite"][0] != "F")) { // T = true ; F = false
				httpResult.Errors = "ERR: Invalid MOVE overwrite value ... It must be `T` as true or `F` as false"
				httpResult.HttpStatus = -616
				return
			} //end if
			isMove = true
			break
		case "PROPFIND":
			isPropFind = true
			break
		case "OPTIONS":
			isOptions = true
			break
		default:
			httpResult.Errors = "ERR: Invalid Method: `" + method + "`"
			httpResult.HttpStatus = -101
			return
	} //end switch
	//--
	var downloadBodyToFile bool = false
	if((isGet == true) || (isPost == true)) { // allow download to file just for GET / POST
		downloadLocalDirPath = smart.StrTrimWhitespaces(downloadLocalDirPath)
		if(downloadLocalDirPath != "") {
			if(downloadLocalDirPath == "/") { // must check this before Add Dir Last Slash
				httpResult.Errors = "ERR: Using root path as DOWNLOAD File Path is Disallowed: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -801
				return
			} //end if
			downloadLocalDirPath = smart.PathAddDirLastSlash(downloadLocalDirPath)
			if(downloadLocalDirPath == "./") { // security risk: can overwrite the current executable ...
				httpResult.Errors = "ERR: Using current path as DOWNLOAD File Path is Disallowed: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -802
				return
			} //end if
			if(!smart.PathIsSafeValidPath(downloadLocalDirPath)) {
				httpResult.Errors = "ERR: The DOWNLOAD File Path is Invalid or Unsafe: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -803
				return
			} //end if
			if(smart.PathIsEmptyOrRoot(downloadLocalDirPath)) {
				httpResult.Errors = "ERR: The DOWNLOAD File Path is Empty or is Root: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -804
				return
			} //end if
			if(smart.PathIsAbsolute(downloadLocalDirPath)) { // {{{SYNC-HTTPCLI-DOWNLOAD-PATH-DISALLOW-ABSOLUTE}}}
				httpResult.Errors = "ERR: The DOWNLOAD File Path is Absolute, must be Relative: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -805
				return
			} //end if
			if(smart.PathIsBackwardUnsafe(downloadLocalDirPath)) {
				httpResult.Errors = "ERR: The DOWNLOAD File Path is Backward Unsafe: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -806
				return
			} //end if
			if(!smart.PathExists(downloadLocalDirPath)) {
				httpResult.Errors = "ERR: The DOWNLOAD File Path does NOT Exists: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -807
				return
			} //end if
			if(!smart.PathIsDir(downloadLocalDirPath)) {
				httpResult.Errors = "ERR: The DOWNLOAD File Path is not a Directory: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -808
				return
			} //end if
			if(smart.PathIsFile(downloadLocalDirPath)) {
				httpResult.Errors = "ERR: The DOWNLOAD File Path is a File: `" + downloadLocalDirPath + "`"
				httpResult.HttpStatus = -809
				return
			} //end if
			downloadBodyToFile = true
		} //end if
	} else {
		downloadLocalDirPath = ""
	} //end if else
	//--
	if(downloadBodyToFile == true) {
		httpResult.DownloadLocalDir = downloadLocalDirPath
	} else {
		httpResult.DownloadLocalDir = ""
	} //end if else
	//--
	if(timeoutSec == 0) {
		timeoutSec = HTTP_CLI_DEF_TIMEOUT
	} //end if
	if(timeoutSec < HTTP_CLI_MIN_TIMEOUT) {
		timeoutSec = HTTP_CLI_MIN_TIMEOUT
	} else if(timeoutSec > HTTP_CLI_MAX_TIMEOUT) {
		timeoutSec = HTTP_CLI_MAX_TIMEOUT // max is 24 hours (for downloading large files ...)
	} //end if else
	httpResult.ConnTimeout = timeoutSec
	//--
	if(downloadBodyToFile == true) {
		maxBytesRead = 0 // no limit
	} else {
		if(maxBytesRead < HTTP_CLI_DEF_BODY_READ_SIZE) {
			maxBytesRead = HTTP_CLI_DEF_BODY_READ_SIZE // min is 16 MB
		} else if(maxBytesRead > HTTP_CLI_MAX_BODY_READ_SIZE) {
			maxBytesRead = HTTP_CLI_MAX_BODY_READ_SIZE // max 1 GB ; avoid to read in memory more than this !
		} //end if
	} //end if
	if((isHead == true) || (isOptions == true) || (isPropFind == true) || (isMkCol == true) || (isDelete == true) || (isCopy == true) || (isMove == true) || (isPut == true) || (isPatch == true)) {
		if(maxBytesRead > HTTP_CLI_DEF_BODY_READ_SIZE) {
			maxBytesRead = HTTP_CLI_DEF_BODY_READ_SIZE
		} //end if
	} //end if
	httpResult.MaxDownloadSize = maxBytesRead
	//--
	var useAuth uint8 = smart.HTTP_AUTH_MODE_NONE
	if(authUsername != "") {
		if(authUsername == smart.HTTP_AUTH_USER_RAW) {
			useAuth = smart.HTTP_AUTH_MODE_RAW
		} else if(authUsername == smart.HTTP_AUTH_USER_APIKEY) {
			useAuth = smart.HTTP_AUTH_MODE_APIKEY
		} else if(authUsername == smart.HTTP_AUTH_USER_BEARER) {
			useAuth = smart.HTTP_AUTH_MODE_BEARER
		} else if(authUsername == smart.HTTP_AUTH_USER_TOKEN) {
			useAuth = smart.HTTP_AUTH_MODE_TOKEN
		} else { // fallback to Basic Auth ; Cookie Auth does no need to be managed here, it may send the Auth Cookie or 2FA cookie using: ckyArr
			useAuth = smart.HTTP_AUTH_MODE_BASIC
		} //end if else
		httpResult.AuthUserName = authUsername
	} else {
		httpResult.AuthUserName = ""
	} //end if else
	//--
	if(useAuth > smart.HTTP_AUTH_MODE_NONE) { // if use auth (any)
		maxRedirects = 0
	} else { // safe redirects if 301/302 if no auth/credentials ; min: 0 ; max: 10 ; {{{SYNC-SAFE-HTTP-REDIRECT-POLICY}}}
		if(maxRedirects < 0) {
			maxRedirects = 0
		} else if(maxRedirects > HTTP_CLI_MAX_REDIRECTS) {
			maxRedirects = HTTP_CLI_MAX_REDIRECTS
		} //end if else
	} //end if else
	httpResult.MaxRedirects = maxRedirects
	//--
	safeCheckRedirect := func(req *http.Request, numReqs []*http.Request) error { // default behavior in GoLang : HTTP client will follow 10 redirects, and then it will return an error
		var crrRedirNum int = len(numReqs) - 1 // substract the last req. which is always served even if is redirect !
		if(crrRedirNum >= int(maxRedirects)) {
			httpResult.RedirectLocation = req.URL.String()
			return smart.NewError("Redirect Policy Limit: Stop after: " + smart.ConvertUInt8ToStr(maxRedirects) + " times")
		} //end if
		httpResult.LastUri = req.URL.String()
		httpResult.NumRedirects++
		httpResult.RedirUris = append(httpResult.RedirUris, httpResult.LastUri)
		return nil
	} //end function
	//--
	client := http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &transport,
		CheckRedirect: safeCheckRedirect,
	}
	//--
	blackholePBar := bytes.Buffer{}
	pbOptionWriter := pbar.OptionSetWriter(os.Stdout) // default output to stdout
	if(smart.AppGetRunInBackground()) { // if app runs in background, don't want that in logs ... (ex: supervisor mode)
		pbOptionWriter = pbar.OptionSetWriter(&blackholePBar) // in this case output to a bytes buffer that will be discarded after the method ends
	} //end if
	//--
	var errData string = ""
	var multipartType string = ""
	var formDataLen int64 = 0
	var putDataLen int64 = 0
	var patchDataLen int64 = 0
	var req *http.Request
	var errReq error
	var cTypeHdr string = ""
	//--
	if(isPost == true) { // POST must have some data to post
		var formData *bytes.Buffer = nil
		errData, formData, multipartType = reqArrToHttpFormData(reqArr)
		if(errData != "") {
			httpResult.Errors = "ERR: Invalid POST Form Data: " + errData
			httpResult.HttpStatus = -102
			return
		} //end if
		if(formData == nil) {
			httpResult.Errors = "ERR: Empty POST Form Data"
			httpResult.HttpStatus = -103
			return
		} //end if
		formDataLen = int64(len(formData.Bytes()))
		obar := pbar.NewOptions64(
			formDataLen,
			pbOptionWriter,
			pbar.OptionSetBytes64(formDataLen),
			pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
			pbar.OptionSetDescription("[SmartHttpCli:PostData]"),
			pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed") }),
		)
		if(formDataLen > 0) {
			obar.RenderBlank()
		} //end if
		req, errReq = http.NewRequest(method, uri, obar.NewProxyReader(formData))
		blackholePBar = bytes.Buffer{} // free
		log.Println("[INFO]", smart.CurrentFunctionName(), ": Post Data: `" + httpResult.LastUri + "` @ Size:", formDataLen, "bytes (" + smart.PrettyPrintBytes(uint64(formDataLen)) + ")")
	} else if(isPut == true) {
		var ubar *pbar.ProgressBar
		if(isFilePut == true) { // file
			stat, errStat := os.Stat(upldLocalFilePath)
			if(errStat != nil) {
				httpResult.Errors = "ERR: FAILED to stat the PUT File Path: `" + upldLocalFilePath + "`: " + errStat.Error()
				httpResult.HttpStatus = -715
				return
			} //end if
			file, errOpen := os.Open(upldLocalFilePath)
			if(errOpen != nil) {
				httpResult.Errors = "ERR: FAILED to open for read the PUT File Path: `" + upldLocalFilePath + "`: " + errOpen.Error()
				httpResult.HttpStatus = -716
				return
			} //end if
			defer file.Close()
			putDataLen = stat.Size()
			if(DEBUG == true) {
				log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Put File: `" + upldLocalFilePath + "` ; Size:", putDataLen, "bytes")
			} //end if
			ubar = pbar.NewOptions64(
				putDataLen,
				pbOptionWriter,
				pbar.OptionSetBytes64(putDataLen),
				pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
				pbar.OptionSetDescription("[SmartHttpCli:Uploading]"),
				pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed") }),
			)
			if(putDataLen > 0) {
				ubar.RenderBlank()
			} //end if
			req, errReq = http.NewRequest(method, uri, ubar.NewProxyReader(file))
			blackholePBar = bytes.Buffer{} // free
			log.Println("[INFO]", smart.CurrentFunctionName(), ": Upload File [" + httpResult.UploadFileName + "]: `" + httpResult.LastUri + "` @ Size:", putDataLen, "bytes (" + smart.PrettyPrintBytes(uint64(putDataLen)) + ")")
		} else { // body
			if(len(reqArr["@put:ctype"]) == 1) {
				cTypeHdr = reqArr["@put:ctype"][0]
			} //end if
			res := bytes.NewBuffer([]byte(reqArr["@put:data"][0]))
			putDataLen = int64(len(reqArr["@put:data"][0]))
			if(len(reqArr["@put:method"]) == 1) {
				if(reqArr["@put:method"][0] == "POST") {
					method = "POST"
				} //end if
			} //end if
			if(DEBUG == true) {
				log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Body Data " + method + " ; Size:", putDataLen, "bytes")
			} //end if
			ubar = pbar.NewOptions64(
				putDataLen,
				pbOptionWriter,
				pbar.OptionSetBytes64(putDataLen),
				pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
				pbar.OptionSetDescription("[SmartHttpCli:WriteData]"),
				pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed") }),
			)
			if(putDataLen > 0) {
				ubar.RenderBlank()
			} //end if
			req, errReq = http.NewRequest(method, uri, ubar.NewProxyReader(res))
			blackholePBar = bytes.Buffer{} // free
			log.Println("[INFO]", smart.CurrentFunctionName(), ": Upload Data: `" + httpResult.LastUri + "` @ Size:", putDataLen, "bytes (" + smart.PrettyPrintBytes(uint64(putDataLen)) + ")")
		} //end if else
	} else if(isPatch == true) { // body only, no file implementation
		res := bytes.NewBuffer([]byte(reqArr["@patch:data"][0]))
		patchDataLen = int64(len(reqArr["@patch:data"][0]))
		if(DEBUG == true) {
			log.Println("[DEBUG]", smart.CurrentFunctionName(), ": PATCH Data ; Size:", patchDataLen, "bytes")
		} //end if
		ubar := pbar.NewOptions64(
			patchDataLen,
			pbOptionWriter,
			pbar.OptionSetBytes64(patchDataLen),
			pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
			pbar.OptionSetDescription("[SmartHttpCli:WriteData]"),
			pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed") }),
		)
		if(patchDataLen > 0) {
			ubar.RenderBlank()
		} //end if
		req, errReq = http.NewRequest(method, uri, ubar.NewProxyReader(res))
		blackholePBar = bytes.Buffer{} // free
		log.Println("[INFO]", smart.CurrentFunctionName(), ": Upload Data: `" + httpResult.LastUri + "` @ Size:", patchDataLen, "bytes (" + smart.PrettyPrintBytes(uint64(patchDataLen)) + ")")
	} else {
		req, errReq = http.NewRequest(method, uri, nil)
	} //end if else
	//--
	req.Close = true // force to close connection at the end ; {{{SYNC-GO-ERR-HTTP-CLI-TOO-MANY-OPEN-FILES}}} : this is a fix for too many open files # this is requires as well as resp.Body.Close() which is handled below
	//--
	if(errReq != nil) {
		httpResult.Errors = "ERR: Invalid Request: " + errReq.Error()
		httpResult.HttpStatus = -104
		return
	} //end if
	//--
//	req.Header = map[string][]string{} // init, reset
	req.Header = http.Header{} // init, reset
	cTypeHdr = HttpSafeHeaderValue(smart.StrToLower(cTypeHdr))
	if(cTypeHdr != "") {
		req.Header.Set(HTTP_HEADER_CONTENT_TYPE, cTypeHdr)
	} //end if
	//--
	var totalSizeCookies int = 0
	if(ckyArr != nil) {
		for cK, cV := range ckyArr {
			cK = smart.StrTrimWhitespaces(cK)
			if(cK != "") {
				totalSizeCookies += (len(cK) + len(cV))
				if(totalSizeCookies > int(HTTP_MAX_SIZE_SAFE_COOKIE)) {
					httpResult.Errors = "ERR: Cookies are Oversized: " + smart.ConvertIntToStr(totalSizeCookies) + " bytes, but max safe length is: " + smart.ConvertUInt16ToStr(HTTP_MAX_SIZE_SAFE_COOKIE) + " bytes"
					httpResult.HttpStatus = -105
					return
				} //end if
				req.AddCookie(&http.Cookie{
					Name: cK,
					Value: cV,
				})
				if(DEBUG == true) {
					log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Set Cookie: `" + cK + "`: `" + cV + "`")
				} //end if
			} //end if
		} //end for
	} //end if
	//--
	if(isPut == true) {
		req.TransferEncoding = []string{"identity"} // forces to change from the default chunked transfer encoding to linear or gzip (support wider servers)
		req.ContentLength = putDataLen
	} else if(isPatch == true) {
		req.TransferEncoding = []string{"identity"} // forces to change from the default chunked transfer encoding to linear or gzip (support wider servers)
		req.ContentLength = patchDataLen
	} else if(isCopy == true) {
		req.Header.Set(HTTP_HEADER_DAV_DESTINATION, reqArr["@copy:destination"][0])
		req.Header.Set(HTTP_HEADER_DAV_OVERWRITE, reqArr["@copy:overwrite"][0])
	} else if(isMove == true) {
		req.Header.Set(HTTP_HEADER_DAV_DESTINATION, reqArr["@move:destination"][0])
		req.Header.Set(HTTP_HEADER_DAV_OVERWRITE, reqArr["@move:overwrite"][0])
	} //end if
	//--
	if(useAuth == smart.HTTP_AUTH_MODE_BASIC) { // only for Basic Auth ; Example: `authorization: Basic B64(user:pass)` ; header will be created below, as a safe value
		authHead := HttpClientAuthBasicHeader(authUsername, authPassword)
		for k, v := range authHead {
			if(k != "") {
				if(v != nil) {
					for i:=0; i<len(v); i++ {
						req.Header.Add(k, v[i])
						if(DEBUG == true) {
							log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Add Basic Auth Header: `" + k + ": " + v[i] + "`", "#", i)
						} //end if
					} //end for
				} //end if
			} //end if
		} //endfor
	} else if(useAuth == smart.HTTP_AUTH_MODE_TOKEN) { // only for Token Auth ; Example: `authorization: Token *****` ; the expected aHdrVal = `*****`
		if(authPassword != "") {
			var aHdrVal string = HTTP_HEADER_VALUE_AUTH_TYPE_TOKEN + " " + HttpSafeHeaderValue(authPassword)
			req.Header.Add(HTTP_HEADER_AUTH_AUTHORIZATION, aHdrVal)
			if(DEBUG == true) {
				log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Add Token Auth Header: `" + HTTP_HEADER_AUTH_AUTHORIZATION + ": " + aHdrVal + "`")
			} //end if
		} //end if
	} else if(useAuth == smart.HTTP_AUTH_MODE_BEARER) { // only for Bearer Auth ; Example: `authorization: Bearer *****` ; the expected aHdrVal = `*****`
		if(authPassword != "") {
			var aHdrVal string = HTTP_HEADER_VALUE_AUTH_TYPE_BEARER + " " + HttpSafeHeaderValue(authPassword)
			req.Header.Add(HTTP_HEADER_AUTH_AUTHORIZATION, aHdrVal)
			if(DEBUG == true) {
				log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Add Bearer Auth Header: `" + HTTP_HEADER_AUTH_AUTHORIZATION + ": " + aHdrVal + "`")
			} //end if
		} //end if
	} else if(useAuth == smart.HTTP_AUTH_MODE_APIKEY) { // only for ApiKey Auth ; Example: `authorization: ApiKey *****` ; the expected aHdrVal = `*****`
		if(authPassword != "") {
			var aHdrVal string = HTTP_HEADER_VALUE_AUTH_TYPE_APIKEY + " " + HttpSafeHeaderValue(authPassword)
			req.Header.Add(HTTP_HEADER_AUTH_AUTHORIZATION, aHdrVal)
			if(DEBUG == true) {
				log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Add ApiKey Auth Header: `" + HTTP_HEADER_AUTH_AUTHORIZATION + ": " + aHdrVal + "`")
			} //end if
		} //end if
	} else if(useAuth == smart.HTTP_AUTH_MODE_RAW) { // only for Raw Auth ; Example: `authorization: *****` or `authorization: Custom *****` ; the expected aHdrVal = `Custom *****`
		if(authPassword != "") {
			var aHdrVal string = HttpSafeHeaderValue(authPassword)
			req.Header.Add(HTTP_HEADER_AUTH_AUTHORIZATION, aHdrVal)
			if(DEBUG == true) {
				log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Add Raw Auth Header: `" + HTTP_HEADER_AUTH_AUTHORIZATION + ": " + aHdrVal + "`")
			} //end if
		} //end if
	} //end if
	//--
	if(isPost == true) {
		req.Header.Set(HTTP_HEADER_CONTENT_TYPE, multipartType)
		if(DEBUG == true) {
			log.Println("[DEBUG]", smart.CurrentFunctionName(), ": Set POST Data Header : `" + HTTP_HEADER_CONTENT_TYPE + ": " + multipartType + "`")
		} //end if
	} //end if
	//--
	// TODO: allow a custom UA Signature to be set
	req.Header.Set(HTTP_HEADER_USER_AGENT, uaSignature)
	//--
	resp, errResp := client.Do(req)
	if(errResp != nil) {
		httpResult.Errors = "ERR: Invalid Response: " + errResp.Error()
		httpResult.HttpStatus = -106
		return
	} //end if
	defer resp.Body.Close()
	//--
	var statusCode int = resp.StatusCode
	//--
	headData, rdHeadErr := httputil.DumpResponse(resp, false) // if true will include also the body
	if(rdHeadErr != nil) {
		httpResult.Errors = "ERR: Failed to Read Response Header: " + rdHeadErr.Error()
		httpResult.HttpStatus = -107
		return
	} //end if
	//--
	if(resp.ContentLength < 0) {
		resp.ContentLength = 0 // undefined ; avoid use default as -1 because conversion to uint64 for PrettyPrintBytes() ...
	} //end if
	//--
	httpResult.HttpStatus = statusCode
	httpResult.RedirectLocation = smart.StrTrimWhitespaces(resp.Header.Get(HTTP_HEADER_REDIRECT_LOCATION))
	httpResult.ContentLength = resp.ContentLength
	httpResult.LastModified = smart.StrTrimWhitespaces(resp.Header.Get(HTTP_HEADER_CACHE_LMOD))
	httpResult.Expires = smart.StrTrimWhitespaces(resp.Header.Get(HTTP_HEADER_CACHE_EXPS))
	httpResult.RetryAfter = smart.StrTrimWhitespaces(resp.Header.Get(HTTP_HEADER_RETRY_AFTER))
	httpResult.AllowMethods = smart.StrTrimWhitespaces(resp.Header.Get(HTTP_HEADER_ALLOW))
	//--
	for _, cookie := range resp.Cookies() {
		if(smart.StrTrimWhitespaces(cookie.Name) != "") {
			httpResult.Cookies[smart.StrTrimWhitespaces(cookie.Name)] = cookie.Value
		} //end if
	} //end for
	//--
	httpResult.HeadData = string(headData)
	httpResult.HeadDataSize = uint64(len(headData))
	//-- HINT: can detect content type: mimeType := http.DetectContentType(buffer) ; can determine file extension with: fext, _ := mime.ExtensionsByType(mimeType)
	mType, mCharSet := MimeAndCharsetGetFromMimeType(resp.Header.Get(HTTP_HEADER_CONTENT_TYPE))
	var cDisp string = smart.StrTrimWhitespaces(resp.Header.Get(HTTP_HEADER_CONTENT_DISP))
	var mFileName string = ""
	var mDisp string = ""
	if(cDisp != "") {
		dispType, dispParams, dispErr := mime.ParseMediaType(cDisp)
		if(dispErr == nil) {
			mFileName = smart.StrTrimWhitespaces(dispParams["filename"])
			mDisp = smart.StrToLower(smart.StrTrimWhitespaces(dispType))
		} //end if
	} //end if
	httpResult.MimeType = mType
	httpResult.MimeCharSet = mCharSet
	httpResult.MimeDisp = mDisp
	httpResult.MimeFileName = mFileName
	//--
	if(method == "HEAD") { // return everything except the body
		httpResult.Errors = ""
		return
	} //end if
	//--
	if(downloadBodyToFile != true) { // if download in memory use a hardcoded limit
		if(resp.ContentLength > 0) {
			httpResult.BodyDataSize = uint64(resp.ContentLength)
			if(resp.ContentLength > int64(maxBytesRead)) {
				httpResult.Errors = "ERR: Body is Oversized: " + smart.ConvertInt64ToStr(resp.ContentLength) + " bytes / Max Limit Set is: " + smart.ConvertUInt64ToStr(maxBytesRead) + " bytes"
				httpResult.HttpStatus = -108
				return
			} //end if
		} //end if
	} //end if
	//--
	var actionDBar string = ""
	if(downloadBodyToFile == true) {
		actionDBar = "Downloading"
	} else {
		actionDBar = "ReadData"
	} //end if else
	//--
	dbar := pbar.NewOptions64(
		resp.ContentLength,
		pbOptionWriter,
		pbar.OptionSetBytes64(resp.ContentLength),
		pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
		pbar.OptionSetDescription("[SmartHttpCli:" + actionDBar + "]"),
		pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed (" + httpResult.MimeType + ")") }),
	)
	if(resp.ContentLength > 0) {
		dbar.RenderBlank()
	} //end if
	//--
	bodyData := bytes.Buffer{}
	var bytesCopied int64 = 0
	var rdBodyErr error
	//--
	if(downloadBodyToFile == true) { // download body to a file ; bodyData will return the path to this file
		//--
		var dFileName string = ""
		var dFileExt string = ""
		if(dFileExt == "") {
			if(cDisp != "") {
				if(mFileName != "") {
					dFileName = smart.PathBaseNoExtName(mFileName)
					dFileExt  = smart.PathBaseExtension(mFileName)
				} //end if
			} //end if
		} //end if
		if(dFileExt == "") {
			if(mType != "") {
				dFileExts, dExtErr := mime.ExtensionsByType(mType)
				if(dExtErr == nil) {
					if(len(dFileExts) > 0) {
						dFileExt = dFileExts[0]
					} //end if
				} //end if
			} //end if
		} //end if
		if(dFileName == "") {
			dFileName = smart.PathBaseNoExtName(smart.StrTrimWhitespaces(uri))
			if(dFileExt == "") {
				dFileExt = smart.PathBaseExtension(smart.StrTrimWhitespaces(uri))
			} //end if
		} //end if
		//--
		dFileName = smart.StrTrimWhitespaces(dFileName)
		dFileExt = smart.StrTrimWhitespaces(smart.StrToLower(smart.StrTrim(smart.StrTrimWhitespaces(dFileExt), ".")))
		//--
		if(dFileName == "") {
			dFileName = "file"
		} //end if
		if(dFileExt == "") {
			dFileExt = "download"
		} //end if
		//--
		dFileName = dFileName + "." + dFileExt
		if((statusCode < 200) || (statusCode >= 300)) {
			dFileName = "file-err-" + smart.ConvertIntToStr(statusCode) + ".download"
		} //end if
		//-- do minimalistict safety checks, the rest of checks were made above
		dFileName = smart.StrTrimWhitespaces(dFileName)
		if(!smart.PathIsSafeValidFileName(dFileName)) {
			dFileName = "file.download"
		} //end if
		downloadLocalDirPath = smart.StrTrimWhitespaces(downloadLocalDirPath)
		if((downloadLocalDirPath == "") || (!smart.PathIsSafeValidPath(downloadLocalDirPath))) {
			httpResult.Errors = "ERR: Failed to resolve a Download Safe Dir Path: `" + downloadLocalDirPath + "`"
			httpResult.HttpStatus = -810
			return
		} //end if
		if((dFileName == "") || (!smart.PathIsSafeValidFileName(dFileName))) {
			httpResult.Errors = "ERR: Failed to resolve a Download Safe File Name: `" + dFileName + "`"
			httpResult.HttpStatus = -811
			return
		} //end if
		httpResult.DownloadLocalFileName = dFileName
		var dFullPath string = downloadLocalDirPath + dFileName
		if((!smart.PathIsSafeValidPath(dFullPath)) || smart.PathIsBackwardUnsafe(dFullPath)) {
			httpResult.Errors = "ERR: Failed to resolve a Download Safe Path: `" + dFullPath + "`"
			httpResult.HttpStatus = -812
			return
		} //end if
		if(smart.PathIsAbsolute(dFullPath)) { // {{{SYNC-HTTPCLI-DOWNLOAD-PATH-DISALLOW-ABSOLUTE}}}
			httpResult.Errors = "ERR: Unsafe, Cannot use an Absolute Path as a Download Path: `" + dFullPath + "`"
			httpResult.HttpStatus = -813
			return
		} //end if
		//--
		lockFDwn := filelock.LockFile{
			Path: 		dFullPath,  // path that needs to be locked, not the lock file path !
			Timeout: 	timeoutSec, // seconds
		}
		errDwnLock := lockFDwn.Lock()
		if(errDwnLock != nil) {
			httpResult.Errors = "ERR: Failed to get an exclusive Lock for the Download File: `" + dFullPath + "` (file may be already in use by another concurrent process): " + errDwnLock.Error()
			httpResult.HttpStatus = -820
			return
		} //end if
		defer lockFDwn.Unlock()
		//--
		if(smart.PathExists(dFullPath)) {
			if(smart.PathIsFile(dFullPath)) {
				dwDelOk, dwDelErr := smart.SafePathFileDelete(dFullPath, false) // {{{SYNC-HTTPCLI-DOWNLOAD-PATH-DISALLOW-ABSOLUTE}}}
				if(dwDelErr != nil) {
					httpResult.Errors = "ERR: Failed to Remove a residual existing Download File: `" + dFullPath + "`: " + dwDelErr.Error()
					httpResult.HttpStatus = -821
					return
				} //end if
				if(dwDelOk != true) {
					httpResult.Errors = "ERR: Cannot Remove a residual existing Download File: `" + dFullPath + "`"
					httpResult.HttpStatus = -822
					return
				} //end if
				if(smart.PathExists(dFullPath)) {
					httpResult.Errors = "ERR: Could Not Remove a residual existing Download File, it still exists: `" + dFullPath + "`"
					httpResult.HttpStatus = -823
					return
				} //end if
			} else {
				httpResult.Errors = "ERR: Cannot Download File, Path is a Dir: `" + dFullPath + "`"
				httpResult.HttpStatus = -824
				return
			} //end if
		} //end if
		//-- {{{SYNC-HTTPCLI-DOWNLOAD-PATH-DISALLOW-ABSOLUTE}}}
		dFile, dErr := os.OpenFile(dFullPath, os.O_EXCL|os.O_CREATE|os.O_WRONLY|os.O_TRUNC, smart.CHOWN_FILES)
		if(dErr != nil) {
			httpResult.Errors = "ERR: Failed to open the Download File for writing: `" + dFullPath + "`: " + dErr.Error()
			httpResult.HttpStatus = -825
			return
		} //end if
		//--
		log.Println("[INFO]", smart.CurrentFunctionName(), ": [" + method + " / " + smart.ConvertIntToStr(httpResult.HttpStatus) + "] :: Download Data to File [" + dFileName + "] to `" + downloadLocalDirPath + "` from `" + httpResult.LastUri + "` Size:", resp.ContentLength, "bytes (" + smart.PrettyPrintBytes(uint64(resp.ContentLength)) + ")")
		//--
		bytesCopied, rdBodyErr = io.Copy(io.MultiWriter(dFile, dbar), resp.Body)
		//--
		dwFSize, dwFSizErr := smart.SafePathFileGetSize(dFullPath, false) // {{{SYNC-HTTPCLI-DOWNLOAD-PATH-DISALLOW-ABSOLUTE}}}
		if(dwFSizErr != nil) {
			dwFSize = 0
		} //end if
		//--
		httpResult.Errors = ""
		httpResult.BodyDataEncoding = "log"
		httpResult.BodyData = "SmartHttpCli :: Saved to Local Downloads Folder as `" + dFullPath + "`"
		httpResult.BodyDataSize = uint64(dwFSize)
		blackholePBar = bytes.Buffer{} // free
		return
		//--
	} else { // download in memory
		//--
		log.Println("[INFO]", smart.CurrentFunctionName(), ": [" + method + " / " + smart.ConvertIntToStr(httpResult.HttpStatus) + "] :: Read Data in Memory: `" + httpResult.LastUri + "` @ Limit:", maxBytesRead, "bytes ; Size:", resp.ContentLength, "bytes (" + smart.PrettyPrintBytes(uint64(resp.ContentLength)) + ")")
		//--
		limitedReader := io.LimitedReader{R: resp.Body, N: int64(maxBytesRead + 500)} // add extra 500 bytes to read to compare below if body size is higher than limit ; this works also in the case that resp.ContentLength is not reported or is zero ; below will check the size
		bytesCopied, rdBodyErr = io.Copy(io.MultiWriter(&bodyData, dbar), &limitedReader)
		if(rdBodyErr != nil) {
			httpResult.Errors = "ERR: Timed Out (Max seconds: " + smart.ConvertUInt32ToStr(timeoutSec) + ") or Failed to Read Response Body (" + smart.ConvertInt64ToStr(bytesCopied) + " bytes read): " + rdBodyErr.Error()
			httpResult.HttpStatus = -109
			return
		} //end if
		//--
		var sizeRead int64 = int64(len(bodyData.Bytes()))
		if(sizeRead > int64(maxBytesRead)) {
			var displayBodySize int64 = sizeRead
			if(resp.ContentLength > 0) {
				displayBodySize = resp.ContentLength
			} //end if
			httpResult.Errors = "ERR: Body is Oversized: " + smart.ConvertInt64ToStr(displayBodySize) + " bytes / Max Limit Set is: " + smart.ConvertUInt64ToStr(maxBytesRead) + " bytes"
			httpResult.HttpStatus = -110
			return
		} //end if
		//--
	} //end if else
	//--
	var useB64Encoding bool = true
	if(
		(httpResult.MimeType == MIME_TYPE_HTML) || (httpResult.MimeType == MIME_TYPE_CSS) ||
		(httpResult.MimeType == MIME_TYPE_JS) || (httpResult.MimeType == MIME_TYPE_JSON) ||
		(httpResult.MimeType == MIME_TYPE_XML) || (httpResult.MimeType == MIME_TYPE_SVG) ||
		(httpResult.MimeType == MIME_TYPE_TEXT) || (httpResult.MimeType == MIME_TYPE_CSV) ||
		(httpResult.MimeType == MIME_TYPE_EMAIL_MSG) || (httpResult.MimeType == MIME_TYPE_VCARD) ||
		(httpResult.MimeType == MIME_TYPE_ICALENDAR) || (httpResult.MimeType == MIME_TYPE_SIG_GPG) ||
		(smart.StrStartsWith(httpResult.MimeType, "text/"))) { // other text types
			useB64Encoding = false
	} //end if
	//--
	httpResult.Errors = ""
	httpResult.BodyData = string(bodyData.Bytes())
	httpResult.BodyDataSize = uint64(len(httpResult.BodyData))
	if(useB64Encoding == true) {
		httpResult.BodyDataEncoding = "base64"
		httpResult.BodyData = smart.Base64Encode(httpResult.BodyData)
	} //end if else
	blackholePBar = bytes.Buffer{} // free
	return
	//--
} //END FUNCTION


//-----


func TlsConfigServer(forceHttpV1 bool, description string) tls.Config {
	//--
	defer smart.PanicHandler()
	//--
	var nextProtos []string = []string{
		"h2",
		"http/1.1",
	}
	if(forceHttpV1 == true) {
		nextProtos = nextProtos[len(nextProtos)-1:] // keep just the last
	} //end if
	log.Println("[INFO]", smart.CurrentFunctionName() + ": [TLS 1.3]", nextProtos, description)
	//--
	cfg := tls.Config{ // support just TLS 1.3 and 1.2 (backward compatible) ; enable TLS_FALLBACK_SCSV because without there are many downgrade based attacks on TLS if many versions are supported
		MinVersion: 		tls.VersionTLS12,
		MaxVersion: 		tls.VersionTLS13,
		CurvePreferences: 	[]tls.CurveID{ // https://safecurves.cr.yp.to
			tls.CurveP521,
			tls.X25519,
			tls.CurveP384,
		//	tls.CurveP256,
		},
		CipherSuites: []uint16{ // TLS 1.3 ciphersuites are not configurable: https://pkg.go.dev/crypto/tls#Config.CipherSuites
			//-- tls 1.3
			tls.TLS_CHACHA20_POLY1305_SHA256, 	// tls1.3
			tls.TLS_AES_256_GCM_SHA384, 		// tls1.3
			//-- tls 1.2
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 	// tls1.2
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 	// tls1.2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 		// tls1.2 ; macOS, webDAV
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 			// tls1.2 ; macOS, webDAV
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384, 				// tls1.2
			//-- security:
			tls.TLS_FALLBACK_SCSV, // protection against TLS downgrade attacks
			//-- #
		},
		NextProtos: nextProtos,
	}
	//--
	return cfg
	//--
} //END FUNCTION


//-----


func TLSProtoHttpV1Server() map[string]func(*http.Server, *tls.Conn, http.Handler) {
	//--
	defer smart.PanicHandler()
	//--
	return make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0) // disable HTTP/2 on TLS (on non-TLS is always HTTP/1.1)
	//--
} //END FUNCTION


//-----


func HttpMuxServer(srvAddr string, timeoutSec uint32, forceHttpV1 bool, allowLargeHeader bool, description string) (*http.ServeMux, http.Server) {
	//--
	defer smart.PanicHandler()
	//--
	memRateLimitMutex.Lock()
	if(memRateLimitCache == nil) { // start cache just on 1st auth ... otherwise all scripts using this library will run the cache in background, but is needed only by this method !
		memRateLimitCache = smartcache.NewCache("smart.httputils.rateLimit.inMemCache", time.Duration(ICACHEM_CLEANUP_INTERVAL) * time.Second, DEBUG_CACHE)
	} //end if
	memRateLimitMutex.Unlock()
	//--
	if(DEBUG_CACHE == true) {
		log.Println("[DATA] " + smart.CurrentFunctionName() + " :: memRateLimitCache:", memRateLimitCache)
	} //end if
	//--
	mux := http.NewServeMux()
	//--
	tlsCfgSrv := TlsConfigServer(forceHttpV1, description)
	//--
	var maxBytesHeader int = http.DefaultMaxHeaderBytes // 1MB ; as default in Go ; this should be used for internal networking purposes only, not for public web
	if(allowLargeHeader == false) {
		maxBytesHeader = 16384 // limit at 16k (double than standard for web) ; ex: apache / haproxy 8k ; nginx 4k ; iis 16k ; tomcat 48k
	} //end if
	//--
	srv := http.Server{
		Addr: 							srvAddr,
		Handler: 						mux,
		TLSConfig: 						&tlsCfgSrv,
		ReadTimeout: 					time.Duration(timeoutSec) * time.Second,
		ReadHeaderTimeout: 				0, // if set to zero, the value of ReadTimeout is used
		IdleTimeout: 					time.Duration(HTTP_SRV_IDLE_TIMEOUT) * time.Second, // standard
		WriteTimeout: 					time.Duration(timeoutSec) * time.Second,
		MaxHeaderBytes: 				maxBytesHeader,
	}
	//--
	var httpVerStr string = "[HTTP/2 HTTP/1.1]"
	if(forceHttpV1 == true) {
		srv.TLSNextProto = TLSProtoHttpV1Server() // disable HTTP/2 on TLS (on non-TLS is always HTTP/1.1)
		httpVerStr = "[HTTP/1.1]"
	} //end if
	log.Println("[INFO]", smart.CurrentFunctionName() + ":", httpVerStr, description)
	//--
	return mux, srv
	//--
} //END FUNCTION


//-----


func HttpServerIsIpRateLimited(r *http.Request, theLimit int, theBurst int) bool {
	//--
	defer smart.PanicHandler()
	//--
	// ex: set theLimit=1, theBurst=3 to allow one request at 3 seconds for a single IP
	// if the rate limit will overflow, returns TRUE ; if not rate limited returns FALSE
	// theLimit: rate limit (average number of requests per second)
	// theBurst: number of tokens that can be consumed in a single rate limit (consecutive requests up to limit / concurrency)
	// the rate limiter cache clear interval is 5 seconds thus it must be taken in consideration
	//--
	if(theLimit < 1) {
		theLimit = 1
	} //end if
	if(theBurst < 1) {
		theBurst = 1
	} //end if
	//--
	isOkClientRealIp, realClientIp, rawHdrRealIpVal, rawHdrRealIpKey := smart.GetHttpRealClientIpFromRequestHeaders(r) // this is using r.Header.Get() with value from
	if(DEBUG == true) {
		log.Println("[DEBUG] " + smart.CurrentFunctionName() + ":: realClientIp: `" + realClientIp + "` ; rawHdrRealIpVal: `" + rawHdrRealIpVal + "` ; rawHdrRealIpKey: `" + rawHdrRealIpKey + "`")
	} //end if
	//--
	if((isOkClientRealIp != true) || (realClientIp == "")) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), ":: Failed to Get the Visitor IP Address", isOkClientRealIp, realClientIp, rawHdrRealIpVal, rawHdrRealIpKey)
		return true // warn
	} //end if
	//--
	var rLimit rate.Limit = rate.Limit(float64(theLimit))
	//--
	limiter := memRateLimitGetVisitor(realClientIp, rLimit, theBurst)
	if(limiter.Allow() == false) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), ":: Rate Limit restriction for IP:", realClientIp)
		return true // limited ...
	} //end if
	//--
	return false // ok
	//--
} //END FUNCTION


func memRateLimitGetVisitor(ip string, theLimit rate.Limit, theBurst int) *rate.Limiter {
	//--
	defer smart.PanicHandler() // may panic at the cache get assertion
	//--
	now := time.Now()
	limiter := rate.NewLimiter(theLimit, theBurst)
	//--
	exists, obj, _ := memRateLimitCache.Get(ip)
	if(!exists) {
		//--
		xV := visitor {
			limiter: limiter,
			lastSeen: now, // include the current time when creating a new visitor
		}
		obj.Id = ip
		obj.Data = smart.CurrentFunctionName() + " [rate limiter]"
		obj.Obj = xV
		memRateLimitCache.Set(obj, int64(theBurst))
		//--
		return limiter
		//--
	} //end if
	var v visitor = obj.Obj.(visitor) // try to assert
	if(v.limiter == nil) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Failed to Get Cache Object for IP", ip)
		v = visitor {
			limiter: limiter,
			lastSeen: now, // include the current time when creating a new visitor
		}
	} //end if
	v.lastSeen = now
	//--
	return v.limiter
	//--
} //END FUNCTION


//-----


func HttpSafeHeaderValue(str string) string {
	//--
	str = smart.StrTrimWhitespaces(smart.StrNormalizeSpaces(str))
	//--
	return str
	//--
} //END FUNCTION


func HttpSafeHeaderKey(str string) string {
	//--
	str = smart.StrToLower(HttpSafeHeaderValue(str))
	str = smart.StrTrimWhitespaces(smart.StrReplaceAll(str, " ", ""))
	if(str == "") {
		str = HTTP_HEADER_INVALID_EMPTY_KEY // dissalow empty header key, it is unsafe !
	} //end if
	//--
	return str
	//--
} //END FUNCTION


//-----


func HttpHeadersCacheControl(w http.ResponseWriter, r *http.Request, expiration int, modified string, control string) (isCachedContent bool) {
	//--
	defer smart.PanicHandler()
	//--
	modified = smart.StrTrimWhitespaces(modified)
	//--
	now := time.Now().UTC()
	//--
	w.Header().Set(HTTP_HEADER_SERVER_POWERED, HttpSafeHeaderValue(smart.DESCRIPTION + " :: " + smart.VERSION))
	w.Header().Set(HTTP_HEADER_SERVER_SIGN,    HttpSafeHeaderValue(DEFAULT_REALM + " / " + VERSION))
	w.Header().Set(HTTP_HEADER_SERVER_DATE,    now.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) + " " + smart.TIME_ZONE_UTC)
	//--
	if((expiration >= 0) && (modified != "")) {
		//--
		if(expiration < 60) {
			expiration = 60
		} //end if
		expdate := now.Add(time.Duration(expiration) * time.Second)
		//--
		if((control == CACHE_CONTROL_PUBLIC) || (control == CACHE_CONTROL_PRIVATE)) {
			control = control + ", "
		} else {
			control = "" // must be empty for CACHE_CONTROL_DEFAULT
		} //end if
		//--
		dtObjUtc := smart.DateTimeStructUtc(modified)
		if(dtObjUtc.Status == "OK") {
			modified = dtObjUtc.Years + "-" + dtObjUtc.Months + "-" + dtObjUtc.Days + " " + dtObjUtc.Hours + ":" + dtObjUtc.Minutes + ":" + dtObjUtc.Seconds // YYYY-MM-DD HH:II:SS
		} else {
			log.Println("[ERROR] " + smart.CurrentFunctionName() + ": Invalid Modified Date:", modified)
			modified = now.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) // YYYY-MM-DD HH:II:SS
		} //end if
		if(DEBUG == true) {
			log.Println("[DEBUG] " + smart.CurrentFunctionName() + ": Modified Date:", modified)
		} //end if
		//--
		w.Header().Set(HTTP_HEADER_CACHE_EXPS, expdate.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) + " " + smart.TIME_ZONE_UTC) // HTTP 1.0
		w.Header().Set(HTTP_HEADER_CACHE_PGMA, "cache") // HTTP 1.0 cache
		w.Header().Set(HTTP_HEADER_CACHE_LMOD, modified + " " + smart.TIME_ZONE_UTC)
		w.Header().Set(HTTP_HEADER_CACHE_CTRL, control + "max-age=" + smart.ConvertIntToStr(expiration) + ", must-revalidate") // HTTP 1.1 HTTP 1.1 (private will dissalow proxies to cache the content)
		//--
		return true
		//--
	} //end if else
	//-- {{{SYNC-HTTP-NOCACHE-HEADERS}}} ; // default expects ; expiration=-1 ; modified="" ; control=""
	expdate := now.AddDate(-1, 0, 0) // minus one year
	//--
	control = CACHE_CONTROL_NOCACHE
	//--
	w.Header().Set(HTTP_HEADER_CACHE_CTRL, control + ", max-age=0, must-revalidate") // HTTP 1.1 no-cache, not use their stale copy
	w.Header().Set(HTTP_HEADER_CACHE_PGMA, control) // HTTP 1.0 no-cache
	w.Header().Set(HTTP_HEADER_CACHE_EXPS, expdate.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) + " " + smart.TIME_ZONE_UTC) // HTTP 1.0 no-cache expires
	w.Header().Set(HTTP_HEADER_CACHE_LMOD, now.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) + " " + smart.TIME_ZONE_UTC)
	//--
	return false // no cache
	//--
} //END FUNCTION


//-----

type HttpStreamerFunc func() (ioReadStream io.Reader)

// valid code: 200 ; 201 ; 202 ; 203 ; 208
// contentFnameOrPath: stream.ext (will get extension .ext and serve mime type by this extension) ; default, fallback to .stream
// contentDisposition: DISP_TYPE_INLINE | DISP_TYPE_ATTACHMENT
// headers: see httpOKXWriteAllowedHeaders()
func HttpStreamContent(w http.ResponseWriter, r *http.Request, code uint16, streamBytesFunc HttpStreamerFunc, contentFnameOrPath string, contentDisposition string, headers map[string]string) {
	//--
	// {{{SYNC-HTTP-UTILS-SERVE-CONTENT-OR-STREAM-2xx}}}
	//--
	// considerations: streamed content must not be cached ; size of stream content is mostly unknown, skip content length ... ; must have no custom cache control !
	// skip manage 3xx codes with an error 500
	// 4xx / 5xx codes should exit immediately
	// only 2xx codes are ok here, except: 204 (no content)
	//--
	defer smart.PanicHandler()
	//--
	_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
	route := smart.GetHttpPathFromRequest(r)
	//--
	if(streamBytesFunc == nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName() + ": Serving Stream: `" + route + "` Failed: Content Streaming Handler is Null ; StatusCode:", 500, "ClientIP:", realClientIp)
		HttpStatus500(w, r, "Content Streaming Handler is Null", true)
		return
	} //end if
	//--
	switch(code) { // {{{SMARTGO-HTTP-UTILS-STATUS-2xx-CODES}}}
		case 200:
			break
		case 201:
			break
		case 202:
			break
		case 203:
			break
		// code 204 (no content) is not accepted for streams ...
		case 208:
			break
		default:
			log.Println("[ERROR] " + smart.CurrentFunctionName() + ": Invalid Status Code:", code, "; Fallback to 200 ; Route:", route, "; ClientIP:", realClientIp)
			code = 200
	} //end switch
	//--
	contentFnameOrPath = smart.PathBaseName(smart.StrToLower(smart.StrTrimWhitespaces(contentFnameOrPath))) // just file name ; ex: `file.ext`
	if(contentFnameOrPath == "") {
		contentFnameOrPath = "file.stream"
	} //end if
	//--
	mimeType, mimeUseCharset, mimeDisposition := MimeDispositionEval(contentFnameOrPath)
	//--
	contentDisposition = MimeDispositionConformParam(contentDisposition)
	if(contentDisposition == "") { // {{{SYNC-MIME-DISPOSITION-AUTO}}}
		contentDisposition = mimeDisposition
	} else if(contentDisposition != DISP_TYPE_INLINE) {
		contentDisposition = DISP_TYPE_ATTACHMENT
	} //end if
	if(contentDisposition == DISP_TYPE_ATTACHMENT) {
		contentDisposition += `; filename="` + smart.EscapeUrl(contentFnameOrPath) + `"`
	} //end if
	//--
	var contentType string = mimeType
	if(mimeUseCharset == true) {
		contentType += "; charset=" + smart.CHARSET
	} //end if
	//--
	w.Header().Set(HTTP_HEADER_CONTENT_TYPE, contentType)
	w.Header().Set(HTTP_HEADER_CONTENT_DISP, contentDisposition)
	// skip content length header, stream size is unknown
	//--
	httpOKXWriteAllowedHeaders(w, headers, smart.CurrentFunctionName())
	//--
	w.WriteHeader(int(code))
	//--
	log.Println("[NOTICE]", smart.CurrentFunctionName() + ": Serving Stream: `" + route + "` ; ContentType: `" + contentType + "` ; ContentDisposition: `" + contentDisposition + "` ; StatusCode:", code, "; ClientIP:", realClientIp)
	_, errStream := io.Copy(w, streamBytesFunc()) // transfer stream to response
	if(errStream != nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName() + ": Failed to Serve Stream: `" + route + "` ; ClientIP: " + realClientIp + " ; Error:", errStream)
		fmt.Fprintf(w, "%s", errStream) // write error also on stream ...
	} //end if
	return
	//--
} //END FUNCTION


//-----


func httpOKXWriteAllowedHeaders(w http.ResponseWriter, headers map[string]string, callerMethodName string) {
	//--
	callerMethodName = smart.StrTrimWhitespaces(callerMethodName)
	if(callerMethodName == "") {
		callerMethodName = smart.CurrentFunctionName()
	} //end if
	//--
	if(headers == nil) {
		return
	} //end if
	if(len(headers) <= 0) {
		return
	} //end if
	//--
	for key, val := range headers {
		key = HttpSafeHeaderKey(key) 	// this will also trim
		val = HttpSafeHeaderValue(val) 	// this will also trim
		switch(key) {
			//-- these headers are managed above, don't allow rewrite
			case HTTP_HEADER_CONTENT_TYPE:
				break
			case HTTP_HEADER_CONTENT_DISP:
				break
			case HTTP_HEADER_CONTENT_LEN:
				break
			//-- these headers are managed by HttpHeadersCacheControl(), don't allow rewrite
			case HTTP_HEADER_CACHE_CTRL:
				break
			case HTTP_HEADER_CACHE_PGMA:
				break
			case HTTP_HEADER_CACHE_EXPS:
				break
			case HTTP_HEADER_CACHE_LMOD:
				break
			//-- special etag headers, managed above, don't allow rewrite
			case HTTP_HEADER_ETAG_SUM:
				break
			case HTTP_HEADER_ETAG_IFNM:
				break
			//-- special server headers, don't allow rewrite
			case HTTP_HEADER_SERVER_DATE:
				break
			case HTTP_HEADER_SERVER_SIGN:
				break
			case HTTP_HEADER_SERVER_POWERED:
				break
			//-- the rest of headers, custom
			default:
				if((key != "") && (key != HTTP_HEADER_INVALID_EMPTY_KEY)) { // ok
					w.Header().Set(key, val)
					if(DEBUG == true) {
						log.Println("[DEBUG]", callerMethodName + ": Set Header Key / Value: `" + key + ": " + val + "`")
					} //end if
				} else if(key == "") { // if the key is empty, skip
					log.Println("[WARNING]", callerMethodName + ": Skip Empty Key / Value: `[EMPTY]: " + val + "`")
				} else { // if the key is HTTP_HEADER_INVALID_EMPTY_KEY, skip
					log.Println("[WARNING]", callerMethodName + ": Skip Invalid Key / Value: `" + key + ": " + val + "`")
				} //end if
		} //end switch
	} //end for
	//--
} //END FUNCTION


//-----


// valid code: 200 ; 201 ; 202 ; 203 ; 204 ; 208
// contentFnameOrPath: file.html (will get extension .html and serve mime type by this extension) ; default, fallback to .txt
// contentDisposition: DISP_TYPE_INLINE | DISP_TYPE_ATTACHMENT
// for no cache: cacheExpiration = -1 ; cacheLastModified = "" ; cacheControl = "no-cache"
// for using cache: cacheExpiration = 3600 (1h) ; cacheLastModified = "2021-03-16 23:57:58" ; cacheControl = "default" | "public" | "private"
// headers: see httpOKXWriteAllowedHeaders()
func httpStatusOKX(w http.ResponseWriter, r *http.Request, code uint16, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	// {{{SYNC-HTTP-UTILS-SERVE-CONTENT-OR-STREAM-2xx}}}
	//--
	defer smart.PanicHandler()
	//--
	var skipContent bool = false
	switch(code) { // {{{SMARTGO-HTTP-UTILS-STATUS-2xx-CODES}}}
		case 200:
			break
		case 201:
			break
		case 202:
			break
		case 203:
			break
		case 204:
			skipContent = true
			break
		case 208:
			break
		default:
			log.Println("[ERROR] " + smart.CurrentFunctionName() + ": Invalid Status Code:", code, "; Fallback to 200")
			code = 200
	} //end switch
	//--
	var mimeType string = ""
	var mimeUseCharset bool = false
	if(skipContent == true) {
		//--
		content = ""
		contentFnameOrPath = ""
		contentDisposition = ""
		cacheExpiration = -1
		cacheLastModified = ""
		cacheControl = CACHE_CONTROL_NOCACHE
		headers = nil
		//--
	} else {
		//--
		contentFnameOrPath = smart.PathBaseName(smart.StrToLower(smart.StrTrimWhitespaces(contentFnameOrPath))) // just file name ; ex: `file.txt` | `file.html` | ...
		if(contentFnameOrPath == "") {
			contentFnameOrPath = "file.txt"
		} //end if
		//--
		var mimeDisposition string = ""
		mimeType, mimeUseCharset, mimeDisposition = MimeDispositionEval(contentFnameOrPath)
		//--
		contentDisposition = MimeDispositionConformParam(contentDisposition)
		if(contentDisposition == "") { // {{{SYNC-MIME-DISPOSITION-AUTO}}}
			contentDisposition = mimeDisposition
		} else if(contentDisposition != DISP_TYPE_INLINE) {
			contentDisposition = DISP_TYPE_ATTACHMENT
		} //end if
		if(contentDisposition == DISP_TYPE_ATTACHMENT) {
			contentDisposition += `; filename="` + smart.EscapeUrl(contentFnameOrPath) + `"`
		} //end if
		//--
	} //end if
	//--
	var contentType string = mimeType
	if(mimeUseCharset == true) {
		contentType += "; charset=" + smart.CHARSET
	} //end if
	//--
	isCachedContent := HttpHeadersCacheControl(w, r, cacheExpiration, cacheLastModified, cacheControl)
	if(isCachedContent == true) {
		var eTag string = ""
		if(int64(len(content)) <= MAX_SIZE_ETAG) { // {{{SYNC-SIZE-MAX-ETAG}}} ; manage eTag only for content size <= 1MB
			eTag = smart.Md5(content) // do not enclose here in double quotes, needs pure value for below check, 304 (if match)
		} //end if
		if(eTag != "") {
			w.Header().Set(HTTP_HEADER_ETAG_SUM, `"`+eTag+`"`) // trick: use a Weak ETag as (W/"") or by enclosing ETag in double quotes to allow GZip compression ...
			var match string = smart.StrTrimWhitespaces(HttpRequestGetHeaderStr(r, HTTP_HEADER_ETAG_IFNM))
			if(DEBUG == true) {
				log.Println("[DEBUG] " + smart.CurrentFunctionName() + ": If None Match (Header):", match)
			} //end if
			if(match != "") {
				if(match == eTag) {
					w.WriteHeader(304) // Not Modified: HTTP_STATUS_304
					return
				} //end if
			} //end if
		} //end if
	} //end if
	//--
	if(skipContent == true) {
		w.Header().Set(HTTP_HEADER_CONTENT_LEN,  smart.ConvertIntToStr(0)) // mandatory, for skip content to be zero
	} else {
		w.Header().Set(HTTP_HEADER_CONTENT_TYPE, contentType)
		w.Header().Set(HTTP_HEADER_CONTENT_DISP, contentDisposition)
		w.Header().Set(HTTP_HEADER_CONTENT_LEN,  smart.ConvertIntToStr(len(content)))
	} //end if
	//--
	httpOKXWriteAllowedHeaders(w, headers, smart.CurrentFunctionName())
	//--
	w.WriteHeader(int(code)) // status code must be after set headers
	//--
	if((skipContent == true) || (r.Method == "HEAD")) { // {{{SYNC-HTTP-HEAD-DO-NOT-SEND-BODY}}} ; for 2xx codes if the method is HEAD don't send body ; also don't send for 204
		return
	} //end if
	//--
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
func HttpStatus201(w http.ResponseWriter, r *http.Request, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	httpStatusOKX(w, r, 201, content, contentFnameOrPath, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
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
func HttpStatus204(w http.ResponseWriter, r *http.Request, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	httpStatusOKX(w, r, 204, content, contentFnameOrPath, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
	//--
} //END FUNCTION

// @params description: see httpStatusOKX()
func HttpStatus208(w http.ResponseWriter, r *http.Request, content string, contentFnameOrPath string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	httpStatusOKX(w, r, 208, content, contentFnameOrPath, contentDisposition, cacheExpiration, cacheLastModified, cacheControl, headers)
	//--
} //END FUNCTION


//-----


// valid code: 301 ; 302
func httpStatus3XX(w http.ResponseWriter, r *http.Request, code uint16, redirectUrl string, outputHtml bool) {
	//--
	defer smart.PanicHandler()
	//--
	var title string = ""
	switch(code) {
		case 301:
			title = HTTP_STATUS_301
			break
		case 302:
			title = HTTP_STATUS_302
			break
		default:
			log.Println("[ERROR] " + smart.CurrentFunctionName() + ": Invalid Status Code:", code, "FallBack to HTTP Status 301")
			title = HTTP_STATUS_301
			code = 301
	} //end switch
	//--
	var contentType = ""
	if(outputHtml == true) {
		contentType = assets.HTML_CONTENT_HEADER
	} else {
		contentType = assets.TEXT_CONTENT_HEADER
	} //end if
	//--
	redirectUrl = HttpSafeHeaderValue(redirectUrl) // this will also trim
	if(redirectUrl == "") {
		log.Println("[ERROR]: " + smart.CurrentFunctionName() + ": Empty Redirect URL:", code, "FallBack to HTTP Status 500")
		HttpStatus500(w, r, "Invalid Redirect URL for Status: " + title, outputHtml)
		return
	} //end if
	//--
	var content string = ""
	if(outputHtml == true) { // html
		content = assets.HtmlStatusPage(title, smart.EscapeHtml(redirectUrl), false, "")
	} else { // text
		content += title
		if(redirectUrl != "") {
			content += "\n\n" + redirectUrl
		} //end if
		content += "\n"
	} //end if else
	//--
	time.Sleep(250 * time.Millisecond) // fix for TLS bad handshake, is redirecting too quick
	//--
	HttpHeadersCacheControl(w, r, -1, "", CACHE_CONTROL_NOCACHE)
	//--
	w.Header().Set(HTTP_HEADER_REDIRECT_LOCATION, redirectUrl)
	w.Header().Set(HTTP_HEADER_CONTENT_TYPE, contentType)
	w.Header().Set(HTTP_HEADER_CONTENT_DISP, DISP_TYPE_INLINE)
	w.Header().Set(HTTP_HEADER_CONTENT_LEN, smart.ConvertIntToStr(len(content)))
	w.WriteHeader(int(code)) // status code must be after set headers
	w.Write([]byte(content))
	//--
} //END FUNCTION


func HttpStatus301(w http.ResponseWriter, r *http.Request, redirectUrl string, outputHtml bool) {
	//--
	httpStatus3XX(w, r, 301, redirectUrl, outputHtml)
	//--
} //END FUNCTION


func HttpStatus302(w http.ResponseWriter, r *http.Request, redirectUrl string, outputHtml bool) {
	//--
	httpStatus3XX(w, r, 302, redirectUrl, outputHtml)
	//--
} //END FUNCTION


//-----


// valid code: 400 ; 401 ; 402 ; 403 ; 404 ; 405 ; 406 ; 408 ; 409 ; 410 ; 415 ; 422 ; 423 ; 424 ; 429 ; 500 ; 501 ; 502 ; 503 ; 504 ; 507
func httpStatusERR(w http.ResponseWriter, r *http.Request, code uint16, messageText string, outputHtml bool, isMessageTextHtmlPage bool, displayCaptcha bool) {
	//--
	defer smart.PanicHandler()
	//--
	var title string = ""
	var displayAuthLogo bool = false
	switch(code) {
		case 400:
			title = HTTP_STATUS_400
			displayCaptcha = false
			break
		case 401:
			title = HTTP_STATUS_401
			displayAuthLogo = true
			displayCaptcha = false
			break
		case 402:
			title = HTTP_STATUS_402
			displayAuthLogo = true
			displayCaptcha = false
			break
		case 403:
			title = HTTP_STATUS_403
			displayAuthLogo = true
			displayCaptcha = false
			break
		case 404:
			title = HTTP_STATUS_404
			displayCaptcha = false
			break
		case 405:
			title = HTTP_STATUS_405
			displayCaptcha = false
			break
		case 406:
			title = HTTP_STATUS_406
			displayCaptcha = false
			break
		case 408:
			title = HTTP_STATUS_408
			displayCaptcha = false
			break
		case 409:
			title = HTTP_STATUS_409
			displayCaptcha = false
			break
		case 410:
			title = HTTP_STATUS_410
			displayCaptcha = false
			break
		case 415:
			title = HTTP_STATUS_415
			displayCaptcha = false
			break
		case 422:
			title = HTTP_STATUS_422
			displayCaptcha = false
			break
		case 423:
			title = HTTP_STATUS_423
			displayCaptcha = false
			break
		case 424:
			title = HTTP_STATUS_424
			displayCaptcha = false
			break
		case 429: // allow: displayCaptcha
			title = HTTP_STATUS_429
			if(displayCaptcha == true) {
				displayAuthLogo = true
			} //end if
			break
		case 500:
			title = HTTP_STATUS_500
			displayCaptcha = false
			break
		case 501:
			title = HTTP_STATUS_501
			displayCaptcha = false
			break
		case 502:
			title = HTTP_STATUS_502
			displayCaptcha = false
			break
		case 503:
			title = HTTP_STATUS_503
			displayCaptcha = false
			break
		case 504:
			title = HTTP_STATUS_504
			displayCaptcha = false
			break
		case 507:
			title = HTTP_STATUS_507
			displayCaptcha = false
			break
		default:
			log.Println("[ERROR] " + smart.CurrentFunctionName() + ": Invalid Status Code:", code, "FallBack to HTTP Status 500")
			title = HTTP_STATUS_500
			code = 500
			displayCaptcha = false
	} //end switch
	//--
	// display captcha or auth logo are optional, and should not care below if instead serving 429 html+captcha will serve a json because client ask for in the accepted header ...
	//--
	var outputTEXT bool = false
	var outputJSON bool = false
	var outputXML bool = false
	if((outputHtml == true) && (isMessageTextHtmlPage != true)) { // {{{SYNC-HTTP-UTILS-OUTPUT-STATUS-TEXT-FLEXIBLE}}}
		//-- do the below detections only in the following conditions: if default output is HTML and is not MessageTextHtmlPage ; otherwise if is text do not do at all, it can be: text, json, xml, etc ..., to simplify things
		arrAccepts := ParseClientMimeAcceptHeader(HttpRequestGetHeaderStr(r, HTTP_HEADER_ACCEPT_MIMETYPE)) // {{{SYNC-SMARTGO-HTTP-ACCEPT-HEADER}}} ; accept headers can be many, just get the prefered one
		if((arrAccepts != nil) && (len(arrAccepts) > 0)) {
			if(!smart.InListArr(MIME_TYPE_HTML, arrAccepts)) { // only if does not accept html, try other mimes: json, xml, text
				if(smart.InListArr(MIME_TYPE_JSON, arrAccepts)) { // check for JSON 1st, have priority
					outputJSON = true
				} else if(smart.InListArr(MIME_TYPE_XML, arrAccepts)) { // 2nd check for xml, have 2nd priority
					outputXML = true
				} else if(smart.InListArr(MIME_TYPE_TEXT, arrAccepts)) { // 3rd check for text, have lower priority
					outputTEXT = true // must be set as explicit text only of was html and client request explicit header text
					outputHtml = false
				} //end if else
			} //end if
		} //end if
	} //end if
	//--
	var contentType = ""
	if(outputJSON == true) {
		contentType = assets.JSON_CONTENT_HEADER
	} else if(outputXML == true) {
		contentType = assets.XML_CONTENT_HEADER
	} else if(outputHtml == true) {
		contentType = assets.HTML_CONTENT_HEADER
	} else {
		contentType = assets.TEXT_CONTENT_HEADER
	} //end if else
	//--
	messageText = smart.StrTrimWhitespaces(messageText)
	var content string = ""
	if(outputJSON == true) { // json
		var jsonMsg map[string]string = map[string]string{
			"status": smart.ConvertUInt16ToStr(code),
			"title": title,
			"message": messageText,
		}
		content = smart.JsonNoErrChkEncode(jsonMsg, true, false)
		content += "\n"
	} else if(outputXML == true) { // xml
		type response struct {
			Status  string   `xml:"status"`
			Title   string   `xml:"title"`
			Message string   `xml:"message"`
		}
		xmlMsg := response{}
		xmlMsg.Status = smart.ConvertUInt16ToStr(code)
		xmlMsg.Title = title
		xmlMsg.Message = messageText
		content = smart.XmlNoErrChkEncode(xmlMsg, true, true)
		content += "\n"
	} else if(outputHtml == true) { // html
		if(isMessageTextHtmlPage == true) {
			content = messageText
		} else {
			var extraHtml string = ""
			if(displayCaptcha == true) {
				var ckName string = "Status" + smart.ConvertUInt16ToStr(code) // ex: `Status429` {{{SYNC-HTTP-UTILS-STATUS-COOKIE-NAME}}}
				var cliUidHash string = GetClientIdentUidHash(r, DEFAULT_REALM)
				captcha, errCaptcha := smartcaptcha.GetCaptchaHtmlAndCode("ascii", ckName, cliUidHash)
				if(errCaptcha == nil) {
					extraHtml = captcha.Html
				} else {
					log.Println("[ERROR]", smart.CurrentFunctionName(), "Captcha ERR:", errCaptcha)
				} //end if else
			} //end if
			content = assets.HtmlStatusPage(title, messageText, displayAuthLogo, extraHtml)
		} //end if else
	} else { // text ; can be also: json / xml as text in non-html mode
		if(outputTEXT == true) { // only if explicit by header and is not explicit text
			content = title + "\n" + messageText
		} else { // {{{SYNC-HTTP-UTILS-OUTPUT-STATUS-TEXT-FLEXIBLE}}} ; explicit text goes here
			if(messageText != "") {
				content = messageText
			} else {
				content = title // use title only if the messageText is empty ; otherwise may be json or xml, don't use ...
			} //end if
		} //end if else
		content += "\n"
	} //end if else
	//--
	HttpHeadersCacheControl(w, r, -1, "", CACHE_CONTROL_NOCACHE)
	//--
	w.Header().Set(HTTP_HEADER_CONTENT_TYPE, contentType)
	w.Header().Set(HTTP_HEADER_CONTENT_DISP, DISP_TYPE_INLINE)
	w.Header().Set(HTTP_HEADER_CONTENT_LEN, smart.ConvertIntToStr(len(content)))
	w.WriteHeader(int(code)) // status code must be after set headers
	w.Write([]byte(content))
	//--
} //END FUNCTION


//-----


func getClientIdentSignature(r *http.Request) string {
	//--
	signature := smart.GetHttpUserAgentFromRequest(r)
	//--
	isOk, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
	//--
	var cliType string = "Client"
	if(isOk != true) {
		cliType = "Fake-Client"
	} //end if
	//--
	return cliType + " // " + realClientIp + " :: " + signature // fix: do not use Proxy client IP here ... if using DNS load balancing + multiple load balancers with multiple backends switching the load balancer (aka reverse proxy) when browsing and changing between web pages will change this signature which will change the client_ident_private_key() and then may lead to user session expired ...
	//--
} //END FUNCTION


func GetClientIdentAppSafeSignature(r *http.Request) string { // used as base for generating derived client unique signature
	//--
	ns, _ := smart.AppGetNamespace()
	sk, _ := smart.AppGetSecurityKey()
	//--
	return getClientIdentSignature(r) + " [#] " + ns + "*" + smart.Base64ToBase64s(smart.Sh3a512B64(sk)) + "." // use a hash of security key to avoid expose by mistake !
	//--
} //END FUNCTION


func GetClientIdentUidHash(r *http.Request, suffix string) string { // used for captcha and other specific purposes
	//--
	pk := GetClientIdentAppSafeSignature(r)
	//--
	suffix = smart.StrTrimWhitespaces(suffix)
	if(suffix != "") {
		pk += smart.FORM_FEED + suffix
	} //end if
	//--
	return smart.Base64ToBase64s(smart.Sh3a512B64(pk))
	//--
} //END FUNCTION


//-----


func HttpHeaderAuthBasic(w http.ResponseWriter, authRealm string) {
	//--
	defer smart.PanicHandler()
	//--
	authRealm = HttpSafeHeaderValue(authRealm)
	//--
	w.Header().Set(HTTP_HEADER_AUTH_AUTHENTICATE, HTTP_HEADER_VALUE_AUTH_TYPE_BASIC + ` realm="` + smart.StrReplaceAll(authRealm, `"`, `'`) + `"`) // the safety of characters in authRealm should normally checked before calling this method ...
	//--
} //END FUNCTION


//-----


func HttpStatus400(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 400, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus401(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool, isMessageTextHtmlPage bool) {
	//--
	httpStatusERR(w, r, 401, messageText, outputHtml, isMessageTextHtmlPage, false)
	//--
} //END FUNCTION

func HttpStatus402(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 402, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus403(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 403, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus404(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 404, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus405(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 405, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus406(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 406, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus408(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 408, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus409(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 409, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus410(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 410, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus415(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 415, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus422(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 422, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus423(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 423, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus424(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 424, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus429(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool, displayCaptcha bool) {
	//--
	httpStatusERR(w, r, 429, messageText, outputHtml, false, displayCaptcha)
	//--
} //END FUNCTION


func HttpStatus500(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 500, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus501(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 501, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus502(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 502, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus503(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 503, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus504(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 504, messageText, outputHtml, false, false)
	//--
} //END FUNCTION

func HttpStatus507(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 507, messageText, outputHtml, false, false)
	//--
} //END FUNCTION


//-----


type CookieSameSiteType uint8
const(
	CookieSameSiteDefault CookieSameSiteType = iota
	CookieSameSiteEmpty
	CookieSameSiteNone
	CookieSameSiteLax
	CookieSameSiteStrict
)

type CookieData struct {
	Name     string
	Value    string
	Expires  int64
	Path     string
	Domain   string
	SameSite CookieSameSiteType
	Secure   bool
	HttpOnly bool
}

const CookieDefaultPath   string = "/"
const CookieDefaultDomain string = "@"


// UnsetCookie: just set a cookie with an empty value and/or expires -1


func HttpRequestSetCookies(w http.ResponseWriter, r *http.Request, arrSetCookies []CookieData) uint8 {
	//--
	if(arrSetCookies == nil) {
		return 0
	} //end if
	if(len(arrSetCookies) <= 0) {
		return 0
	} //end if
	//--
	var success uint8 = 0
	for i:=0; i<len(arrSetCookies); i++ {
		cky := arrSetCookies[i]
		err := HttpRequestSetCookie(w, r, cky.Name, cky.Value, cky.Expires, cky.Path, cky.Domain, cky.SameSite, cky.Secure, cky.HttpOnly)
		if(err == nil) {
			success++
		} //end if
		if(i >= 255) { // max 255 cookies : hardcoded value
			break
		} //end if
	} //end if
	//--
	return success
	//--
} //END FUNCTION


func HttpRequestSetCookieWithDefaults(w http.ResponseWriter, r *http.Request, name string, value string, expires int64) error {
	//--
	defer smart.PanicHandler()
	//--
	return HttpRequestSetCookie(w, r, name, value, expires, CookieDefaultPath, CookieDefaultDomain, CookieSameSiteDefault, false, false)
	//--
} //END FUNCTION


func HttpRequestSetCookie(w http.ResponseWriter, r *http.Request, name string, value string, expires int64, path string, domain string, samesite CookieSameSiteType, secure bool, httpOnly bool) error {
	//--
	defer smart.PanicHandler()
	//--
	name = smart.StrTrimWhitespaces(name)
	if(name == "") {
		return smart.NewError("Name is Empty")
	} //end if
	if(smart.ValidateCookieName(name) != true) {
		return smart.NewError("Name is Invalid")
	} //end if
	//--
	if(smart.StrTrimWhitespaces(value) == "") { // do not trim value
		expires = -1 // as in PHP, force unset
	} //end if
	//--
	ck := http.Cookie{
		Name: name,
		Value: value,
	}
	//-- if expires is zero, do not set, it is session
	if(expires > 0) {
		ck.Expires = time.Now().Add(time.Second * time.Duration(expires)) // now + seconds
	} else if(expires < 0) {
		ck.Expires = time.Now().Add(time.Second * time.Duration(-1 * ((3600 * 24) - expires))) // minus one day - seconds
	} //end if
	//--
	path = smart.StrTrimWhitespaces(path)
	if(path != "") {
		ck.Path = path
	} //end if
	//--
	domain = smart.StrTrimWhitespaces(domain) // if is empty means only current domain (excludding current sub-domains)
	if(domain == "@") {
		domain = smart.GetCookieDefaultDomain() // can return "" or "*" or "dom.ext" ; if "*" must detect and use current base domain as this means current base domain plus all it's sub-domains ...
	} //end if
	if(domain == "*") { // the DEFAULT Cookie Domain (retrieved below) can return also "*", so DO NOT use this conditional in ELSE !!
		var dom string = ""
		var err error = nil
		dom, _, err = smart.GetHttpDomainAndPortFromRequest(r)
		if(err != nil) {
			domain = "" // reset
		} else {
			dom, err = smart.GetBaseDomainFromDomain(dom)
			if(err != nil) {
				domain = "" // reset
			} else {
				domain = smart.StrTrimWhitespaces(dom)
			} //end if
		} //end if
	} //end if
	if(domain != "") {
		if(!smart.IsNetValidHostName(domain)) { // if IPv4 or IPv6 don't set cookie domain !
			domain = "" // reset
		} //end if
	} //end if
	if(domain != "") {
		ck.Domain = domain
	} //end if
	//--
	switch(samesite) {
		case CookieSameSiteEmpty:
			// skip
			break
		case CookieSameSiteNone:
			ck.SameSite = http.SameSiteNoneMode
			break
		case CookieSameSiteLax:
			ck.SameSite = http.SameSiteLaxMode
			break
		case CookieSameSiteStrict:
			ck.SameSite = http.SameSiteStrictMode
			break
		case CookieSameSiteDefault: fallthrough
		default: // use default cookie policy
			policy := smart.GetCookieDefaultSameSitePolicy()
			switch(policy) {
				case "None":
					ck.SameSite = http.SameSiteNoneMode
					if(smart.GetHttpProtocolFromRequest(r) == smart.HTTP_PROTO_PREFIX_HTTPS) { // fix: try to not set COOKIE SECURE except if over HTTPS ; some new browsers, ex: Chromium will not accept None policy cookies over plain HTTP but only over HTTPS ; but if on HTTP and not HTTPS with Chromium a None policy cookie is useless even with COOKIE SECURE set ON if already on HTTP plain ...
						secure = true; // {{{SYNC-COOKIE-POLICY-NONE}}} ; new browsers (ex: Chromium) require this if SameSite cookie policy is set explicit to None ; but anyway, if not already on a secure protocol try to not set this, will still work in Firefox
					} //end if
					break
				case "Lax":
					ck.SameSite = http.SameSiteLaxMode
					break
				case "Strict":
					ck.SameSite = http.SameSiteStrictMode
					break
				case "Empty": fallthrough
				default:
					// skip
			} //end switch
	} //end switch
	//--
	if(secure == true) {
		ck.Secure = true
	} //end if
	//--
	if(httpOnly == true) {
		ck.HttpOnly = true
	} //end if
	//--
	http.SetCookie(w, &ck)
	//--
	return nil
	//--
} //END FUNCTION


func HttpRequestGetCookies(r *http.Request) map[string]string {
	//--
	defer smart.PanicHandler()
	//--
	var cookies map[string]string = map[string]string{}
	//--
	reqCookies := r.Cookies()
	if((reqCookies != nil) && (len(reqCookies) > 0)) {
		for _, reqCookie := range reqCookies {
			if(smart.StrTrimWhitespaces(reqCookie.Name) != "") { // do not trim, must match exactly
				cookies[reqCookie.Name] = smart.RawUrlDecode(reqCookie.Value) // cookie values are raw, needs URL decode ; do not trim ; include empty cookies ; register all cookies and pass back ; by example when using Basic Auth + 2FA (custom mode only, because it needs a custom UI) cookies may be needed
			} //end if
		} //end for
	} //end if
	//--
	return cookies
	//--
} //END FUNCTION


func HttpRequestGetCookie(r *http.Request, name string) string {
	//--
	defer smart.PanicHandler()
	//--
	name = smart.StrTrimWhitespaces(name)
	if((name == "") || (!smart.ValidateCookieName(name))) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Empty or Invalid Cookie Name: `" + name + "`")
		return ""
	} //end if
	//--
	cookie, err := r.Cookie(name)
	if(err != nil) {
		return "" // avoid panic
	} //end if
	//--
	return smart.RawUrlDecode(cookie.Value) // cookie values are raw, needs URL decode ; do not trim
	//--
} //END FUNCTION


//-----


func IsAjaxRequest(r *http.Request) bool {
	//--
	hdrReqWith := smart.StrToLower(smart.StrTrimWhitespaces(HttpRequestGetHeaderStr(r, HTTP_HEADER_CONTENT_X_REQUESTED_WITH)))
	//--
	if(hdrReqWith == "") {
		return false
	} //end if
	//--
	if(hdrReqWith != HTTP_AJAX_REQUEST_SIGNATURE) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func ParseClientMimeAcceptHeader(str string) []string {
	//--
	// ex: `application/json, text/javascript, */*; q=0.01`
	// returns: [`application/json`, `text/javascript`, `*/*`]
	//--
	var arr []string = []string{}
	//--
	str = smart.StrTrimWhitespaces(str)
	if(str == "") {
		return arr
	} //end if
	//--
	str = smart.StrToLower(str)
	//--
	if(smart.StrContains(str, ",")) {
		//--
		exp := smart.Explode(",", str)
		for i:=0; i<len(exp); i++ {
			exp[i] = smart.StrTrimWhitespaces(exp[i])
			if(exp[i] != "") {
				if(smart.StrContains(exp[i], ";")) {
					exr := smart.ExplodeWithLimit(";", exp[i], 2)
					exr[0] = smart.StrTrimWhitespaces(exr[0])
					if(exr[0] != "") {
						arr = append(arr, exr[0])
					} //end if
				} else {
					arr = append(arr, exp[i])
				} //end if
			} //end if
		} //end for
		//--
	} else {
		//--
		arr = append(arr, str)
		//--
	} //end if
	//--
	return arr
	//--
} //END FUNCTION


//-----


func HttpRequestGetHeaderStr(r *http.Request, hdrKey string) string {
	//--
	defer smart.PanicHandler()
	//--
	if((r.Header == nil) || (len(r.Header) <= 0)) {
		return ""
	} //end if
	//--
	hdrKey = smart.StrTrimWhitespaces(hdrKey)
	if(hdrKey == "") {
		return ""
	} //end if
	//--
	return r.Header.Get(hdrKey) // return header values as list, separed by comma if there are multiple headers
	//--
} //END FUNCTION


func HttpRequestGetHeaderArr(r *http.Request, hdrKey string) []string {
	//--
	defer smart.PanicHandler()
	//--
	if((r.Header == nil) || (len(r.Header) <= 0)) {
		return []string{}
	} //end if
	//--
	hdrKey = smart.StrTrimWhitespaces(hdrKey)
	if(hdrKey == "") {
		return []string{}
	} //end if
	//--
	hdrVals := HttpRequestGetHeaders(r)
	if((hdrVals == nil) || (len(hdrVals) <= 0)) {
		return []string{}
	} //end if
	//--
	val, ok := hdrVals[hdrKey]
	if((!ok) || (val == nil)) {
		return []string{}
	} //end if
	//--
	return val
	//--
} //END FUNCTION


func HttpRequestGetHeaders(r *http.Request) map[string][]string {
	//--
	defer smart.PanicHandler()
	//--
	var headers map[string][]string = map[string][]string{}
	//--
	if((r.Header != nil) && (len(r.Header) > 0)) {
		for key, values := range r.Header {
			headers[key] = values
		} //end for
	} //end if
	//--
	return headers
	//--
} //END FUNCTION


//-----


// can be used for a HTTP Client to do Basic Authentication against a server that supports it
func HttpClientAuthBasicHeader(authUsername string, authPassword string) http.Header {
	//--
	defer smart.PanicHandler()
	//--
	return http.Header{HTTP_HEADER_AUTH_AUTHORIZATION: {HTTP_HEADER_VALUE_AUTH_TYPE_BASIC + " " + smart.Base64Encode(authUsername + ":" + authPassword)}}
	//--
} //END FUNCTION


//------


func IsValidHttpAuthRealm(authRealm string) bool {
	//--
	if((smart.StrTrimWhitespaces(authRealm) == "") || (len(smart.StrTrimWhitespaces(authRealm)) < 7) || (len(authRealm) > 50) || (!smart.StrRegexMatch(`^[ _a-zA-Z0-9\-\.@\/\:]+$`, authRealm))) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----

// modes: 1 = Basic Auth ; 28 = Token ; 29 = Bearer ; 129 = Cookie ; 229 = ApiKey
type HttpAuthCheckFunc func(string, uint8, string, map[string]string, string, string, string, *http.Request) (bool, smart.AuthDataStruct, []CookieData) // (authRealm, authMode, realClientIp, arrCookies, user, pass, token) : true if OK / false if NOT, authData, arrSetCookies

// if returns a non empty string there is an error ; if error it already outputs the 401 headers and content so there is nothing more to do ...
// it handles 401 or 403 access by IP list
func HttpAuthCheck(w http.ResponseWriter, r *http.Request, authRealm string, authUsername string, authPassword string, authToken string, allowedIPs string, customAuthCheck HttpAuthCheckFunc, outputHtml bool) (error, smart.AuthDataStruct) { // check if HTTP(S) Basic Auth is OK ; return: errMsg, authData
	//--
	defer smart.PanicHandler()
	//--
	aData := smart.AuthDataStruct{}
	var err string = ""
	//--
	const errTxtProvider string = "Either must supply a fixed username/password and/or username/token, either an auth method."
	//--
	allowedIPs = smart.StrTrimWhitespaces(allowedIPs)
	if(allowedIPs != "") {
		errValidateAllowedIpList := smart.ValidateIPAddrList(allowedIPs)
		if(errValidateAllowedIpList != nil) {
			err = "IP Restrictions List is Invalid: " + errValidateAllowedIpList.Error()
			HttpStatus500(w, r, err, outputHtml)
			return smart.NewError(err), aData
		} //end if
	} //end if
	//--
	if(customAuthCheck == nil) {
		if((smart.AuthBasicIsEnabled() != true) && (smart.AuthTokenIsEnabled() != true)) {
			err = "All Supported Authentication Modes (Basic, Token) are Disabled"
			HttpStatus500(w, r, err, outputHtml)
			return smart.NewError(err), aData
		} //end if
	} else {
		if(smart.AuthAnyIsEnabled() != true) { // will check if any auth is available: basic, bearer, token, cookie, apikey
			err = "All Supported Authentication Modes (Basic, Token, Bearer, Cookie, ApiKey) are Disabled"
			HttpStatus500(w, r, err, outputHtml)
			return smart.NewError(err), aData
		} //end if
	} //end if else
	//--
	if( // use a fixed user/pass with the default authCheck (HTTP Basic Only)
		(smart.StrTrimWhitespaces(authUsername) == "") &&
		(smart.StrTrimWhitespaces(authPassword) == "") &&
		(smart.StrTrimWhitespaces(authToken) == "") &&
		(customAuthCheck == nil)) {
			err = "ERROR: Invalid Auth Provider. " + errTxtProvider
			HttpStatus500(w, r, err, outputHtml)
			return smart.NewError(err), aData
	} //end if
	if( // use a custom auth check, in this case user/pass must be empty !
		(customAuthCheck != nil) &&
		((smart.StrTrimWhitespaces(authUsername) != "") || (smart.StrTrimWhitespaces(authPassword) != "") || (smart.StrTrimWhitespaces(authToken) != ""))) {
			err = "ERROR: Auth Provider Mismatch. " + errTxtProvider
			HttpStatus500(w, r, err, outputHtml)
			return smart.NewError(err), aData
	} //end if
	//--
	authRealm = smart.StrTrimWhitespaces(smart.StrReplaceAll(authRealm, `"`, `'`))
	authUsername = smart.StrTrimWhitespaces(authUsername)
	// do not trim password !
	//--
	if(IsValidHttpAuthRealm(authRealm) != true) {
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": HTTP(S) Server :: AUTH.FIX :: Invalid Realm `" + authRealm + "` ; The Realm was set to default: `" + DEFAULT_REALM + "`")
		authRealm = DEFAULT_REALM
	} //end if
	//--
	var rAddr string = r.RemoteAddr
	ip, port := smart.GetHttpRemoteAddrIpAndPortFromRequest(r) // this is using r.RemoteAddr
	if(ip == "") {
		err = "ERROR: Empty or Invalid Client Remote Address: `" + rAddr + "`"
		HttpStatus500(w, r, err, outputHtml)
		return smart.NewError(err), aData
	} //end if
	//--
	isOkClientRealIp, realClientIp, rawHdrRealIpVal, rawHdrRealIpKey := smart.GetHttpRealClientIpFromRequestHeaders(r) // this is using r.Header.Get() with value from
	if(DEBUG == true) {
		log.Println("[DEBUG] " + smart.CurrentFunctionName() + ": realClientIp: `" + realClientIp + "` ; rawHdrRealIpVal: `" + rawHdrRealIpVal + "` ; rawHdrRealIpKey: `" + rawHdrRealIpKey + "`")
	} //end if
	//--
	if(allowedIPs != "") {
		if((ip == "") || (!smart.StrContains(allowedIPs, "<"+ip+">"))) { // {{{SYNC-VALIDATE-IP-IN-A-LIST}}}
			err = "The access to this service is disabled. The IP: `" + ip + "` is not allowed by current IP Address list ..."
		} //end if
		if(isOkClientRealIp == true) {
			if((realClientIp == "") || (!smart.StrContains(allowedIPs, "<"+realClientIp+">"))) { // {{{SYNC-VALIDATE-IP-IN-A-LIST}}}
				err = "The access to this service is disabled. The Client IP: `" + realClientIp + "` is not allowed by current IP Address list ..."
			} //end if
		} //end if
		if(err != "") {
			log.Println("[WARNING]", smart.CurrentFunctionName(), ": HTTP(S) Server :: AUTH.IP.DENY [" + authRealm + "] :: Client: `<" + ip + ">` / `<" + realClientIp + ">` is matching the IP Addr Allowed List: `" + allowedIPs + "`")
			HttpStatus403(w, r, err, outputHtml)
			return smart.NewError(err), aData
		} //end if
		log.Println("[OK]", smart.CurrentFunctionName(), ": HTTP(S) Server :: AUTH.IP.ALLOW [" + authRealm + "] :: Client: `<" + ip + ">` / `<" + realClientIp + ">` is matching the IP Addr Allowed List: `" + allowedIPs + "`")
	} //end if
	//--
	var cacheKeyCliIpAddr string = ip
	var isAuthMemKeyUsingProxyRealClientIp bool = false
	if(isOkClientRealIp == true) {
		if((smart.StrTrimWhitespaces(realClientIp) != "") && (realClientIp != smart.DEFAULT_FAKE_IP_CLIENT)) {
			cacheKeyCliIpAddr = realClientIp // if behind a proxy and detected ok, use this
			isAuthMemKeyUsingProxyRealClientIp = true
		} //end if
	} //end if
	if(DEBUG == true) {
		log.Println("[DEBUG] " + smart.CurrentFunctionName() + ": :: Auth MemCache Key: `" + cacheKeyCliIpAddr + "` ; Using Real Client IP:", isAuthMemKeyUsingProxyRealClientIp)
	} //end if
	//--
	memAuthMutex.Lock()
	if(memAuthCache == nil) { // start cache just on 1st auth ... otherwise all scripts using this library will run the cache in background, but is needed only by this method !
		memAuthCache = smartcache.NewCache("smart.httputils.auth.inMemCache", time.Duration(ICACHEM_CLEANUP_INTERVAL) * time.Second, DEBUG_CACHE)
	} //end if
	memAuthMutex.Unlock()
	//--
	if(DEBUG_CACHE == true) {
		log.Println("[DATA] " + smart.CurrentFunctionName() + ": [" + authRealm + "] :: memAuthCache:", memAuthCache)
	} //end if
	//--
	cacheExists, cachedObj, cacheExpTime := memAuthCache.Get(cacheKeyCliIpAddr)
	if(cacheExists == true) {
		if((cachedObj.Id == cacheKeyCliIpAddr) && (len(cachedObj.Data) >= (int(ICACHEM_FAILS_NUM)+1))) { // allow max 10 invalid attempts then lock for 5 mins ... for this cacheKeyCliIpAddr
			var skip429 bool = false
			var ckName string = "Status429" // {{{SYNC-HTTP-UTILS-STATUS-COOKIE-NAME}}}
			var ckVal string = smart.StrTrimWhitespaces(HttpRequestGetCookie(r, ckName))
			if(ckVal != "") {
				var cliUidHash string = GetClientIdentUidHash(r, DEFAULT_REALM)
				isCaptchaValid, captchaValidateErr := smartcaptcha.ValidateCaptcha(ckVal, ckName, cliUidHash)
				if(captchaValidateErr == nil) {
					if(isCaptchaValid == true) {
						skip429 = true
						memAuthCache.Unset(cacheKeyCliIpAddr) // unset from cache, on captcha solved
						cachedObj.Data = "." // reset also this
						HttpRequestSetCookieWithDefaults(w, r, ckName, "", -1) // unset captcha cookie
					} //end if
				} //end if
			} //end if
			if(skip429 != true) {
				err = "Invalid Login Timeout for Client: `" + cacheKeyCliIpAddr + "` # Lock Timeout: " + smart.ConvertUInt32ToStr(ICACHEM_EXPIRATION) + " seconds / Try again after: " + time.Unix(cacheExpTime, 0).UTC().Format(smart.DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
				w.Header().Set(HTTP_HEADER_RETRY_AFTER, time.Unix(cacheExpTime, 0).UTC().Format(smart.DATE_TIME_FMT_ISO_STD_GO_EPOCH) + " UTC")
				HttpStatus429(w, r, err, outputHtml, true) // display captcha
				return smart.NewError(err), aData
			} //end if
		} //end if
	} //end if
	//--
	var authCookieIsSet bool = false
	var authCookieName string = ""
	var authCookieVal string = ""
	if(smart.AuthCookieIsEnabled() == true) {
		authCookieName = smart.AuthCookieNameGet()
	} //end if
	var cookies map[string]string = HttpRequestGetCookies(r)
	if((cookies != nil) && (len(cookies) > 0)) {
		if((smart.AuthCookieIsEnabled() == true) && (smart.StrTrimWhitespaces(authCookieName) != "")) {
			valCkAuth, foundValCkAuth := cookies[authCookieName]
			if(foundValCkAuth == true) {
				if(valCkAuth != "") {
					authCookieVal = valCkAuth
					authCookieIsSet = true
				} //end if
			} //end if
		} //end if
	} //end if
	//-- cookies
	var httpAuthMode uint8 = smart.HTTP_AUTH_MODE_NONE
	var authHeader string = ""
	var token string = ""
	var user string = ""
	var pass string = ""
	var ok bool = false
	if((smart.AuthBasicIsEnabled() == true) || (smart.AuthTokenIsEnabled() == true) || (smart.AuthBearerIsEnabled() == true) || (smart.AuthApikeyIsEnabled() == true)) {
		authHeader = smart.StrTrimWhitespaces(HttpRequestGetHeaderStr(r, HTTP_HEADER_AUTH_AUTHORIZATION)) // prefer authorization first
	} //end if
	//-- order to check: Cookie, Bearer, Token, Basic
	if(
		(authCookieIsSet == true) && // Cookie Auth: mandatory check first the cookie
		(smart.AuthCookieIsEnabled() == true) && (smart.AuthCookieNameGet() != "") && (smart.StrTrimWhitespaces(authCookieName) != "") &&
		(cookies != nil) && (len(cookies) > 0)) { // if no authorization header (prefered) fallback to cookie ; pass back all cookies, not just the auth one ; by example when using 2FA cookies may be needed
			if(smart.StrTrimWhitespaces(authCookieVal) != "") {
				httpAuthMode = smart.HTTP_AUTH_MODE_COOKIE
				ok = true
			} //end if
	} else if(smart.StrTrimWhitespaces(authHeader) != "") { // if not cookie, check in this order: basic, token, bearer, apikey
		if((smart.AuthBasicIsEnabled() == true) && (smart.StrIStartsWith(authHeader, HTTP_HEADER_VALUE_AUTH_TYPE_BASIC + " "))) { // Basic Auth ; must be checked last if enabled, as a fallback ; reason: if enabled the Auth Basic Prompt (Header) will be enabled
			httpAuthMode = smart.HTTP_AUTH_MODE_BASIC
			user, pass, ok = r.BasicAuth() // do not trim password
			user = smart.StrTrimWhitespaces(user)
			if((user == "") || (smart.StrTrimWhitespaces(pass) == "")) {
				ok = false
			} //end if
			// DO NOT MANUALLY SET ok TO TRUE, must be preserved as is above comming from r.BasicAuth()
		} else if((smart.AuthTokenIsEnabled() == true) && (smart.StrIStartsWith(authHeader, HTTP_HEADER_VALUE_AUTH_TYPE_TOKEN + " "))) { // Token Auth
			httpAuthMode = smart.HTTP_AUTH_MODE_TOKEN
			token = smart.StrTrimWhitespaces(smart.StrSubstr(authHeader, 6, 0))
			if(token != "") {
				ok = true
			} //end if
		} else if((smart.AuthBearerIsEnabled() == true) && (smart.StrIStartsWith(authHeader, HTTP_HEADER_VALUE_AUTH_TYPE_BEARER + " "))) { // Bearer Auth
			httpAuthMode = smart.HTTP_AUTH_MODE_BEARER
			token = smart.StrTrimWhitespaces(smart.StrSubstr(authHeader, 7, 0))
			if(token != "") {
				ok = true
			} //end if
		} else if((smart.AuthApikeyIsEnabled() == true) && (smart.StrIStartsWith(authHeader, HTTP_HEADER_VALUE_AUTH_TYPE_APIKEY + " "))) { // ApiKey Auth
			httpAuthMode = smart.HTTP_AUTH_MODE_APIKEY
			token = smart.StrTrimWhitespaces(smart.StrSubstr(authHeader, 7, 0))
			if(token != "") {
				ok = true
			} //end if
		} //end if else
	} //end if
	//--
	var aUser string = user // for logging purposes
	//--
	if(!ok) {
		err = "Authentication is Required"
	} else {
		if(customAuthCheck != nil) { // custom auth provider check ; should manage also 2FA if enabled ; can implement any of these modes: HTTP_AUTH_MODE_BASIC, HTTP_AUTH_MODE_TOKEN, HTTP_AUTH_MODE_BEARER, HTTP_AUTH_MODE_COOKIE, HTTP_AUTH_MODE_APIKEY
			var authCustomOk bool = false
			var arrStCookies []CookieData = nil
			authCustomOk, aData, arrStCookies = customAuthCheck(authRealm, httpAuthMode, realClientIp, cookies, user, pass, token, r)
			numCookies := HttpRequestSetCookies(w, r, arrStCookies)
			if(numCookies > 0) {
				log.Println("[NOTICE] " + smart.CurrentFunctionName() + "CustomAuth Cookie Registration: #", numCookies)
			} //end if
			if(authCustomOk != true) {
				aData.OK = false // make sure !
				err = "Auth.Custom [AuthCheck:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] :: [Auth:" + smart.AuthMethodGetNameById(httpAuthMode) + "] :: Failed: no match or invalid"
			} //end if
			if(aData.UserName != "") {
				aUser = aData.UserName
			} //end if
		} else if(httpAuthMode == smart.HTTP_AUTH_MODE_TOKEN) { // token (opaque) auth only
			var tokenAuthOk bool = false
			tkUserName, tokenHash, errTokenSepare := smart.AuthUserTokenDefaultSepareParts(token)
			if(tkUserName != "") {
				aUser = tkUserName // for logging purposes
			} //end if
			if(errTokenSepare != nil) {
				err = "Auth.Default: [Token:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: " + errTokenSepare.Error()
			} else if((smart.StrTrimWhitespaces(tkUserName) != "") && (smart.AuthIsValidUserName(tkUserName) == true) && (smart.StrTrimWhitespaces(tokenHash) != "")) {
				tokenAuthOk, aData = smart.AuthUserTokenDefaultCheck(authRealm, tkUserName, tokenHash, httpAuthMode, authUsername, authToken, "", "", smart.HTTP_AUTH_DEFAULT_PRIV, smart.HTTP_AUTH_DEFAULT_RESTR, smart.AuthGetUserDefaultPrivKey(tkUserName), "", smart.AuthGetUserDefaultSecurityKey(tkUserName), 0, nil) // only opaque tokens are supported
				if(tokenAuthOk != true) { // default check: user, pass, requiredUsername, requiredPassword
					aData.OK = false // make sure to set to false, it was not OK
					err = "Auth.Default: [Token:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: no match or invalid"
				} //end if
			} else {
				err = "Auth.Default: [Token:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: Empty or Invalid UserName / Token Hash"
			} //end if else
		} else if(httpAuthMode == smart.HTTP_AUTH_MODE_BASIC) { // basic auth only, no 2FA (2FA req. custom implementation)


			if((smart.StrTrimWhitespaces(user) != "") && (smart.StrTrimWhitespaces(pass) != "")) {

				if((smart.StrTrimWhitespaces(user) != "") && (smart.StrContains(user, "#") != false) && (smart.StrTrimWhitespaces(pass) != "")) { // Auth Basic.Token


					var tokenBasicAuthOk bool = false
					tkUserName, tokenHash, errTokenSepare := smart.AuthUserTokenBasicSepareParts(user, pass)
					if(tkUserName != "") {
						aUser = tkUserName // for logging purposes
					} //end if
					if(errTokenSepare != nil) { // expects: username=user#token ; pass=Token-Hash
						err = "Auth.Default: [Basic.Token:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: " + errTokenSepare.Error()
					} else if((smart.StrTrimWhitespaces(tkUserName) != "") && (smart.AuthIsValidUserName(tkUserName) == true) && (smart.StrTrimWhitespaces(tokenHash) != "")) {

						tokenBasicAuthOk, aData = smart.AuthUserTokenDefaultCheck(authRealm, tkUserName, tokenHash, httpAuthMode, authUsername, authToken, "", "", smart.HTTP_AUTH_DEFAULT_PRIV, smart.HTTP_AUTH_DEFAULT_RESTR, smart.AuthGetUserDefaultPrivKey(tkUserName), "", smart.AuthGetUserDefaultSecurityKey(tkUserName), 0, nil) // only opaque tokens are supported with the auth basic mode
						if(tokenBasicAuthOk != true) { // default check: user, pass, requiredUsername, requiredPassword
							aData.OK = false // make sure to set to false, it was not OK
							err = "Auth.Default: [Basic.Token:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: no match or invalid"
						} //end if


					} else {
						err = "Auth.Default: [Basic.Token:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: Empty or Invalid UserName / Token Hash"
					} //end if else


				} else if((smart.StrTrimWhitespaces(user) != "") && (smart.AuthIsValidUserName(user) == true) && (smart.StrTrimWhitespaces(pass) != "")) { // Auth Basic
					if(smart.Auth2FACookieIsEnabled() != true) {
						var authBasicOk bool = false
						authBasicOk, aData = smart.AuthUserPassDefaultCheck(authRealm, user, pass, httpAuthMode, authUsername, authPassword, smart.ALGO_PASS_PLAIN, "", "", smart.HTTP_AUTH_DEFAULT_PRIV, smart.HTTP_AUTH_DEFAULT_RESTR, smart.AuthGetUserDefaultPrivKey(user), "", smart.AuthGetUserDefaultSecurityKey(user), 0, nil) // only plain type password can be provided in the default mode ; to use hashed passwords needs custom auth check implementation
						if(authBasicOk != true) { // default check: user, pass, requiredUsername, requiredPassword
							aData.OK = false // make sure to set to false, it was not OK
							err = "Auth.Default: [Basic:User/Pass:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: no match or invalid"
						} //end if
					} else {
						err = "Auth.Default: [Basic:User/Pass:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: 2FA is Unsupported by the Default Provider"
					} //end if else
				} else {
					err = "Auth.Default: [Basic/Basic.Token:User/Pass:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: Empty or Invalid UserName / Password"
				} //end if else

			} else {
				err = "Auth.Default: [Basic:User/Pass:" + smart.ConvertUInt8ToStr(httpAuthMode) + "] Failed: Empty or Invalid UserName / Password"
			} //end if else


		} else { // except HTTP_AUTH_MODE_BASIC without 2FA, supported as default implementation, other modes (incl. 2FA) requires custom implementation, via custom auth provider, see above: customAuthCheck
			err = "Auth Mode NOT Supported: [" + smart.ConvertUInt8ToStr(httpAuthMode) + "] / [Auth:" + smart.AuthMethodGetNameById(httpAuthMode) + "]"
		} //end if else
	} //end if else
	//--
	if(err != "") {
		//-- write to cache invalid login
		if(cacheExists != true) {
			cachedObj.Id = cacheKeyCliIpAddr
			cachedObj.Data = "."
		} else {
			cachedObj.Data += "."
		} //end if
		memAuthCache.Set(cachedObj, int64(ICACHEM_EXPIRATION))
		log.Println("[NOTICE] " + smart.CurrentFunctionName() + ": Set-In-Cache: AUTH.FAILED [" + authRealm + "] :: [Auth:" + smart.AuthMethodGetNameById(httpAuthMode) + "] :: Client: `" + cachedObj.Id + "` # `" + cachedObj.Data + "` @", len(cachedObj.Data))
		//--
		if(smart.AuthBasicIsEnabled() == true) { // show Auth Basic Prompt (Header) ONLY if Auth Basic is Enabled, otherwise does not make sense ...
		//	if((httpAuthMode != smart.HTTP_AUTH_MODE_COOKIE) && (httpAuthMode != smart.HTTP_AUTH_MODE_TOKEN) && (httpAuthMode != smart.HTTP_AUTH_MODE_BEARER) && (httpAuthMode != smart.HTTP_AUTH_MODE_APIKEY)) {
			if((httpAuthMode == smart.HTTP_AUTH_MODE_BASIC) || (httpAuthMode == smart.HTTP_AUTH_MODE_NONE)) { // this condition is better than above ; needs to include also auth none because prior the browser will authenticate is actually Auth None instead of Auth Basic
				var authDisableHeader string = ""
				if(IsAjaxRequest(r) == true) {
					authDisableHeader = smart.StrToLower(smart.StrTrimWhitespaces(HttpRequestGetHeaderStr(r, HTTP_HEADER_DISABLE_AUTH_PROMPT)))
				} //end if
				if(authDisableHeader != "true") { // {{{SYNC-HTTP-UTILS-CLI-HDR-NO-AUTH-PROMPT-TRUE}}} ; support (just for ajax requests) without raising the auth prompt
					HttpHeaderAuthBasic(w , authRealm)
				} //end if
			} //end if
		} //end if
		HttpStatus401(w, r, "Access to this area requires Authentication", outputHtml, false)
		//--
		if(aUser != "") { // log only if non-empty user
			log.Printf("[WARNING] " + smart.CurrentFunctionName() + ": HTTP(S) Server :: AUTH.FAILED [" + authRealm + "] :: [Auth:" + smart.AuthMethodGetNameById(httpAuthMode) + "] :: UserName: `" + aUser + "` # [%s %s %s] %s on Host [%s] for RemoteAddress [%s] on Client [%s] with RealClientIP [%s] %s\n", r.Method, r.URL, r.Proto, "401", r.Host, rAddr, ip + ":" + port, realClientIp, " # HTTP Header Key: `" + rawHdrRealIpKey + "` # HTTP Header Value: `" + rawHdrRealIpVal + "`")
		} //end if
		//--
		return smart.NewError(err), aData
		//--
	} //end if
	//--
	if(cacheExists == true) {
		memAuthCache.Unset(cacheKeyCliIpAddr) // unset on 1st successful login
	} //end if
	//--
	log.Println("[OK] " + smart.CurrentFunctionName() + ": HTTP(S) Server :: AUTH.SUCCESS [" + authRealm + "] :: [Auth:" + smart.AuthMethodGetNameById(httpAuthMode) + "] :: UserName: `" + aUser + "` # From RemoteAddress: `" + ip + "` on Port: `" + port + "`" + " # RealClientIP: `" + realClientIp + "` # Using Real Client IP: [", isAuthMemKeyUsingProxyRealClientIp, "] # HTTP RealIP Header Key: `" + rawHdrRealIpKey + "` # HTTP RealIP Header Value: `" + rawHdrRealIpVal + "`")
	//--
	return nil, aData
	//--
} //END FUNCTION


//-----


func MimeTypeByFileExtension(fext string) string {
	//--
	fext = smart.StrTrimWhitespaces(fext) // ex: .html
	if(fext == "") {
		return ""
	} //end if
	//--
	return mime.TypeByExtension(smart.StrToLower(fext))
	//--
} //END FUNCTION


func MimeTypeByFilePath(path string) string {
	//--
	path = smart.StrTrimWhitespaces(path)
	if(path == "") {
		return ""
	} //end if
	//--
	return MimeTypeByFileExtension(smart.PathBaseExtension(path))
	//--
} //END FUNCTION


//-----


func MimeAndCharsetGetFromMimeType(mType string) (string, string) {
	//--
	mType = smart.StrToLower(smart.StrTrimWhitespaces(mType))
	if(mType == "") {
		return "", ""
	} //end if
	//--
	var mCharSet string = ""
	if(smart.StrContains(mType, ";")) {
		mTypArr := smart.Explode(";", mType)
		mType = smart.StrTrimWhitespaces(mTypArr[0]) // already StrToLower
		mCharSet = smart.StrTrimWhitespaces(mTypArr[1])
		if(smart.StrIStartsWith(mCharSet, "charset=")) {
			mCharSet = smart.StrToUpper(smart.StrTrimWhitespaces(smart.StrSubstr(mCharSet, 8, 0)))
		} else {
			mCharSet = "" // clear, is invalid, may contain other things ...
		} //end if else
	} //end if
	//--
	return mType, mCharSet
	//--
} //END FUNCTION


//-----


func MimeDispositionConformParam(mimeDisposition string) string {
	//--
	mimeDisposition = smart.StrToLower(smart.StrTrimWhitespaces(mimeDisposition))
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
	defer smart.PanicHandler()
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
			mimeType = MIME_TYPE_TEXT
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- html : must be default inline
		case "html":
			mimeType = MIME_TYPE_HTML
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- css
		case "css":
			mimeType = MIME_TYPE_CSS
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- javascript
		case "js":
			mimeType = MIME_TYPE_JS
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "json":
			mimeType = MIME_TYPE_JSON
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- web images
		case "svg":
			mimeType = MIME_TYPE_SVG
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "png":
			mimeType = MIME_TYPE_PNG
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "gif":
			mimeType = MIME_TYPE_GIF
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "jpeg": fallthrough
		case "jpe": fallthrough
		case "jpg":
			mimeType = MIME_TYPE_JPEG
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "webp":
			mimeType = MIME_TYPE_WEBP
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "ico":
			mimeType = MIME_TYPE_FAVICON
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- fonts
		case "woff2":
			mimeType = MIME_TYPE_WOFF2
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "woff":
			mimeType = MIME_TYPE_WOFF1
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "ttf":
			mimeType = MIME_TYPE_TTF
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- xml
		case "xml":
			mimeType = MIME_TYPE_XML
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- data
		case "csv": fallthrough // csv comma
		case "tab": // csv tab
			mimeType = MIME_TYPE_CSV
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- email / calendar / addressbook
		case "eml":
			mimeType = MIME_TYPE_EMAIL_MSG
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "vcf":
			mimeType = MIME_TYPE_VCARD
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		case "ics":
			mimeType = MIME_TYPE_ICALENDAR
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- specials
		case "asc": fallthrough
		case "sig":
			mimeType = MIME_TYPE_SIG_GPG
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- portable documents
		case "pdf":
			mimeType = MIME_TYPE_PDF
			mimeDisposition = DISP_TYPE_INLINE // DISP_TYPE_ATTACHMENT
			break
		//-------------- theora
		case "ogg": fallthrough // theora audio
		case "oga":
			mimeType = MIME_TYPE_AUDIO_OGG
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "ogv": // theora video
			mimeType = MIME_TYPE_VIDEO_OGV
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- webm
		case "webm": // google vp8
			mimeType = MIME_TYPE_VIDEO_WEBM
			mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- mp3 / mp4
		case "mp4": fallthrough // mp4 video (it can be also mp4 audio, but cast it as video by default)
		case "m4v": // mp4 video
			mimeType = MIME_TYPE_VIDEO_MPEG
			mimeDisposition = DISP_TYPE_INLINE
			break
		case "mp3": fallthrough // mp3 audio
		case "mp4a": // mp4 audio
			mimeType = MIME_TYPE_AUDIO_MPEG
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
			mimeType = MIME_TYPE_HTML
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- php
		case "php":
			mimeType = MIME_TYPE_TEXT // application/x-php is just for environments where PHP is executable, not for golang
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
		//	mimeDisposition = DISP_TYPE_INLINE
			break
		//-------------- plain text and development
		case "ini": fallthrough // ini file
		case "yml": fallthrough // yaml file
		case "yaml": fallthrough // yaml file
		case "md": fallthrough // markdown
		case "markdown": fallthrough // markdown
		case "pem": fallthrough // PEM Certificate File
		case "crl": fallthrough // Certificate Revocation List
		case "crt": fallthrough // Certificate File
		case "cer": fallthrough // Certificate File
		case "key": fallthrough // Certificate Key File
		case "log": fallthrough // log file
		case "sql": fallthrough // sql file
		case "inc": fallthrough // include file
		case "sh": fallthrough // shell script
		case "diff": fallthrough // Diff File
		case "patch": fallthrough // Diff Patch
		case "go": fallthrough // Go Lang
		case "tcl": fallthrough // TCL
		case "tk": fallthrough // Tk
		case "lua": fallthrough // Lua
		case "gjs": fallthrough // gnome js
		case "toml": fallthrough // Tom's Obvious, Minimal Language (used with Cargo / Rust definitions)
		case "pl": fallthrough // perl
		case "py": fallthrough // python
		case "phps": fallthrough // php source, assign text/plain !
		case "rs": fallthrough // Rust Language
		case "c": fallthrough // C Language
		case "h": fallthrough // C/C++ Defs
		case "cpp": fallthrough // C++ Language
		case "vala": fallthrough // vala language
		case "swift": fallthrough // apple swift language
		case "java": fallthrough // java source code
		case "pas": fallthrough // Delphi / Pascal
		case "bash":  // bash (shell) script
			mimeType = MIME_TYPE_TEXT
			mimeUseCharset = true
			mimeDisposition = DISP_TYPE_ATTACHMENT
			break
		//-------------- default
		default: // others
			mimeUseCharset = false
			mimeType = MimeTypeByFilePath(lfile)
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
				log.Println("[DEBUG] " + smart.CurrentFunctionName() + ": Fallback on MimeType:", mimeType)
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
