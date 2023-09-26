
// GO Lang :: SmartGo / Web HTTP Utils :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20230926.1746 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package httputils

import (
	"os"
	"runtime"
	"sync"

	"log"
	"fmt"
	"time"

	"io"
//	"io/ioutil"
	"bytes"

	"mime"
	"mime/multipart"

	"net/http"
	"net/http/httputil"
	"crypto/tls"
	"crypto/x509"
	"crypto/subtle"

	smart 		"github.com/unix-world/smartgo"
	smartcache 	"github.com/unix-world/smartgo/simplecache"
	assets 		"github.com/unix-world/smartgo/web-assets"
	pbar 		"github.com/unix-world/smartgo/progressbar"
)


//-----

const (
	VERSION string = "r.20230926.1746"

	DEBUG bool = false
	DEBUG_CACHE bool = false

	//--
	DEFAULT_CLIENT_UA string = "NetSurf/3.10"
	//--
	HTTP_CLI_DEF_BODY_READ_SIZE uint64 = smart.SIZE_BYTES_16M 		//  16MB
	HTTP_CLI_MAX_BODY_READ_SIZE uint64 = smart.SIZE_BYTES_16M * 32 	// 512MB
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
	HTTP_MAX_SIZE_SAFE_URL uint16 = 4096
	//--

	//--
	DEFAULT_REALM string = "SmartGO Web Server" // must be min 7 chars
	//--
	DISP_TYPE_INLINE string = "inline"
	DISP_TYPE_ATTACHMENT string = "attachment"
	MIME_TYPE_DEFAULT string = "application/octet-stream"
	//--
	CACHE_CLEANUP_INTERVAL uint32 = 5 // 5 seconds
	CACHE_EXPIRATION uint32 = 300 // 300 seconds = 5 mins
	CACHE_CONTROL_NOCACHE = "no-cache"
	CACHE_CONTROL_PRIVATE = "private"
	CACHE_CONTROL_PUBLIC = "public"
	//--
	REGEX_SAFE_HTTP_FORM_VAR_NAME string = `^[a-zA-Z0-9_\-]+$`
	//--

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
	HTTP_STATUS_410 string = "410 Gone"
	HTTP_STATUS_429 string = "429 Too Many Requests"
	//--
	HTTP_STATUS_500 string = "500 Internal Server Error"
	HTTP_STATUS_501 string = "501 Not Implemented"
	HTTP_STATUS_502 string = "502 Bad Gateway"
	HTTP_STATUS_503 string = "503 Service Unavailable"
	HTTP_STATUS_504 string = "504 Gateway Timeout"
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
	HTTP_HEADER_AUTH_AUTHORIZATION string = "authorization"
	HTTP_HEADER_AUTH_AUTHENTICATE string = "www-authenticate"
	HTTP_HEADER_VALUE_AUTH_TYPE_BASIC string = "Basic" // keep camel case
	//--
	HTTP_HEADER_DAV_DESTINATION string = "destination"
	HTTP_HEADER_DAV_OVERWRITE string = "overwrite"
	//--
	HTTP_HEADER_USER_AGENT string = "user-agent"
	//-- #end sync
)


//-----

var memAuthMutex sync.Mutex
var memAuthCache *smartcache.InMemCache = nil

//-----


func httpHeaderSignatureUserAgent() string {
	//--
	return DEFAULT_CLIENT_UA + " (" + smart.DESCRIPTION + " " + smart.VERSION + " " + VERSION + "; " + runtime.GOOS + "/" + runtime.GOARCH + "; " + "GoLang/" + runtime.Version() + ")"
	//--
} //END FUNCTION


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


func HttpClientAuthBasicHeader(authUsername string, authPassword string) http.Header {
	//--
	return http.Header{HTTP_HEADER_AUTH_AUTHORIZATION: {HTTP_HEADER_VALUE_AUTH_TYPE_BASIC + " " + smart.Base64Encode(authUsername + ":" + authPassword)}}
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


func HttpClientDoRequestHEAD(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "HEAD"
	var reqArr map[string][]string = nil
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


// IMPORTANT: will not rewrite the download file if exists ... must be previous deleted !
// can handle: GET or POST
func HttpClientDoRequestDownloadFile(downloadLocalDirPath string, method string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, reqArr map[string][]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var putLocalFilePath string = ""
	//--
	downloadLocalDirPath = smart.StrTrimWhitespaces(downloadLocalDirPath)
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
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestGET(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxBytesRead uint64, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "GET"
	var reqArr map[string][]string = nil
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPOST(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, reqArr map[string][]string, timeoutSec uint32, maxBytesRead uint64, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "POST"
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPUTFile(putLocalFilePath string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "PUT"
	var reqArr map[string][]string = nil
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPUT(putData string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "PUT"
	var reqArr map[string][]string = map[string][]string{
		"@put:data": { putData },
	}
	putData = "" // free mem
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestMKCOL(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "MKCOL"
	var reqArr map[string][]string = nil
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestDELETE(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "DELETE"
	var reqArr map[string][]string = nil
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestCOPY(destinationUri string, overwrite bool, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
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
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestMOVE(destinationUri string, overwrite bool, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
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
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestPROPFIND(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "PROPFIND"
	var reqArr map[string][]string = nil
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


func HttpClientDoRequestOPTIONS(uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, timeoutSec uint32, maxRedirects uint8, authUsername string, authPassword string) *HttpClientRequest {
	//--
	var method string = "OPTIONS"
	var reqArr map[string][]string = nil
	var putLocalFilePath string = ""
	var downloadLocalDirPath string = ""
	var maxBytesRead uint64 = HTTP_CLI_DEF_BODY_READ_SIZE
	//--
	return httpClientDoRequest(method, uri, tlsServerPEM, tlsInsecureSkipVerify, ckyArr, reqArr, putLocalFilePath, downloadLocalDirPath, timeoutSec, maxBytesRead, maxRedirects, authUsername, authPassword)
	//--
} //END FUNCTION


//-----


func reqArrToHttpFormData(reqArr map[string][]string) (err string, formData *bytes.Buffer, multipartType string) {
	//--
	// This will create the form data or multi/part form data by reading all files in memory
	//--
	var emptyData *bytes.Buffer = &bytes.Buffer{}
	var postData  *bytes.Buffer = &bytes.Buffer{}
	//--
	if(reqArr == nil) {
		return "", emptyData, ""
	} //end if
	//--
	w := multipart.NewWriter(postData)
	defer w.Close()
	//--
	var validPostVarsOrFiles int = 0
	//--
	for key, val := range reqArr {
		key = smart.StrTrimWhitespaces(key)
		if(key != "") {
			if(smart.StrRegexMatchString(REGEX_SAFE_HTTP_FORM_VAR_NAME, key)) { // form field
				for z:=0; z<len(val); z++ {
					if(int64(len(val[z])) > int64(HTTP_CLI_MAX_POST_VAL_SIZE)) {
						return "ERR: FAILED to Add Post Form Variable: `" + key + "`: `" + smart.ConvertIntToStr(len(val[z])) + "` bytes ; Oversized #" + smart.ConvertIntToStr(z), emptyData, ""
					} //end if
					v, ev := w.CreateFormField(key)
					if(ev != nil) {
						return "ERR: FAILED to Add Post Form Variable: `" + key + "`: `" + val[z] + "` #" + smart.ConvertIntToStr(z) + ": " + ev.Error(), emptyData, ""
					} //end if
					v.Write([]byte(val[z]))
					validPostVarsOrFiles++
					if(DEBUG == true) {
						log.Println("[DEBUG] reqArrToHttpFormData :: Post Form Variable Add: `" + key + "`: `" + val[z] + "` #", z)
					} //end if
				} //end for
			} else if(key == "@file") { // form file
				for z:=0; z<len(val); z++ {
					var uploadFilePath string = val[z]
					if(!smart.PathIsSafeValidPath(uploadFilePath)) {
						return "ERR: The POST File Path is Invalid or Unsafe: `" + uploadFilePath + "`", emptyData, ""
					} //end if
					if(smart.PathIsEmptyOrRoot(uploadFilePath)) {
						return "ERR: The POST File Path is Empty or is Root: `" + uploadFilePath + "`", emptyData, ""
					} //end if
					if(smart.PathIsAbsolute(uploadFilePath)) {
						return "ERR: The POST File Path is Absolute, must be Relative: `" + uploadFilePath + "`", emptyData, ""
					} //end if
					if(smart.PathIsBackwardUnsafe(uploadFilePath)) {
						return "ERR: The POST File Path is Backward Unsafe: `" + uploadFilePath + "`", emptyData, ""
					} //end if
					if(!smart.PathExists(uploadFilePath)) {
						return "ERR: The POST File Path does NOT Exists: `" + uploadFilePath + "`", emptyData, ""
					} //end if
					if(smart.PathIsDir(uploadFilePath)) {
						return "ERR: The POST File Path is a Directory: `" + uploadFilePath + "`", emptyData, ""
					} //end if
					if(!smart.PathIsFile(uploadFilePath)) {
						return "ERR: The POST File Path is NOT a File: `" + uploadFilePath + "`", emptyData, ""
					} //end if
					var fName string = smart.StrTrimWhitespaces(smart.PathBaseName(uploadFilePath))
					if((fName == "") || (!smart.PathIsSafeValidFileName(fName))) {
						return "ERR: FAILED to detect the File Name from the POST File Path: `" + uploadFilePath + "`", emptyData, ""
					} //end if
					f, ef := w.CreateFormFile("file", fName)
					if(ef != nil) {
						return "ERR: FAILED to add the POST File Path: `" + uploadFilePath + "`: " + ef.Error(), emptyData, ""
					} //end if
					stat, errStat := os.Stat(uploadFilePath)
					if(errStat != nil) {
						return "ERR: FAILED to stat the POST File Path: `" + uploadFilePath + "`: " + errStat.Error(), emptyData, ""
					} //end if
					if(stat.Size() > int64(HTTP_CLI_MAX_POST_FILE_SIZE)) {
						return "ERR: FAILED to read the POST File Path: `" + uploadFilePath + "`: File is Oversized: " + smart.ConvertInt64ToStr(stat.Size()), emptyData, ""
					} //end if
					file, errOpen := os.Open(uploadFilePath)
					if(errOpen != nil) {
						return "ERR: FAILED to open for read the POST File Path: `" + uploadFilePath + "`: " + errOpen.Error(), emptyData, ""
					} //end if
					_, errCopy := io.Copy(f, file)
					file.Close()
					if(errCopy != nil) {
						return "ERR: FAILED to read the POST File Path: `" + uploadFilePath + "`: " + errCopy.Error(), emptyData, ""
					} //end if
					validPostVarsOrFiles++
					if(DEBUG == true) {
						log.Println("[DEBUG] reqArrToHttpFormData :: Post File Add: `" + uploadFilePath + "` @ Size:", stat.Size() ,"bytes #", z)
					} //end if
				} //end for
			} else {
				return "ERR: Invalid Key in Request Arr Data: `" + key + "`", emptyData, ""
			} //end if else
		} else {
			return "ERR: Empty Key in Request Arr Data", emptyData, ""
		} //end if
		if(int64(len(postData.Bytes())) > int64(HTTP_CLI_MAX_POST_DATA_SIZE)) {
			return "ERR: POST Data is Oversized,Max Limit is: " + smart.ConvertUInt64ToStr(HTTP_CLI_MAX_POST_DATA_SIZE) + " bytes", emptyData, ""
		} //end if
	} //end for
	//--
	if(validPostVarsOrFiles <= 0) {
		return "ERR: No Valid POST Data found", emptyData, ""
	} //end if
	//--
	return "", postData, w.FormDataContentType()
	//--
} //END FUNCTION


// If Auth User/Pass is set will dissalow redirects, by auto-setting maxRedirects=0 !
// Min Read Limit is 10MB (set maxBytesRead=0 as default) ; Max Read Limit is 1GB (because is in memory !)
func httpClientDoRequest(method string, uri string, tlsServerPEM string, tlsInsecureSkipVerify bool, ckyArr map[string]string, reqArr map[string][]string, putLocalFilePath string, downloadLocalDirPath string, timeoutSec uint32, maxBytesRead uint64, maxRedirects uint8, authUsername string, authPassword string) (httpResult *HttpClientRequest) {
	//--
	httpResult = &HttpClientRequest {
		Errors: "?",
		UserAgent: httpHeaderSignatureUserAgent(),
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
		UploadLocalFile: putLocalFilePath,
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
	transport := &http.Transport{
		TLSClientConfig: TlsConfigClient(tlsInsecureSkipVerify, tlsServerPEM),
		TLSHandshakeTimeout: time.Duration(HTTP_CLI_TLS_TIMEOUT) * time.Second, // fix for TLS handshake error ; default is 10 seconds
		DisableKeepAlives: true, // fix ; {{{SYNC-GO-ERR-HTTP-CLI-TOO-MANY-OPEN-FILES}}} : this is a fix for too many open files # this is requires as well as resp.Body.Close() which is handled below
	}
	//--
	uri = smart.StrTrimWhitespaces(uri)
	if((uri == "") || (len(uri) > int(HTTP_MAX_SIZE_SAFE_URL))) {
		httpResult.Uri = ""
		httpResult.Errors = "ERR: URL is Empty or Too Long"
		httpResult.HttpStatus = -101
		return
	} //end if
	httpResult.Uri = uri
	//--
	method = smart.StrToUpper(smart.StrTrimWhitespaces(method))
	var isHead bool = false
	var isGet bool = false
	var isPost bool = false
	var isPut bool = false
	var isFilePut bool = false
	var isMkCol bool = false
	var isDelete bool = false
	var isCopy bool = false
	var isMove bool = false
	var isPropFind bool = false
	var isOptions bool = false
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
			putLocalFilePath = smart.StrTrimWhitespaces(putLocalFilePath)
			if(putLocalFilePath != "") {
				isFilePut = true
				if(!smart.PathIsSafeValidPath(putLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is Invalid or Unsafe: `" + putLocalFilePath + "`"
					httpResult.HttpStatus = -701
					return
				} //end if
				if(smart.PathIsEmptyOrRoot(putLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is Empty or is Root: `" + putLocalFilePath + "`"
					httpResult.HttpStatus = -702
					return
				} //end if
				if(smart.PathIsAbsolute(putLocalFilePath)) { // {{{SYNC-HTTPCLI-UPLOAD-PATH-ALLOW-ABSOLUTE}}}
					httpResult.Errors = "ERR: The PUT File Path is Absolute, must be Relative: `" + putLocalFilePath + "`"
					httpResult.HttpStatus = -703
					return
				} //end if
				if(smart.PathIsBackwardUnsafe(putLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is Backward Unsafe: `" + putLocalFilePath + "`"
					httpResult.HttpStatus = -704
					return
				} //end if
				if(!smart.PathExists(putLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path does NOT Exists: `" + putLocalFilePath + "`"
					httpResult.HttpStatus = -705
					return
				} //end if
				if(smart.PathIsDir(putLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is a Directory: `" + putLocalFilePath + "`"
					httpResult.HttpStatus = -706
					return
				} //end if
				if(!smart.PathIsFile(putLocalFilePath)) {
					httpResult.Errors = "ERR: The PUT File Path is NOT a File: `" + putLocalFilePath + "`"
					httpResult.HttpStatus = -707
					return
				} //end if
				var fName string = smart.StrTrimWhitespaces(smart.PathBaseName(putLocalFilePath))
				if((fName == "") || (!smart.PathIsSafeValidFileName(fName))) {
					httpResult.Errors = "ERR: FAILED to detect a valid File Name from the PUT File Path: `" + putLocalFilePath + "` as `" + fName + "`"
					httpResult.HttpStatus = -708
					return
				} //end if
				putFSize, putFSizeErr := smart.SafePathFileGetSize(putLocalFilePath, false) // {{{SYNC-HTTPCLI-UPLOAD-PATH-ALLOW-ABSOLUTE}}}
				if(putFSizeErr != "") {
					httpResult.Errors = "ERR: FAILED to determine a valid File Size from the PUT File Path: `" + putLocalFilePath + "` # " + putFSizeErr
					httpResult.HttpStatus = -709
					return
				} //end if
				if(putFSize <= 0) {
					httpResult.Errors = "ERR: The File Size of the PUT File Path: `" + putLocalFilePath + "` Must be Greater than Zero"
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
			var lenPutData int = len(reqArr["@copy:destination"][0])
			if(lenPutData <= 0) { // DO NOT TRIM ! If non-empty need to be sent as is
				httpResult.Errors = "ERR: The String Size of the COPY destination must be Greater than Zero"
				httpResult.HttpStatus = -603
				return
			} else if(int64(lenPutData) > int64(HTTP_MAX_SIZE_SAFE_URL)) {
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
			var lenPutData int = len(reqArr["@move:destination"][0])
			if(lenPutData <= 0) { // DO NOT TRIM ! If non-empty need to be sent as is
				httpResult.Errors = "ERR: The String Size of the MOVE destination must be Greater than Zero"
				httpResult.HttpStatus = -613
				return
			} else if(int64(lenPutData) > int64(HTTP_MAX_SIZE_SAFE_URL)) {
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
			httpResult.HttpStatus = -102
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
			if(smart.PathIsAbsolute(downloadLocalDirPath)) { // {{{SYNC-HTTPCLI-DOWNLOAD-PATH-ALLOW-ABSOLUTE}}}
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
	if((isHead == true) || (isOptions == true) || (isPropFind == true) || (isMkCol == true) || (isDelete == true) || (isCopy == true) || (isMove == true) || (isPut == true)) {
		if(maxBytesRead > HTTP_CLI_DEF_BODY_READ_SIZE) {
			maxBytesRead = HTTP_CLI_DEF_BODY_READ_SIZE
		} //end if
	} //end if
	httpResult.MaxDownloadSize = maxBytesRead
	//--
	var useAuth bool = false
	if(authUsername != "") {
		useAuth = true
		httpResult.AuthUserName = authUsername
	} else {
		httpResult.AuthUserName = ""
	} //end if else
	//--
	if(useAuth == true) {
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
			return smart.CreateNewError("Redirect Policy Limit: Stop after: " + smart.ConvertUInt8ToStr(maxRedirects) + " times")
		} //end if
		httpResult.LastUri = req.URL.String()
		httpResult.NumRedirects++
		httpResult.RedirUris = append(httpResult.RedirUris, httpResult.LastUri)
		return nil
	} //end function
	//--
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: transport,
		CheckRedirect: safeCheckRedirect,
	}
	//--
	var errData string = ""
	var formData *bytes.Buffer = &bytes.Buffer{}
	var multipartType string = ""
	var formDataLen int64 = 0
	var putDataLen int64 = 0
	var req *http.Request
	var errReq error
	if(isPost == true) { // POST must have some data to post
		errData, formData, multipartType = reqArrToHttpFormData(reqArr)
		if(errData != "") {
			httpResult.Errors = "ERR: Invalid POST Form Data: " + errData
			httpResult.HttpStatus = -103
			return
		} //end if
		formDataLen = int64(len(formData.Bytes()))
		obar := pbar.NewOptions64(
			formDataLen,
			pbar.OptionSetBytes64(formDataLen),
			pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
			pbar.OptionSetDescription("[SmartHttpCli:PostData]"),
			pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed") }),
		)
		obar.RenderBlank()
		req, errReq = http.NewRequest(method, uri, obar.NewProxyReader(formData))
		log.Println("[INFO] SmartHttpCli :: Post Data: `" + httpResult.LastUri + "` @ Size:", formDataLen, "bytes (" + smart.PrettyPrintBytes(formDataLen) + ")")
	} else if(isPut == true) {
		var ubar *pbar.ProgressBar
		if(isFilePut == true) {
			stat, errStat := os.Stat(putLocalFilePath)
			if(errStat != nil) {
				httpResult.Errors = "ERR: FAILED to stat the PUT File Path: `" + putLocalFilePath + "`: " + errStat.Error()
				httpResult.HttpStatus = -715
				return
			} //end if
			file, errOpen := os.Open(putLocalFilePath)
			if(errOpen != nil) {
				httpResult.Errors = "ERR: FAILED to open for read the PUT File Path: `" + putLocalFilePath + "`: " + errOpen.Error()
				httpResult.HttpStatus = -716
				return
			} //end if
			defer file.Close()
			putDataLen = stat.Size()
			if(DEBUG == true) {
				log.Println("[DEBUG] SmartHttpCli :: Put File: `" + putLocalFilePath + "` ; Size:", putDataLen, "bytes")
			} //end if
			ubar = pbar.NewOptions64(
				putDataLen,
				pbar.OptionSetBytes64(putDataLen),
				pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
				pbar.OptionSetDescription("[SmartHttpCli:Uploading]"),
				pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed") }),
			)
			ubar.RenderBlank()
			req, errReq = http.NewRequest(method, uri, ubar.NewProxyReader(file))
			log.Println("[INFO] SmartHttpCli :: Upload File [" + httpResult.UploadFileName + "]: `" + httpResult.LastUri + "` @ Size:", putDataLen, "bytes (" + smart.PrettyPrintBytes(putDataLen) + ")")
		} else {
			res := bytes.NewBuffer([]byte(reqArr["@put:data"][0]))
			putDataLen = int64(len(reqArr["@put:data"][0]))
			if(DEBUG == true) {
				log.Println("[DEBUG] SmartHttpCli :: Put Data ; Size:", putDataLen, "bytes")
			} //end if
			ubar = pbar.NewOptions64(
				putDataLen,
				pbar.OptionSetBytes64(putDataLen),
				pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
				pbar.OptionSetDescription("[SmartHttpCli:WriteData]"),
				pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed") }),
			)
			ubar.RenderBlank()
			req, errReq = http.NewRequest(method, uri, ubar.NewProxyReader(res))
			log.Println("[INFO] SmartHttpCli :: Upload Data: `" + httpResult.LastUri + "` @ Size:", putDataLen, "bytes (" + smart.PrettyPrintBytes(putDataLen) + ")")
		} //end if else
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
	req.Header = map[string][]string{} // init, reset
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
					log.Println("[DEBUG] SmartHttpCli :: Set Cookie: `" + cK + "`: `" + cV + "`")
				} //end if
			} //end if
		} //end for
	} //end if
	//--
	if(isPut == true) {
		req.TransferEncoding = []string{"identity"} // forces to change from the default chunked transfer encoding to linear or gzip (support wider servers)
		req.ContentLength = putDataLen
	} else if(isCopy == true) {
		req.Header.Set(HTTP_HEADER_DAV_DESTINATION, reqArr["@copy:destination"][0])
		req.Header.Set(HTTP_HEADER_DAV_OVERWRITE, reqArr["@copy:overwrite"][0])
	} else if(isMove == true) {
		req.Header.Set(HTTP_HEADER_DAV_DESTINATION, reqArr["@move:destination"][0])
		req.Header.Set(HTTP_HEADER_DAV_OVERWRITE, reqArr["@move:overwrite"][0])
	} //end if
	//--
	if(useAuth == true) {
		authHead := HttpClientAuthBasicHeader(authUsername, authPassword)
		for k, v := range authHead {
			if(k != "") {
				if(v != nil) {
					for i:=0; i<len(v); i++ {
						req.Header.Add(k, v[i])
						if(DEBUG == true) {
							log.Println("[DEBUG] SmartHttpCli :: Add Auth Header: `" + k + ": " + v[i] + "` #", i)
						} //end if
					} //end for
				} //end if
			} //end if
		} //endfor
	} //end if
	//--
	if(isPost == true) {
		req.Header.Set(HTTP_HEADER_CONTENT_TYPE, multipartType)
		if(DEBUG == true) {
			log.Println("[DEBUG] SmartHttpCli :: Set POST Data Header : `" + HTTP_HEADER_CONTENT_TYPE + ": " + multipartType + "`")
		} //end if
	} //end if
	//--
	req.Header.Set(HTTP_HEADER_USER_AGENT, httpHeaderSignatureUserAgent())
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
	var mType string = smart.StrToLower(smart.StrTrimWhitespaces(resp.Header.Get(HTTP_HEADER_CONTENT_TYPE)))
	var cDisp string = smart.StrTrimWhitespaces(resp.Header.Get(HTTP_HEADER_CONTENT_DISP))
	var mFileName string = ""
	var mDisp string = ""
	var mCharSet string = ""
	if(cDisp != "") {
		dispType, dispParams, dispErr := mime.ParseMediaType(cDisp)
		if(dispErr == nil) {
			mFileName = smart.StrTrimWhitespaces(dispParams["filename"])
			mDisp = smart.StrToLower(smart.StrTrimWhitespaces(dispType))
		} //end if
	} //end if
	if(smart.StrContains(mType, ";")) {
		mTypArr := smart.Explode(";", mType)
		mType = smart.StrTrimWhitespaces(mTypArr[0])
		mCharSet = smart.StrTrimWhitespaces(mTypArr[1])
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
		pbar.OptionSetBytes64(resp.ContentLength),
		pbar.OptionThrottle(time.Duration(500) * time.Millisecond),
		pbar.OptionSetDescription("[SmartHttpCli:" + actionDBar + "]"),
		pbar.OptionOnCompletion(func(){ fmt.Println(" ...Completed") }),
	)
	dbar.RenderBlank()
	//--
	var bodyData *bytes.Buffer = &bytes.Buffer{}
	var bytesCopied int64 = 0
	var rdBodyErr error
	//--
	var useB64Encoding bool = true
	if(
		(httpResult.MimeType == "application/javascript") || (httpResult.MimeType == "application/json") ||
		(httpResult.MimeType == "application/xml") || (httpResult.MimeType == "image/svg+xml") ||
		(httpResult.MimeType == "application/x-php") ||
		(httpResult.MimeType == "message/rfc822") ||
		(smart.StrStartsWith(httpResult.MimeType, "text/"))) {
			useB64Encoding = false
	} //end if
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
		if(!smart.PathIsSafeValidFileName(dFileName)) {
			dFileName = "file.download"
		} //end if
		dFileName = smart.StrTrimWhitespaces(dFileName)
		if((dFileName == "") || (!smart.PathIsSafeValidFileName(dFileName))) {
			httpResult.Errors = "ERR: Failed to resolve a Download Safe File Name: `" + dFileName + "`"
			httpResult.HttpStatus = -810
			return
		} //end if
		httpResult.DownloadLocalFileName = dFileName
		var dFullPath string = downloadLocalDirPath + dFileName
		if((!smart.PathIsSafeValidPath(dFullPath)) || smart.PathIsBackwardUnsafe(dFullPath)) {
			httpResult.Errors = "ERR: Failed to resolve a Download Safe Path: `" + dFullPath + "`"
			httpResult.HttpStatus = -811
			return
		} //end if
		//--
		var theDwnLockFile string = dFullPath + ".tmp"
		//--
		if(!smart.PathExists(theDwnLockFile)) {
			if(smart.PathExists(dFullPath)) {
				if(smart.PathIsFile(dFullPath)) {
					smart.SafePathFileDelete(dFullPath, false) // {{{SYNC-HTTPCLI-DOWNLOAD-PATH-ALLOW-ABSOLUTE}}}
				} else {
					httpResult.Errors = "ERR: Failed to clear the Download File for writing: `" + dFullPath + "`"
					httpResult.HttpStatus = -812
					return
				} //end if
			} //end if
		} //end if
		dFile, dErr := os.OpenFile(dFullPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, smart.CHOWN_FILES)
		if(dErr != nil) {
			httpResult.Errors = "ERR: Failed to open the Download File for writing: `" + dFullPath + "`: " + dErr.Error()
			httpResult.HttpStatus = -813
			return
		} //end if
		smart.SafePathFileWrite(theDwnLockFile, "a", false, smart.DateNowLocal() + "\n" + dFullPath + "\n") // append, to see if there are colissions {{{SYNC-HTTPCLI-DOWNLOAD-PATH-ALLOW-ABSOLUTE}}}
		defer func() {
			dFile.Close()
			smart.SafePathFileDelete(theDwnLockFile, false) // {{{SYNC-HTTPCLI-DOWNLOAD-PATH-ALLOW-ABSOLUTE}}}
		}()
		//--
		log.Println("[INFO] SmartHttpCli [" + smart.ConvertIntToStr(httpResult.HttpStatus) + "] :: Download File [" + dFileName + "] to `" + downloadLocalDirPath + "` from `" + httpResult.LastUri + "` Size:", resp.ContentLength, "bytes (" + smart.PrettyPrintBytes(resp.ContentLength) + ")")
		//--
		bytesCopied, rdBodyErr = io.Copy(io.MultiWriter(dFile, dbar), resp.Body)
		//--
		dwFSize, dwFSizErr := smart.SafePathFileGetSize(dFullPath, false) // {{{SYNC-HTTPCLI-DOWNLOAD-PATH-ALLOW-ABSOLUTE}}}
		if(dwFSizErr != "") {
			dwFSize = 0
		} //end if
		//--
		httpResult.Errors = ""
		httpResult.BodyDataEncoding = "log"
		httpResult.BodyData = "SmartHttpCli :: Saved to Local Downloads Folder as `" + dFullPath + "`"
		httpResult.BodyDataSize = uint64(dwFSize)
		return
		//--
	} else { // download in memory
		//--
		log.Println("[INFO] SmartHttpCli [" + smart.ConvertIntToStr(httpResult.HttpStatus) + "] :: Download Data: `" + httpResult.LastUri + "` @ Limit:", maxBytesRead, "bytes ; Size:", resp.ContentLength, "bytes (" + smart.PrettyPrintBytes(resp.ContentLength) + ")")
		//--
		limitedReader := &io.LimitedReader{R: resp.Body, N: int64(maxBytesRead + 500)} // add extra 500 bytes to read to compare below if body size is higher than limit ; this works also in the case that resp.ContentLength is not reported or is zero ; below will check the size
		bytesCopied, rdBodyErr = io.Copy(io.MultiWriter(bodyData, dbar), limitedReader)
		if(rdBodyErr != nil) {
			httpResult.Errors = "ERR: Failed to Read Response Body (" + smart.ConvertInt64ToStr(bytesCopied) + "bytes read): " + rdBodyErr.Error()
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
	httpResult.Errors = ""
	httpResult.BodyData = string(bodyData.Bytes())
	httpResult.BodyDataSize = uint64(len(httpResult.BodyData))
	if(useB64Encoding == true) {
		httpResult.BodyDataEncoding = "base64"
		httpResult.BodyData = smart.Base64Encode(httpResult.BodyData)
	} //end if else
	return
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


func HttpMuxServer(srvAddr string, timeoutSec uint32, forceHttpV1 bool, description string) (*http.ServeMux, *http.Server) {
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
		log.Println("[NOTICE] Smart.HttpMuxServer: HTTP/1.1", description)
	} //end if
	//--
	return mux, srv
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
	w.Header().Set(HTTP_HEADER_SERVER_POWERED, smart.DESCRIPTION + " :: " + smart.VERSION)
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
		if(control != CACHE_CONTROL_PUBLIC) {
			control = CACHE_CONTROL_PRIVATE
		} //end if
		//--
		dtObjUtc := smart.DateTimeStructUtc(modified)
		if(dtObjUtc.Status == "OK") {
			modified = dtObjUtc.Years + "-" + dtObjUtc.Months + "-" + dtObjUtc.Days + " " + dtObjUtc.Hours + ":" + dtObjUtc.Minutes + ":" + dtObjUtc.Seconds // YYYY-MM-DD HH:II:SS
		} else {
			log.Println("[ERROR] HttpHeadersCacheControl: Invalid Modified Date:", modified)
			modified = now.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) // YYYY-MM-DD HH:II:SS
		} //end if
		if(DEBUG == true) {
			log.Println("[DEBUG] HttpHeadersCacheControl: Modified Date:", modified)
		} //end if
		//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
		w.Header().Set(HTTP_HEADER_CACHE_EXPS, expdate.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) + " " + TZ_UTC) // HTTP 1.0
		w.Header().Set(HTTP_HEADER_CACHE_PGMA, "cache") // HTTP 1.0 cache
		w.Header().Set(HTTP_HEADER_CACHE_LMOD, modified + " " + TZ_UTC)
		w.Header().Set(HTTP_HEADER_CACHE_CTRL, control + ", max-age=" + smart.ConvertIntToStr(expiration)) // HTTP 1.1 HTTP 1.1 (private will dissalow proxies to cache the content)
		//--
		return true
		//--
	} //end if else
	//-- {{{SYNC-HTTP-NOCACHE-HEADERS}}} ; // default expects ; expiration=-1 ; modified="" ; control=""
	expdate := now.AddDate(-1, 0, 0) // minus one year
	//--
	control = CACHE_CONTROL_NOCACHE
	//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
	w.Header().Set(HTTP_HEADER_CACHE_CTRL, control + ", must-revalidate") // HTTP 1.1 no-cache, not use their stale copy
	w.Header().Set(HTTP_HEADER_CACHE_PGMA, control) // HTTP 1.0 no-cache
	w.Header().Set(HTTP_HEADER_CACHE_EXPS, expdate.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) + " " + TZ_UTC) // HTTP 1.0 no-cache expires
	w.Header().Set(HTTP_HEADER_CACHE_LMOD, now.Format(smart.DATE_TIME_FMT_RFC1123_GO_EPOCH) + " " + TZ_UTC)
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


func httpStatus3XX(w http.ResponseWriter, r *http.Request, code uint16, redirectUrl string, outputHtml bool) {
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
			log.Println("[ERROR] httpStatus3XX: Invalid Status Code:", code, "FallBack to HTTP Status 301")
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
	redirectUrl = smart.StrTrimWhitespaces(smart.StrNormalizeSpaces(redirectUrl))
	if(redirectUrl == "") {
		log.Println("[ERROR]: httpStatus3XX: Empty Redirect URL:", code, "FallBack to HTTP Status 500")
		HttpStatus500(w, r, "Invalid Redirect URL for Status: " + title, outputHtml)
		return
	} //end if
	//--
	var content string = ""
	if(outputHtml == true) { // html
		content = assets.HtmlStatusPage(title, smart.EscapeHtml(redirectUrl), false)
	} else { // text
		content += title
		if(redirectUrl != "") {
			content += "\n\n" + redirectUrl
		} //end if
		content += "\n"
	} //end if else
	//--
	httpHeadersCacheControl(w, r, -1, "", CACHE_CONTROL_NOCACHE)
	//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
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


func httpStatusERR(w http.ResponseWriter, r *http.Request, code uint16, messageText string, outputHtml bool) {
	//--
	var title string = ""
	var displayAuthLogo bool = false
	switch(code) {
		case 400:
			title = HTTP_STATUS_400
			break
		case 401:
			title = HTTP_STATUS_401
			displayAuthLogo = true
			break
		case 403:
			title = HTTP_STATUS_403
			displayAuthLogo = true
			break
		case 404:
			title = HTTP_STATUS_404
			break
		case 410:
			title = HTTP_STATUS_410
			break
		case 429:
			title = HTTP_STATUS_429
			displayAuthLogo = true
			break
		case 500:
			title = HTTP_STATUS_500
			break
		case 501:
			title = HTTP_STATUS_501
			break
		case 502:
			title = HTTP_STATUS_502
			break
		case 503:
			title = HTTP_STATUS_503
			break
		case 504:
			title = HTTP_STATUS_504
			break
		default:
			log.Println("[ERROR] httpStatusERR: Invalid Status Code:", code, "FallBack to HTTP Status 500")
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
		content = assets.HtmlStatusPage(title, messageText, displayAuthLogo)
	} else { // text
		content += title
		if(messageText != "") {
			content += "\n\n" + messageText
		} //end if
		content += "\n"
	} //end if else
	//--
	httpHeadersCacheControl(w, r, -1, "", CACHE_CONTROL_NOCACHE)
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

func HttpStatus401(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 401, messageText, outputHtml)
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

func HttpStatus410(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 410, messageText, outputHtml)
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

func HttpStatus501(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 501, messageText, outputHtml)
	//--
} //END FUNCTION

func HttpStatus502(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 502, messageText, outputHtml)
	//--
} //END FUNCTION

func HttpStatus503(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 503, messageText, outputHtml)
	//--
} //END FUNCTION

func HttpStatus504(w http.ResponseWriter, r *http.Request, messageText string, outputHtml bool) {
	//--
	httpStatusERR(w, r, 504, messageText, outputHtml)
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
	var rAddr string = r.RemoteAddr
	ip, port := smart.GetSafeIpAndPortFromRequestRemoteAddr(r) // this is using r.RemoteAddr
	if(ip == "") {
		err = "ERROR: Empty or Invalid Client Remote Address: `" + rAddr + "`"
		HttpStatus500(w, r, err, outputHtml)
		return err
	} //end if
	//--
	isOkClientRealIp, realClientIp, rawHdrRealIpVal, rawHdrRealIpKey := smart.GetSafeRealClientIpFromRequestHeaders(r) // this is using r.Header.Get() with value from
	if(DEBUG == true) {
		log.Println("[DEBUG] HttpBasicAuthCheck :: realClientIp: `" + realClientIp + "` ; rawHdrRealIpVal: `" + rawHdrRealIpVal + "` ; rawHdrRealIpKey: `" + rawHdrRealIpKey + "`")
	} //end if
	//--
	if(allowedIPs != "") {
		if((ip == "") || (!smart.StrContains(allowedIPs, "<" + ip + ">"))) {
			err = "The access to this service is disabled. The IP: `" + ip + "` is not allowed by current IP Address list ..."
		} //end if
		if(isOkClientRealIp == true) {
			if((realClientIp == "") || (!smart.StrContains(allowedIPs, "<" + realClientIp + ">"))) {
				err = "The access to this service is disabled. The Client IP: `" + realClientIp + "` is not allowed by current IP Address list ..."
			} //end if
		} //end if
		if(err != "") {
			log.Println("[WARNING] HTTP(S) Server :: BASIC.AUTH.IP.DENY [" + authRealm + "] :: Client: `<" + ip + ">` / `<" + realClientIp + ">` is matching the IP Addr Allowed List: `" + allowedIPs + "`")
			HttpStatus403(w, r, err, outputHtml)
			return err
		} //end if
		log.Println("[OK] HTTP(S) Server :: BASIC.AUTH.IP.ALLOW [" + authRealm + "] :: Client: `<" + ip + ">` / `<" + realClientIp + ">` is matching the IP Addr Allowed List: `" + allowedIPs + "`")
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
		log.Println("[DEBUG] HttpBasicAuthCheck :: Auth MemCache Key: `" + cacheKeyCliIpAddr + "` ; Using Proxy Real Client IP:", isAuthMemKeyUsingProxyRealClientIp)
	} //end if
	//--
	memAuthMutex.Lock()
	if(memAuthCache == nil) { // start cache just on 1st auth ... otherwise all scripts using this library will run the cache in background, but is needed only by this method !
		memAuthCache = smartcache.NewCache("smart.httputils.auth.inMemCache", time.Duration(CACHE_CLEANUP_INTERVAL) * time.Second, DEBUG_CACHE)
	} //end if
	memAuthMutex.Unlock()
	//--
	if(DEBUG_CACHE == true) {
		log.Println("[DATA] HttpBasicAuthCheck [" + authRealm + "] :: memAuthCache:", memAuthCache)
	} //end if
	cacheExists, cachedObj, cacheExpTime := memAuthCache.Get(cacheKeyCliIpAddr)
	if(cacheExists == true) {
		if((cachedObj.Id == cacheKeyCliIpAddr) && (len(cachedObj.Data) >= 10)) { // allow max 10 invalid attempts then lock for 5 mins ... for this cacheKeyCliIpAddr
			err = "Invalid Login Timeout for Client: `" + cacheKeyCliIpAddr + "` # Lock Timeout: " + smart.ConvertUInt32ToStr(uint32(CACHE_EXPIRATION)) + " seconds / Try again after: " + time.Unix(cacheExpTime, 0).UTC().Format(smart.DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
			w.Header().Set(HTTP_HEADER_RETRY_AFTER, time.Unix(cacheExpTime, 0).UTC().Format(smart.DATE_TIME_FMT_ISO_STD_GO_EPOCH) + " UTC")
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
		((len(smart.StrTrimWhitespaces(authPassword)) < 7) || (len(authPassword) > 255)) || // {{{SYNC-GO-SMART-AUTH-PASS-LEN}}}
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
			cachedObj.Id = cacheKeyCliIpAddr
			cachedObj.Data = "."
		} else {
			cachedObj.Data += "."
		} //end if
		memAuthCache.Set(cachedObj, uint64(CACHE_EXPIRATION))
		log.Println("[NOTICE] HttpBasicAuthCheck: Set-In-Cache: AUTH.FAILED [" + authRealm + "] for Client: `" + cachedObj.Id + "` # `" + cachedObj.Data + "` @", len(cachedObj.Data))
		//-- {{{SYNC-GO-HTTP-LOW-CASE-HEADERS}}}
		httpHeadersCacheControl(w, r, -1, "", CACHE_CONTROL_NOCACHE)
		w.Header().Set(HTTP_HEADER_AUTH_AUTHENTICATE, HTTP_HEADER_VALUE_AUTH_TYPE_BASIC + ` realm="` + authRealm + `"`) // the safety of characters in authRealm was checked above !
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
			w.Write([]byte(assets.HtmlStatusPage(HTTP_STATUS_401, "Access to this area requires Authentication", true)))
		} else {
			w.Write([]byte(HTTP_STATUS_401 + "\n"))
		} //end if else
		//--
		log.Printf("[WARNING] HTTP(S) Server :: BASIC.AUTH.FAILED [" + authRealm + "] :: UserName: `" + user + "` # [%s %s %s] %s on Host [%s] for RemoteAddress [%s] on Client [%s] with RealClientIP [%s] %s\n", r.Method, r.URL, r.Proto, "401", r.Host, rAddr, ip + ":" + port, realClientIp, " # HTTP Header Key: `" + rawHdrRealIpKey + "` # HTTP Header Value: `" + rawHdrRealIpVal + "`")
		//--
		return err
		//--
	} //end if
	//--
	if(cacheExists == true) {
		memAuthCache.Unset(cacheKeyCliIpAddr) // unset on 1st successful login
	} //end if
	//--
	log.Println("[OK] HTTP(S) Server :: BASIC.AUTH.SUCCESS [" + authRealm + "] :: UserName: `" + user + "` # From RemoteAddress: `" + ip + "` on Port: `" + port + "`" + " # RealClientIP: `" + realClientIp + "` # Using Proxy Detected RealClientIP: [", isAuthMemKeyUsingProxyRealClientIp, "] # HTTP Header Key: `" + rawHdrRealIpKey + "` # HTTP Header Value: `" + rawHdrRealIpVal + "`")
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
