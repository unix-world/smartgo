
// GO Lang :: SmartGo / Web Server / Utils :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250107.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"time"
	"net/http"

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


func GetUrlQueryParam(r *http.Request, param string) string {
	//--
	param = smart.StrTrimWhitespaces(param)
	if(param == "") {
		return ""
	} //end if
	//--
	return r.URL.Query().Get(param)
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


func GetBasePath() string { // includes trailing slashes
	//--
	return smart.GetHttpProxyBasePath() // if no proxy, this is: `/` ; but under proxy may be the same or as: `/custom-path/`
	//--
} //END FUNCTION


func GetCurrentPath(r *http.Request) string { // this does not include the proxy prefix, it is the internal path
	//--
	return smart.GetHttpPathFromRequest(r)
	//--
} //END FUNCTION


func GetCurrentBrowserPath(r *http.Request) string { // this includes the proxy prefix
	//--
	return smart.GetHttpBrowserPathFromRequest(r)
	//--
} //END FUNCTION


func GetCurrentYear() string {
	//--
	return smart.ConvertIntToStr(time.Now().UTC().Year())
	//--
} //END FUNCTION


func RequestHaveQueryString(r *http.Request) bool {
	//--
	defer smart.PanicHandler()
	//--
	return (len(r.URL.RawQuery) > 0)
	//--
} //END FUNCTION


func GetAuthRealm() string {
	//--
	return httpAuthRealm
	//--
} //END FUNCTION


// #END
