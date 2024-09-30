
// GO Lang :: SmartGo / Web Server / Routing-Defaults :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240930.1531 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"net/http"

	smart 			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web/assets/web-assets"
	srvassets 		"github.com/unix-world/smartgo/web/assets/srv-assets"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)


//-- info page (html)
var RouteHandlerInfoPage HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (code uint16, content string, contentFileName string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	// route: /info
	//--
	defer smart.PanicHandler() // safe recovery handler
	remoteAddr, remotePort := smart.GetHttpRemoteAddrIpAndPortFromRequest(r)
	_, realClientIp, _, _ := smart.GetHttpRealClientIpFromRequestHeaders(r)
	dom, port, _ := smart.GetHttpDomainAndPortFromRequest(r)
	baseDom, _ := smart.GetBaseDomainFromDomain(dom)
	var proxyRealIpKey string = smart.GetHttpProxyRealClientIpHeaderKey()
	if(proxyRealIpKey == "") {
		proxyRealIpKey = "No:Proxy"
	} else {
		proxyRealIpKey = "Proxy:" + proxyRealIpKey
	} //end if
	code = 200
	var headHtml string = ""
	var bodyHtml string = "<h1>" + "Server Info" + "</h1>" + "<h4>" + smart.StrNl2Br(smart.EscapeHtml(TheStrSignature)) + "</h4>"
	bodyHtml += "Visitor Real-IP [" + smart.EscapeHtml(proxyRealIpKey) + "] is: <b>`" + smart.EscapeHtml(realClientIp) + "`</b> ; Remote-IP (Host:Port) is: " + smart.EscapeHtml("`" + remoteAddr + "`:`" + remotePort + "`") + "<br>"
	bodyHtml += "Visitor UserAgent: <i>`" + smart.EscapeHtml(smart.GetHttpUserAgentFromRequest(r)) + "`</i>" + "<br>"
	bodyHtml += "Server Protocol: <b>`" + smart.EscapeHtml(smart.GetHttpProtocolFromRequest(r)) + "`</b>" + "<br>"
	bodyHtml += "Server BaseDomain: `" + smart.EscapeHtml(baseDom) + "`" + "<br>"
	bodyHtml += "Server Domain: <b>`" + smart.EscapeHtml(dom) + "`</b>" + "<br>"
	bodyHtml += "Server Port: `" + smart.EscapeHtml(port) + "`" + "<br>"
	bodyHtml += "Server Path: <b>`" + smart.EscapeHtml(smart.GetHttpBrowserPathFromRequest(r)) + "`</b>" + " ; Served GO Path: `" + smart.EscapeHtml(smart.GetHttpPathFromRequest(r)) + "`" + "<br>" // under proxy may differ
	bodyHtml += "Server QueryString: `" + smart.EscapeHtml(smart.GetHttpQueryStringFromRequest(r)) + "`" + "<br>"
	// TODO: have method to get also: Proxy IP (if used) ; Go Server Port (may differ from the above external port)
	bodyHtml += `<hr>`
	bodyHtml += `<i class="sfi sfi-info sfi-3x"></i>`
	bodyHtml += `<img src="lib/framework/img/golang-logo.svg" height="64" style="margin-top:-24px; margin-left:12px;">`
	bodyHtml += "<hr>"
	bodyHtml += `<div style="font-size:0.75rem; color:#CCCCDD; text-align:right;">&copy; 2023-` + smart.EscapeHtml(GetCurrentYear()) + ` unix-world.org</div>`
	content = srvassets.HtmlServerTemplate(TheStrSignature, headHtml, bodyHtml)
	contentFileName = "index.html"
	//-- optionals
	contentDisposition = ""
	cacheExpiration = -1
	cacheLastModified = ""
	cacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
	headers = map[string]string{}
	headers["Z-Srv-Info"] = TheStrSignature
	//--
	return
}


//-- status page (html)
var RouteHandlerStatusPage HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (code uint16, content string, contentFileName string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	// route: /status
	//--
	defer smart.PanicHandler() // safe recovery handler
	code = 202
	var headHtml string = "<style>" + "\n" + "div.status { text-align:center; margin:10px; cursor:help; }" + "\n" + "div.signature { background:#778899; color:#FFFFFF; font-size:2rem; font-weight:bold; text-align:center; border-radius:3px; padding:10px; margin:20px; }" + "\n" + "</style>"
	var bodyHtml string = `<div class="status"><img alt="status:svg" title="Service Status: Up and Running ..." width="48" height="48" src="data:image/svg+xml,` + smart.EscapeHtml(smart.EscapeUrl(assets.ReadWebAsset("lib/framework/img/loading-spin.svg"))) + `"></div>` + "\n" + `<div class="signature">` + "\n" + "<pre>" + "\n" + smart.EscapeHtml(TheStrSignature) + "</pre>" + "\n" + "</div>"
	content = assets.HtmlStandaloneTemplate(TheStrSignature, headHtml, bodyHtml)
	contentFileName = "status.html"
	//-- optionals
//	contentDisposition = ""
//	cacheExpiration = -1
//	cacheLastModified = ""
//	cacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
//	headers = nil
	//--
	return
}


//-- version page (json)
var RouteHandlerVersionPage HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (code uint16, content string, contentFileName string, contentDisposition string, cacheExpiration int, cacheLastModified string, cacheControl string, headers map[string]string) {
	//--
	// route: /version
	//--
	defer smart.PanicHandler() // safe recovery handler
	code = 203
	ver := versionStruct{Version:TheStrSignature, Copyright:SIGNATURE}
	content = smart.JsonNoErrChkEncode(ver, false, false)
	contentFileName = "version.json"
	//-- optionals
//	contentDisposition = ""
//	cacheExpiration = -1
//	cacheLastModified = ""
//	cacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
//	headers = nil
	//--
	return
}


// #END
