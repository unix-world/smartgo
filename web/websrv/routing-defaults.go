
// GO Lang :: SmartGo / Web Server / Routing-Defaults :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241031.1532 :: STABLE

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
	var proxySetDetected string = smart.GetHttpProxyRealServerHostPortHeaderKey() // Proxy IP:port (if used) ; Go Server Port (may differ from the above external port)
	var proxyRealClientIp string = smart.GetHttpProxyRealClientIpHeaderKey()
	var proxyRealIpStatus string = "NoProxy"
	if(proxyRealClientIp != "") {
		proxyRealIpStatus = "Proxy:" + proxyRealClientIp
	} //end if
	signature := smart.GetHttpUserAgentFromRequest(r)
	bw, cls, os, mb := smart.GetUserAgentBrowserClassOs(signature)
	var isMobile string = "no"
	if(mb == true) {
		isMobile = "yes"
	} //end if
	code = 200
	const title string = "Service Info"
	var headHtml string = ""
	var bodyHtml string = `<h1 style="display:inline-block;">`
	bodyHtml += `<i class="sfi sfi-info sfi-3x" style="color:#DDDDDD!important;"></i>`
	bodyHtml += "&nbsp;"
	bodyHtml += smart.EscapeHtml(title)
	bodyHtml += `</h1>`
	bodyHtml += `<h4>` + smart.StrNl2Br(smart.EscapeHtml(TheStrSignature)) + `</h4>`
	bodyHtml += `<hr>`
	bodyHtml += "Client Real-IP [" + smart.EscapeHtml(proxyRealIpStatus) + "] is: <b>`" + smart.EscapeHtml(realClientIp) + "`</b> ; Remote-IP (Host:Port) is: " + smart.EscapeHtml("`" + remoteAddr + "`:`" + remotePort + "`") + "<br>"
	bodyHtml += "Client UserAgent: <i>`" + smart.EscapeHtml(signature) + "`</i>" + "<br>"
	bodyHtml += `<div style="margin-top:4px; margin-bottom:12px;" title="` + smart.EscapeHtml("Client Browser Class: " + "`" + cls + "`" + " ; Client is Mobile: " + "`" + isMobile + "`") + `">`
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetClientBwLogo(bw, true)) + `" height="64" style="margin-right:12px; cursor:help;" alt="image-cli-bw" title="Client Browser: ` + smart.EscapeHtml("`" + bw + "`") + `">`
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetClientOSLogo(os, true)) + `" height="64" style="margin-right:12px; cursor:help;" alt="image-cli-os" title="Client OS: ` + smart.EscapeHtml("`" + os + "`") + `">`
	bodyHtml += `</div>`
	bodyHtml += `<hr>`
	bodyHtml += "Server Proxy: <b>`" + smart.EscapeHtml(proxySetDetected) + "`</b>" + "<br>"
	bodyHtml += "Server Protocol: <b>`" + smart.EscapeHtml(smart.GetHttpProtocolFromRequest(r)) + "`</b>" + "<br>"
	bodyHtml += "Server BaseDomain: `" + smart.EscapeHtml(baseDom) + "`" + "<br>"
	bodyHtml += "Server Domain: <b>`" + smart.EscapeHtml(dom) + "`</b>" + "<br>"
	bodyHtml += "Server Port: `" + smart.EscapeHtml(port) + "`" + "<br>"
	bodyHtml += "Server Path: <b>`" + smart.EscapeHtml(smart.GetHttpBrowserPathFromRequest(r)) + "`</b>" + " ; Internal Route Path: `" + smart.EscapeHtml(smart.GetHttpPathFromRequest(r)) + "`" + "<br>" // under proxy may differ
	bodyHtml += "Server QueryString: `" + smart.EscapeHtml(smart.GetHttpQueryStringFromRequest(r)) + "`" + "<br>"
	bodyHtml += `<div style="margin-top:4px; margin-bottom:12px;">`
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetProxyLogo(proxySetDetected, false)) + `" height="64" style="margin-right:12px; cursor:help;" alt="proxy-logo" title="Proxy: ` + smart.EscapeHtml("`" + proxySetDetected + "`") + `">`
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetSfLogo(false)) + `" height="64" style="margin-right:12px; cursor:help;" alt="sf-logo" title="Platform: ` + smart.EscapeHtml("`" + smart.NAME + " (" + smart.DESCRIPTION + ") " + smart.VERSION + "`") + `">`
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetGolangLogo(false)) + `" height="64" style="margin-right:12px; cursor:help;" alt="golang-logo" title="Runtime: ` + smart.EscapeHtml("`" + smart.CurrentRuntimeVersion() + "`") + `">`
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetOSLogo(false)) + `" height="64" style="margin-right:12px; cursor:help;" alt="os-logo" title="OS / Arch: ` + smart.EscapeHtml("`" + smart.CurrentOSName() + "`" + " / " + "`" + smart.CurrentOSArch() + "`") + `">`
	bodyHtml += `</div>`
	bodyHtml += `<hr>`
	bodyHtml += `<div style="font-size:0.75rem; color:#CCCCDD; text-align:right;">&copy; 2023-` + smart.EscapeHtml(GetCurrentYear()) + ` unix-world.org</div>`
	content = srvassets.HtmlServerTemplate(title, headHtml, bodyHtml)
	contentFileName = "index.html"
	//-- optionals
	contentDisposition = ""
	cacheExpiration = -1
	cacheLastModified = ""
	cacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
	headers = map[string]string{}
	headers["Z-Date-Time-UTC"] = smart.DateNowIsoUtc() // no need to be escaped, will be escaped later by httpStatusOKX() using: HttpSafeHeaderKey() and HttpSafeHeaderValue()
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
	const title string = "Service Status: Up and Running ..."
	var headHtml string = "<style>" + "\n" + "div.status { text-align:center; margin:10px; cursor:help; }" + "\n" + "div.signature { background:#778899; color:#FFFFFF; font-size:2rem; font-weight:bold; text-align:center; border-radius:3px; padding:10px; margin:20px; }" + "\n" + "</style>"
	var bodyHtml string = `<div class="status"><img alt="status:svg" title="` + smart.EscapeHtml(title) + `" width="48" height="48" src="data:image/svg+xml,` + smart.EscapeHtml(smart.EscapeUrl(assets.ReadWebAsset("lib/framework/img/loading-spin.svg"))) + `"></div>` + "\n" + `<div class="signature">` + "\n" + "<pre>" + "\n" + smart.EscapeHtml(TheStrSignature) + "</pre>" + "\n" + "</div>"
	content = assets.HtmlStandaloneTemplate(title, headHtml, bodyHtml)
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
	ver := versionStruct{
		Version: 	TheStrSignature,
		GoVersion: 	smart.CurrentRuntimeVersion(),
		OsName: 	smart.CurrentOSName(),
		OsArch: 	smart.CurrentOSArch(),
		Copyright: 	SIGNATURE,
	}
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
