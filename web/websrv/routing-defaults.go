
// GO Lang :: SmartGo / Web Server / Routing-Defaults :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250207.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"net/http"

	"io"
	"os"

	smart 			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web/assets/web-assets"
	srvassets 		"github.com/unix-world/smartgo/web/assets/srv-assets"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)


//-- home page (html)
var RouteHandlerHomePage HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (response HttpResponse) {
	//--
	// route: /
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	response.StatusCode = 200
	const title string = "WebApp"
	var headHtml string = assets.HTML_CSS_STYLE_PREFER_COLOR_DARK + "\n" + "<style>" + "\n" + "div.app { text-align:center; margin:20px; } div.app * { color: #ED2839 !important; }" + "\n" + "</style>"
	var bodyHtml string = `<center><div class="app" style="background:#FFFFFF; width:552px; border-radius:7px;">` + "<h1>" + smart.EscapeHtml(TheStrName) + "</h1>" + "\n" + `<img alt="app:svg" title="` + smart.EscapeHtml(title) + `" width="512" height="512" src="` + smart.EscapeHtml(assets.GetAppLogo(false)) + `"></div></center>` + "\n"
	response.ContentBody = assets.HtmlStandaloneFaviconTemplate(title, headHtml, bodyHtml, false, assets.GetAppLogo(true)) // skip js
	response.ContentFileName = "webapp.html"
	//-- optionals
	response.ContentDisposition = ""
	response.CacheExpiration = -1
	response.CacheLastModified = ""
	response.CacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
	response.Headers = nil
	response.Cookies = nil
	response.LogMessage = ""
	//--
	return
	//--
} //end fx


//-- favicon (streaming) page (svg)
var RouteHandlerFaviconStream HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (response HttpResponse) {
	//--
	// route: /favicon
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	response.Headers = map[string]string{}
	response.Headers["Z-Content"] = "Streaming"
	//--
	var fName string = "favicon.svg"
	var fPath string = WEB_PUBLIC_RELATIVE_ROOT_PATH + fName
	if(!smart.PathIsFile(fPath)) {
		response.StatusCode = 500
		response.ContentBody = "Streaming File cannot be found: `" + fName + "`"
		response.ContentFileName = "500.html"
		return
	} //end if
	response.ContentFileName = fName
	response.ContentStream = func() (ioReadStream io.Reader) {
		ioReadStream, fErr := os.Open(fPath)
		if(fErr != nil) {
			log.Println("[ERROR]", "Streaming Handler File `" + fPath + "` Open Error", fErr)
			return
		} //end if
		return
	} //end fx
	//--
	return
	//--
} //end fx


//-- info page (html)
var RouteHandlerInfoPage HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (response HttpResponse) {
	//--
	// route: /info
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	remoteAddr, remotePort := GetVisitorRemoteIpAddrAndPort(r)
	_, realClientIp := GetVisitorRealIpAddr(r)
	basedom, dom, port, _ := GetBaseDomainDomainPort(r)
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
	response.StatusCode = 208
	const title string = "Service Info"
	var headHtml string = assets.HTML_META_ROBOTS_NOINDEX + "\n" + assets.HTML_CSS_STYLE_PREFER_COLOR_DARK
	var bodyHtml string = `<h1 style="display:inline-block;">`
//	bodyHtml += `<i class="sfi sfi-info sfi-3x" style="color:#DDDDDD!important;"></i>` // Sfi Font is N/A on standalone assets template
//	bodyHtml += "&nbsp;"
	bodyHtml += smart.EscapeHtml(title)
	bodyHtml += `</h1>`
	bodyHtml += `<h4>` + smart.Nl2Br(smart.EscapeHtml(TheStrSignature)) + `</h4>`
	bodyHtml += `<hr>`
	bodyHtml += "Client Real-IP [" + smart.EscapeHtml(proxyRealIpStatus) + "] is: <b>`" + smart.EscapeHtml(realClientIp) + "`</b> ; Remote-IP (Host:Port) is: " + smart.EscapeHtml("`" + remoteAddr + "`:`" + remotePort + "`") + "<br>"
	bodyHtml += "Client UserAgent: <i>`" + smart.EscapeHtml(signature) + "`</i>" + "<br>"
	bodyHtml += `<div style="margin-top:4px; margin-bottom:12px;" title="` + smart.EscapeHtml("Client Browser Class: " + "`" + cls + "`" + " ; Client is Mobile: " + "`" + isMobile + "`") + `">`
	bodyHtml += "\n"
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetClientBwLogo(bw, true)) + `" height="64" style="margin-right:12px; cursor:help;" alt="image-cli-bw" title="Client Browser: ` + smart.EscapeHtml("`" + bw + "`") + `">`
	bodyHtml += "\n"
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetClientOSLogo(os, true)) + `" height="64" style="margin-right:12px; cursor:help;" alt="image-cli-os" title="Client OS: ` + smart.EscapeHtml("`" + os + "`") + `">`
	bodyHtml += "\n"
	bodyHtml += `</div>`
	bodyHtml += `<hr>`
	bodyHtml += "Server Proxy: <b>`" + smart.EscapeHtml(proxySetDetected) + "`</b>" + "<br>"
	bodyHtml += "Server Protocol: <b>`" + smart.EscapeHtml(smart.GetHttpProtocolFromRequest(r)) + "`</b>" + "<br>"
	bodyHtml += "Server BaseDomain: `" + smart.EscapeHtml(basedom) + "`" + "<br>"
	bodyHtml += "Server Domain: <b>`" + smart.EscapeHtml(dom) + "`</b>" + "<br>"
	bodyHtml += "Server Port: `" + smart.EscapeHtml(port) + "`" + "<br>"
	bodyHtml += "Server Base Path: <b>`" + smart.EscapeHtml(GetBaseBrowserPath()) + "`</b>" + " ; Internal Route Base Path: `" + smart.EscapeHtml(GetBasePath()) + "`" + "<br>" // under proxy may differ
	bodyHtml += "Server Path: <b>`" + smart.EscapeHtml(GetCurrentBrowserPath(r)) + "`</b>" + " ; Internal Route Path: `" + smart.EscapeHtml(GetCurrentPath(r)) + "`" + "<br>" // under proxy may differ
	bodyHtml += "Server QueryString: `" + smart.EscapeHtml(smart.GetHttpQueryStringFromRequest(r)) + "`" + "<br>"
	bodyHtml += `<div style="margin-top:4px; margin-bottom:12px;">`
	bodyHtml += "\n"
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetProxyLogo(proxySetDetected, false)) + `" height="64" style="margin-right:12px; cursor:help;" alt="proxy-logo" title="Proxy: ` + smart.EscapeHtml("`" + proxySetDetected + "`") + `">`
	bodyHtml += "\n"
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetSfLogo(false)) + `" height="64" style="margin-right:12px; cursor:help;" alt="sf-logo" title="Platform: ` + smart.EscapeHtml("`" + smart.NAME + " (" + smart.DESCRIPTION + ") " + smart.VERSION + "`") + `">`
	bodyHtml += "\n"
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetGolangLogo(false)) + `" height="64" style="margin-right:12px; cursor:help;" alt="golang-logo" title="Runtime: ` + smart.EscapeHtml("`" + smart.CurrentRuntimeVersion() + "`") + `">`
	bodyHtml += "\n"
	bodyHtml += `<img src="` + smart.EscapeHtml(assets.GetOSLogo(false)) + `" height="64" style="margin-right:12px; cursor:help;" alt="os-logo" title="OS / Arch: ` + smart.EscapeHtml("`" + smart.CurrentOSName() + "`" + " / " + "`" + smart.CurrentOSArch() + "`") + `">`
	bodyHtml += "\n"
	bodyHtml += `</div>`
	bodyHtml += `<hr>`
	bodyHtml += `<div style="font-size:0.75rem; color:#CCCCDD; text-align:right;">&copy; 2023-` + smart.EscapeHtml(GetCurrentYear()) + ` unix-world.org</div>`
	response.ContentBody = assets.HtmlStandaloneTemplate(title, headHtml, bodyHtml, true) // load js assets
	response.ContentFileName = "index.html"
	//-- optionals
	response.ContentDisposition = smarthttputils.DISP_TYPE_INLINE // "" is equivalent to smarthttputils.DISP_TYPE_INLINE ; or smarthttputils.DISP_TYPE_ATTACHMENT
	response.CacheExpiration = -1
	response.CacheLastModified = ""
	response.CacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
	response.Headers = map[string]string{}
	response.Headers["Z-Date-Time-UTC"] = smart.DateNowIsoUtc() // no need to be escaped, will be escaped later by httpStatusOKX() using: HttpSafeHeaderKey() and HttpSafeHeaderValue()
	response.Cookies = nil
	response.LogMessage = ""
	//--
	return
	//--
} //end fx


//-- status page (html)
var RouteHandlerStatusPage HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (response HttpResponse) {
	//--
	// route: /status
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	response.StatusCode = 202
	const title string = "Service Status: Up and Running ..."
	var headHtml string = assets.HTML_META_ROBOTS_NOINDEX + "\n" + assets.HTML_CSS_STYLE_PREFER_COLOR_DARK + "\n" + "<style>" + "\n" + "div.status { text-align:center; margin:10px; cursor:help; }" + "\n" + "div.signature { background:#778899; color:#FFFFFF; font-size:2rem; font-weight:bold; text-align:center; border-radius:3px; padding:10px; margin:20px; }" + "\n" + "</style>"
	var bodyHtml string = `<div class="status"><img alt="status:svg" title="` + smart.EscapeHtml(title) + `" width="48" height="48" src="` + smart.EscapeHtml(assets.GetSvgAsset("lib/framework/img/loading-spin.svg", false)) + `"></div>` + "\n" + `<div class="signature">` + "\n" + "<pre>" + "\n" + `<i class="sfi sfi-info"></i> &nbsp; ` + smart.EscapeHtml(TheStrSignature) + " ... is running" + "\n" + smart.EscapeHtml(smart.DateNowUtc()) + "</pre>" + "\n" + "</div>"
	response.ContentBody = srvassets.HtmlServerTemplate(title, headHtml, bodyHtml, false) // skip js ; contains SFI Icons
	response.ContentFileName = "status.html"
	//-- optionals
//	response.ContentDisposition = ""
//	response.CacheExpiration = -1
//	response.CacheLastModified = ""
//	response.CacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
	response.Headers = map[string]string{}
	response.Headers["Refresh"] = "15" // refresh every 15 seconds
//	response.Cookies = nil
//	response.LogMessage = ""
	//--
	return
	//--
} //end fx


//-- version page (json)
var RouteHandlerVersionPage HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (response HttpResponse) {
	//--
	// route: /version
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	response.StatusCode = 203
	json := versionStruct{
		Platform: 	"`" + smart.NAME + " (" + smart.DESCRIPTION + ") " + smart.VERSION + "`",
		Server: 	TheStrName,
		Version: 	VERSION,
		GoVersion: 	smart.CurrentRuntimeVersion(),
		OsName: 	smart.CurrentOSName(),
		OsArch: 	smart.CurrentOSArch(),
		Copyright: 	SIGNATURE,
	}
	response.ContentBody = smart.JsonNoErrChkEncode(json, false, false)
	response.ContentFileName = "version.json"
	//-- optionals
//	response.ContentDisposition = ""
//	response.CacheExpiration = -1
//	response.CacheLastModified = ""
//	response.CacheControl = smarthttputils.CACHE_CONTROL_NOCACHE
//	response.Headers = nil
//	response.Cookies = nil
//	response.LogMessage = ""
	//--
	return
	//--
} //end fx


// #END
