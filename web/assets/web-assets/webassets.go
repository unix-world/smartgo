
// GO Lang :: SmartGo / Web Assets (static) :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241223.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower versions)
package webassets

import (
	"log"

	smart "github.com/unix-world/smartgo"

	"embed"
)
//go:embed lib/*
var assets embed.FS

//-----

const(
	VERSION string = "r.20241223.2358"

	LAST_MODIFIED_DATE_TIME string = "2024-12-23 17:08:17" // must be UTC time, (string) assets last modified ; UPDATE THIS AFTER EACH TIME THE ASSETS ARE MODIFIED !

	CACHED_EXP_TIME_SECONDS uint32 = 2 * 3600 // (int) cache time of assets ; 2h
)

var (
	DEBUG bool = smart.DEBUG
)

//-----


func GetSvgAsset(img string, asPath bool) string {
	//--
	var out string = img
	if(asPath == false) {
		out = smart.DATA_URL_SVG_IMAGE_PREFIX + smart.EscapeUrl(ReadWebAsset(img))
	} //end if
	//--
	return out
	//--
} //END FUNCTION


//--


func GetAppLogo(asPath bool) string {
	//--
	const img string = "lib/core/img/app/app.svg"
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


func GetAuthLogo(asPath bool) string {
	//--
	const img string = "lib/framework/img/unicorn-auth-logo.svg"
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


func GetServerLogo(asPath bool) string {
	//--
	const img string = "lib/core/img/app/server.svg"
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


func GetMaintenanceLogo(asPath bool) string {
	//--
	const img string = "lib/core/img/app/maintenance.svg"
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


func GetSfLogo(asPath bool) string {
	//--
	const img string = "lib/framework/img/sf-logo.svg"
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


func GetGolangLogo(asPath bool) string {
	//--
	const img string = "lib/framework/img/golang-logo.svg"
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


func GetProxyLogo(proxyIpPort string, asPath bool) string {
	//--
	var img string = "lib/core/img/browser/@smart-robot.svg"
	if(smart.StrTrimWhitespaces(proxyIpPort) != "") {
		img = "lib/framework/img/haproxy-logo.svg"
	} //end if
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


//--


func GetClientBwLogo(bw string, asPath bool) string {
	//--
	bw = smart.StrToLower(smart.StrTrimWhitespaces(bw))
	//--
	var img string = "lib/core/img/browser/xxx.svg"
	switch(bw) {
		case "fox":
			img = "lib/core/img/browser/fox.svg"
			break
		case "smk":
			img = "lib/core/img/browser/smk.svg"
			break
		case "crm":
			img = "lib/core/img/browser/crm.svg"
			break
		case "iee":
			img = "lib/core/img/browser/iee.svg"
			break
		case "sfr":
			img = "lib/core/img/browser/sfr.svg"
			break
		case "wkt":
			img = "lib/core/img/browser/wkt.svg"
			break
		case "eph":
			img = "lib/core/img/browser/eph.svg"
			break
		case "knq":
			img = "lib/core/img/browser/knq.svg"
			break
		case "opr":
			img = "lib/core/img/browser/opr.svg"
			break
		case "moz":
			img = "lib/core/img/browser/moz.svg"
			break
		case "nsf":
			img = "lib/core/img/browser/nsf.svg"
			break
		case "lyx":
			img = "lib/core/img/browser/lyx.svg"
			break
		case "app":
			img = "lib/core/img/browser/nwjs.svg"
			break
		case "@s#":
			img = "lib/core/img/browser/@smart-robot.svg"
			break
		case "bot":
			img = "lib/core/img/browser/bot.svg"
			break
		default:
			// use default, unknown bw
	} //end switch
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


func GetClientOSLogo(os string, asPath bool) string {
	//--
	os = smart.StrToLower(smart.StrTrimWhitespaces(os))
	//--
	var img string = "lib/core/img/os/other-os.svg"
	switch(os) {
		case "win":
			img = "lib/core/img/os/windows-os.svg"
			break
		case "mac":
			img = "lib/core/img/os/mac-os.svg"
			break
		case "lnx":
			img = "lib/core/img/os/linux-generic.svg"
			break
		case "bsd":
			img = "lib/core/img/os/bsd-generic.svg"
			break
		case "sun":
			img = "lib/core/img/os/unix-solaris.svg"
			break
		case "ios":
			img = "lib/core/img/os/mobile/ios.svg"
			break
		case "and":
			img = "lib/core/img/os/mobile/android.svg"
			break
		case "lxm":
			img = "lib/core/img/os/mobile/linux-mobile.svg"
			break
		case "wmo":
			img = "lib/core/img/os/mobile/windows-mobile.svg"
			break
		default:
			// use default, unknown os
	} //end switch
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


//--


func GetOSLogo(asPath bool) string {
	//--
	// if asPath is TRUE, will return as Path ; if asPath is FALSE will return dataImage for embed
	//--
	os := smart.CurrentOSName()
	arch := smart.CurrentOSArch()
	//--
	var img string = "lib/core/img/os/other-os.svg"
	if(arch == "wasm") {
		img = "lib/core/img/os/wasm.svg"
	} else {
		switch(os) {
			case "linux":
				img = "lib/core/img/os/linux-generic.svg"
				break
			case "openbsd":
				img = "lib/core/img/os/bsd-openbsd.svg"
				break
			case "netbsd":
				img = "lib/core/img/os/bsd-netbsd.svg"
				break
			case "freebsd":
				img = "lib/core/img/os/bsd-freebsd.svg"
				break
			case "dragonfly":
				img = "lib/core/img/os/bsd-dragonfly.svg"
				break
			case "illumos": fallthrough
			case "solaris":
				img = "lib/core/img/os/unix-solaris.svg"
				break
			case "darwin":
				img = "lib/core/img/os/mac-os.svg"
				break
			case "windows":
				img = "lib/core/img/os/windows-os.svg"
				break
			case "ios":
				img = "lib/core/img/os/mobile/ios.svg"
				break
			case "android":
				img = "lib/core/img/os/mobile/android.svg"
				break
		//	case "plan9": fallthrough // use other
		//	case "aix": fallthrough // use other
			default:
				// use default, unknown os
		} //end switch
	} //end if
	//--
	return GetSvgAsset(img, asPath)
	//--
} //END FUNCTION


//-----


func ReadWebAsset(path string) string { // OK
	//--
	defer smart.PanicHandler()
	//--
	if(DEBUG == true) {
		log.Println("[DEBUG] " + smart.CurrentFunctionName() + ": Trying to Read the Asset: `" + path + "` ...")
	} //end if
	//--
	if(smart.PathIsBackwardUnsafe(path) == true) {
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": Failed to Read Asset: `" + path + "` # unsafe backward path")
		return ""
	} //end if
	path = smart.SafePathFixSeparator(path) // do always, not os context ToSlash !
	path = smart.StrTrimWhitespaces(smart.StrTrim(path, "/ ")) // remove `/` and space + all whitespaces
	if(path == "") {
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": Failed to Read Asset: `" + path + "` # empty path")
		return ""
	} //end if
	if(!smart.StrStartsWith(path, "lib/")) {
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": Failed to Read Asset: `" + path + "` # path must start with `lib/`")
		return ""
	} //end if
	path = smart.StrTrimWhitespaces(smart.StrTrim(path, "/ ")) // remove `/` and space + all whitespaces
	if((path == "") || (path == ".") || (path == "..") || (path == "/")) {
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": Failed to Read Asset: `" + path + "` # unsupported path")
		return ""
	} //end if
	if(smart.PathIsAbsolute(path) == true) {
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": Failed to Read Asset: `" + path + "` # not a relative path")
		return ""
	} //end if
	if(smart.PathIsSafeValidSafePath(path) != true) {
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": Failed to Read Asset: `" + path + "` # unsafe path")
		return ""
	} //end if
	//--
	content, err := assets.ReadFile(path)
	if(err != nil) {
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": Failed to Read Asset: `" + path + "` #", err) // mostly will cover 404
		return ""
	} //end if
	//--
	if(DEBUG == true) {
		log.Println("[DATA] " + smart.CurrentFunctionName() + ": Reading Asset: `" + path + "` [DONE] :: ContentLength=", len(content), "bytes")
	} //end if
	//--
	return string(content)
	//--
} //END FUNCTION


//-----


func HtmlStatusPage(titleText string, messageText string, displayAuthLogo bool, extraHtml string) string {
	//--
	defer smart.PanicHandler()
	//--
	titleText = smart.StrTrimWhitespaces(titleText)
	messageText = smart.StrTrimWhitespaces(messageText)
	extraHtml = smart.StrTrimWhitespaces(extraHtml)
	//--
	if(titleText == "") {
		titleText = "Untitled"
		log.Println("[WARNING] " + smart.CurrentFunctionName() + ": requires a non-empty Title !")
	} //end if
	if(messageText == "") {
		messageText = "Unknown Error ..."
	} //end if
	if(extraHtml != "") {
		extraHtml = "<hr>" + "\n" + extraHtml
	} else {
		extraHtml = "<!-- Ex: N/A -->"
	} //end if
	//--
	var authLogo string = ""
	if(displayAuthLogo == true) {
		authLogo = `<img alt="logo-unicorn" title="Smart.Unicorn Secure Authentication" style="cursor:help;" width="64" height="64" src="` + smart.EscapeHtml(GetAuthLogo(false)) + `">` + " &nbsp;\n"
	} //end if
	//--
	arr := map[string]string{ // no server content (all embedded) to avoid loops 9ex: 404 loop
		"TITLE-TEXT": 	titleText,
		"MESSAGE-TEXT": messageText,
		"FOOTER-HTML": 	`<img alt="logo-server" title="Go Standalone Web Server" style="cursor:help;" width="64" height="64" src="` + smart.EscapeHtml(GetServerLogo(false)) + `">` + " &nbsp;\n" +
						`<img alt="logo-runtime" title="Built with Go Lang" style="cursor:help;" width="64" height="64" src="` + smart.EscapeHtml(GetGolangLogo(false)) + `">` + " &nbsp;\n" +
						authLogo +
						`<img alt="logo-framework" title="Smart.Framework.Go" style="cursor:help;" width="64" height="64" src="` + smart.EscapeHtml(GetSfLogo(false)) + `">` + "\n",
	}
	phd := map[string]string{
		"HEAD-EXT-HTML": HTML_CSS_STYLE_PREFER_COLOR_DARK,
		"BODY-EXT-HTML": extraHtml,
	}
	//--
	return smart.RenderMainHtmlMarkersTpl(HTML_TPL_STATUS, arr, phd) + "\n" + "<!-- TPL:Static.Status -->" + "\n"
	//--
} //END FUNCTION


//-----

func HtmlStandaloneTemplate(titleText string, headHtml string, bodyHtml string, loadjs bool) string { // OK: can be used as standalone
	//--
	return htmlStandaloneChooseTemplate(titleText, headHtml, bodyHtml, "", loadjs)
	//--
} //END FUNCTION


func HtmlStandaloneFaviconTemplate(titleText string, headHtml string, bodyHtml string, loadjs bool, favicon string) string { // OK: can be used as standalone with a static favicon as data
	//--
	return htmlStandaloneChooseTemplate(titleText, headHtml, bodyHtml, favicon, loadjs)
	//--
} //END FUNCTION


func htmlStandaloneChooseTemplate(titleText string, headHtml string, bodyHtml string, favicon string, loadjs bool) string {
	//--
	defer smart.PanicHandler()
	//--
	titleText = smart.StrTrimWhitespaces(titleText)
	//--
	headHtml = smart.StrTrimWhitespaces(headHtml)
	if(headHtml == "") {
		headHtml = "<!-- Head Html -->"
	} //end if
	//--
	if(smart.StrTrimWhitespaces(bodyHtml) == "") {
		bodyHtml = "<!-- Body Html -->"
	} //end if
	//--
	arr := map[string]string{
		"TITLE": 		titleText,
		"HEAD-HTML": 	headHtml,
		"BODY-HTML": 	bodyHtml,
	}
	//--
	favicon = smart.StrTrimWhitespaces(favicon)
	var theTpl string = HTML_TPL_DEF
	if(favicon != "") {
		arr["FAVICON"] = favicon
		theTpl = HTML_TPL_FAVICON_DEF
	}
	//--
	var headCssJs string = "<!-- Head: Css / Js -->"
	var assetsAll []string
	assetsAll = append(assetsAll, headCssJs)
	//-- # start: sync with app-go.css
	var theCss string = "" // init
	// No SF Icons in this template !
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/css/default.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_CSS_END)
	} //end if
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/css/toolkit/ux-toolkit.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_CSS_END)
	} //end if
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/css/toolkit/ux-toolkit-responsive.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_CSS_END)
	} //end if
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/core/css/custom.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_CSS_END)
	} //end if
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/core/css/notifications.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_CSS_END)
	} //end if
	theCss = "" // clear
	//-- # end: sync with app-go.css
	if(loadjs == true) {
		var jsSmarSettings string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/settings.js"))
		assetsAll = append(assetsAll, TAG_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmarSettings)) + TAG_JS_END)
		var jsSmartUtilsCore string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/core_utils.js"))
		assetsAll = append(assetsAll, TAG_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsCore)) + TAG_JS_END)
		var jsSmartUtilsDate string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/date_utils.js"))
		assetsAll = append(assetsAll, TAG_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsDate)) + TAG_JS_END)
		var jsSmartUtilsCrypt string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/crypt_utils.js"))
		assetsAll = append(assetsAll, TAG_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsCrypt)) + TAG_JS_END)
	} else {
		assetsAll = append(assetsAll, `<!-- JS: skip -->`)
	} //end if
	//--
	if(len(assetsAll) > 0) {
		headCssJs = smart.Implode("\n", assetsAll)
	} //end if
	//--
	parr := map[string]string{
		"HEAD-CSS-JS": headCssJs,
	}
	//--
	return smart.RenderMainHtmlMarkersTpl(theTpl, arr, parr) + "\n" + "<!-- TPL:static -->" + "\n"
	//--
} //END FUNCTION


//-----


const (
	TEXT_CONTENT_HEADER string = "text/plain; charset=" + smart.CHARSET // keep separate, can be used also by HTTP Headers: Content-Type
	HTML_CONTENT_HEADER string = "text/html; charset="  + smart.CHARSET // keep separate, can be used also by HTTP Headers: Content-Type
	JSON_CONTENT_HEADER string = "application/json; charset="  + smart.CHARSET // keep separate, can be used also by HTTP Headers: Content-Type
	XML_CONTENT_HEADER  string = "application/xml; charset="  + smart.CHARSET // keep separate, can be used also by HTTP Headers: Content-Type

	HTML_META_FAVICON   string = `<link rel="icon" href="` + smart.DATA_URL_EMPTY_PREFIX + `">`
	HTML_META_VIEWPORT  string = `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
	HTML_META_CHAREQUIV string = `<meta charset="` + smart.CHARSET + `"><meta http-equiv="Content-Type" content="` + HTML_CONTENT_HEADER + `">`

	TAG_CSS_START string = `<link rel="stylesheet" type="text/css" href="` + smart.DATA_URL_CSS_PREFIX
	TAG_CSS_END string = `">`
	TAG_JS_START string = `<script src="` + smart.DATA_URL_JS_PREFIX
	TAG_JS_END string = `"></script>`

	HTML_TPL_STATUS string = `<!DOCTYPE html>
<!-- TPL.SmartGo.STATUS -->
<html>
<head>
` + HTML_META_CHAREQUIV + `
` + HTML_META_FAVICON + `
<title>[###TITLE-TEXT|html###]</title>
` + HTML_META_VIEWPORT + `
<style>
* { font-family: 'IBM Plex Sans', 'Noto Sans', arial, sans-serif; font-smooth: always; }
hr { height:1px; border:none 0; border-top:1px solid #CCCCCC; }
h1, h2, h3, h4, h5, h6 { color:#333333; }
div.message { line-height: 36px; text-align: left; font-size: 1.25rem; font-weight: bold; font-style: normal; padding-left: 16px; padding-right: 16px; padding-top: 12px; padding-bottom: 8px; margin-top: 8px; margin-bottom: 8px; max-width: calc(100% - 10px) !important; min-width: 100px; min-height: 40px; height: auto !important; border-radius: 5px; box-sizing: content-box !important; opacity: 1 !important; background-color: #C62828 !important; color: #FFFFFF !important; }
</style>
[:::HEAD-EXT-HTML:::]
</head>
<body>
<h1 style="display:inline; font-size:4rem;">[###TITLE-TEXT|html###]</h1>
<br>
<br>
<hr>
<div class="message">[###MESSAGE-TEXT|html|nl2br###]</div>
[:::BODY-EXT-HTML:::]
<hr>
<small id="server-signature"><b>Smart.Framework.Go</b> :: WebApp</small>
<div align="right" title="` + smart.COPYRIGHT + `">[###FOOTER-HTML###]</div>
<br>
</body>
</html>
<!-- #end TPL -->
`

	HTML_TPL_DEF string = `<!DOCTYPE html>
<!-- TPL.SmartGo.DEF -->
<html>
<head>
` + HTML_META_CHAREQUIV + `
` + HTML_META_FAVICON + `
<title>[###TITLE|html###]</title>
` + HTML_META_VIEWPORT + `
[:::HEAD-CSS-JS:::]
[###HEAD-HTML###]
</head>
<body>
[###BODY-HTML###]
</body>
</html>
<!-- #end TPL -->
`

	HTML_TPL_FAVICON_DEF string = `<!DOCTYPE html>
<!-- TPL.SmartGo.FAV.DEF -->
<html>
<head>
` + HTML_META_CHAREQUIV + `
` + `<link rel="icon" href="[###FAVICON|html###]">` + `
<title>[###TITLE|html###]</title>
` + HTML_META_VIEWPORT + `
[:::HEAD-CSS-JS:::]
[###HEAD-HTML###]
</head>
<body>
[###BODY-HTML###]
</body>
</html>
<!-- #end TPL -->
`

	HTML_CSS_STYLE_PREFER_COLOR_DARK string = `<style>@media (prefers-color-scheme: dark) { body { background-color: #2E2E2E; color: #F8F8F8; } h1, h2, h3, h4, h5, h6 { color: #F8F8F8; } hr { height:1px; border:none 0; border-top:1px dashed #888888; } }</style>`
)


//-----


// #END
