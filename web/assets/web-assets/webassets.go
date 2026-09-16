
// GO Lang :: SmartGo / Web Assets (static) :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260903.2358 :: STABLE

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
	VERSION string = "r.20260903.2358"

	LAST_MODIFIED_DATE_TIME string = "2026-09-03 23:58:07" // must be UTC time, (string) assets last modified ; UPDATE THIS AFTER EACH TIME THE ASSETS ARE MODIFIED !

	CACHED_EXP_TIME_SECONDS uint32 = 2 * 3600 // (int) cache time of assets ; 2h
)

var (
	DEBUG bool = smart.DEBUG
)

//-----


func RenderSrvMainHtmlMarkersFileTpl(mtplAssetFile string, arrobj map[string]string, arrpobj map[string]string, semaphores []string) (string, error) {
	//--
	// this is a server-side template, cannot be used as static, needs a web server to serve the svg/css/js dynamic load assets from the template
	//--
	defer smart.PanicHandler()
	//--
	if(arrobj == nil) {
		arrobj = map[string]string{}
	} //end if
	_, keySemExists := arrobj["SEMAPHORE"]
	if(keySemExists == true) {
		return "", smart.NewError("The `SEMAPHORE` key is special and all semaphores must be set via method `semaphores` parameter")
	} //end if
	//--
	if(arrpobj == nil) {
		arrpobj = map[string]string{}
	} //end if
	_, keyRTExists := arrpobj["RENDER-DATE-TIME"]
	if(keyRTExists == true) {
		return "", smart.NewError("The `RENDER-DATE-TIME` placeholder key is special and reserved for TPL rendering DateTime placeholder")
	} //end if
	//--
	defaultKeys := []string {
		"APP-REALM",
		"FAVICON",
		"TITLE",
		"HEAD-META",
		"HEAD-CSS",
		"HEAD-JS",
		"ALIGN-CENTER",
		"HEADER",
		"MAIN",
		"ASIDE",
		"FOOTER",
		"COOKIE-LIFETIME", // default is: 0 (session)
		"COOKIE-DOMAIN", // defaul is empty
		"COOKIE-SAMESITE", // default is: Lax
		"MODAL-BOX-PROTECTED",
		"NOTIFY-LOAD-ERROR",
		"AUTORUN-DELAY-MSEC", // milliseconds ; this is used just in TPL QUnit by now, set it default to 0 as no-autorun (seconds)
		"TIMEOUT-EXECUTION-SEC", // seconds ; this is used just in TPL QUnit by now, set it default to 120 (seconds)
		"DEBUG-MODE",
	}
	//--
	for _, v := range defaultKeys {
		_, keyExists := arrobj[v]
		if(keyExists == false) {
			arrobj[v] = "" // if key does not exists initialize
		} //end if
	} //end if
	//--
	if(arrobj["APP-REALM"] == "") {
		appNameSpace, _ := smart.AppGetNamespace()
		arrobj["APP-REALM"] = appNameSpace
	} //end if
	//--
	if(arrobj["COOKIE-LIFETIME"] == "") {
		arrobj["COOKIE-LIFETIME"] = "0"
	} //end if
	if(arrobj["COOKIE-DOMAIN"] == "") {
		arrobj["COOKIE-DOMAIN"] = smart.GetCookieDefaultDomain()
	} //end if
	if(arrobj["COOKIE-SAMESITE"] == "") {
		arrobj["COOKIE-SAMESITE"] = smart.GetCookieDefaultSameSitePolicy()
	} //end if
	//--
	if(arrobj["MODAL-BOX-PROTECTED"] != "false") {
		arrobj["MODAL-BOX-PROTECTED"] = "true"
	} //end if
	if(arrobj["NOTIFY-LOAD-ERROR"] != "true") {
		arrobj["NOTIFY-LOAD-ERROR"] = "false"
	} //end if
	//--
	if(arrobj["AUTORUN-DELAY-MSEC"] == "") {
		arrobj["AUTORUN-DELAY-MSEC"] = "0" // milliseconds ; zero means no autorun
	} //end if
	if(arrobj["TIMEOUT-EXECUTION-SEC"] == "") {
		arrobj["TIMEOUT-EXECUTION-SEC"] = "120" // seconds
	} //end if
	//--
	if(arrobj["DEBUG-MODE"] == "") {
		if((DEBUG == true) || (smart.DEBUG == true)) {
			arrobj["DEBUG-MODE"] = "yes"
		} //end if
	} //end if
	//--
	arrobj["BASE-HREF"] = smart.GetHttpProxyBasePath() // {{{SYNC-SRV-ASSETS-BASEPATH}}} ; must use HTML BasePath as prefix (default is /), to work with advanced tail dirs routing
	arrobj["SEMAPHORE"] = smart.StrToLower(smart.StrTrimWhitespaces(smart.SmartArrToList(semaphores, false))) // this key is special and is controlled separately
	arrobj["LANG"] = smart.StrToLower(smart.DEFAULT_LANGUAGE)
	arrobj["RELEASE-HASH"] = smart.Crc32bB36(smart.VERSION + smart.ASCII_BELL + smart.DateNowNoTimeUtc())
	arrobj["TIME-DATE-START"] = smart.DateNowLocal()
	//--
	arrpobj["RENDER-DATE-TIME"] = smart.EscapeHtml(smart.DateNowUtc()) // placeholders are not escaped !
	//--
	return smart.RenderMainHtmlMarkersFileTpl(smart.EFS_PREFIX + mtplAssetFile, arrobj, arrpobj, &assets)
	//--
} //END FUNCTION


func RenderSrvMarkersFileTpl(mtplAssetFile string, arrobj map[string]string) (string, error) {
	//--
	// this is a server-side template, cannot be used as static, needs a web server to serve the svg/css/js dynamic load assets from the template
	//--
	defer smart.PanicHandler()
	//--
	return smart.RenderMarkersFileTpl(smart.EFS_PREFIX + mtplAssetFile, arrobj, &assets)
	//--
} //END FUNCTION


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
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "# Trying to Read the Asset: `" + path + "` ...")
	} //end if
	//--
	if(smart.PathIsBackwardUnsafe(path) == true) {
		log.Println("[LOG]", smart.CurrentFunctionName(), "# Failed to Read Asset: `" + path + "` # unsafe backward path")
		return ""
	} //end if
	path = smart.SafePathFixSeparator(path) // do always, not os context ToSlash !
	path = smart.StrTrimWhitespaces(smart.StrTrim(path, "/ ")) // remove `/` and space + all whitespaces
	if(path == "") {
		log.Println("[LOG]", smart.CurrentFunctionName(), "# Failed to Read Asset: `" + path + "` # empty path")
		return ""
	} //end if
	if(!smart.StrStartsWith(path, "lib/")) {
		log.Println("[LOG]", smart.CurrentFunctionName(), "# Failed to Read Asset: `" + path + "` # path must start with `lib/`")
		return ""
	} //end if
	path = smart.StrTrimWhitespaces(smart.StrTrim(path, "/ ")) // remove `/` and space + all whitespaces
	if((path == "") || (path == ".") || (path == "..") || (path == "/")) {
		log.Println("[LOG]", smart.CurrentFunctionName(), "# Failed to Read Asset: `" + path + "` # unsupported path")
		return ""
	} //end if
	if(smart.PathIsAbsolute(path) == true) {
		log.Println("[LOG]", smart.CurrentFunctionName(), "# Failed to Read Asset: `" + path + "` # not a relative path")
		return ""
	} //end if
	if(smart.PathIsSafeValidSafePath(path) != true) {
		log.Println("[LOG]", smart.CurrentFunctionName(), "# Failed to Read Asset: `" + path + "` # unsafe path")
		return ""
	} //end if
	//--
	content, err := smart.SafePathEmbedFileRead(&assets, path)
	if(err != nil) {
		log.Println("[LOG]", smart.CurrentFunctionName(), "# Failed to Read Asset: `" + path + "` #", err) // mostly will cover 404
		return ""
	} //end if
	if(content == nil) {
		log.Println("[LOG]", smart.CurrentFunctionName(), "# Failed to Read Asset: `" + path + "` # Content is Empty") // will also cover 404
		return ""
	} //end if
	//--
	if(DEBUG == true) {
		log.Println("[DATA]", smart.CurrentFunctionName(), "# Reading Asset: `" + path + "` [DONE] :: ContentLength=", len(content), "bytes")
	} //end if
	//--
	return string(content)
	//--
} //END FUNCTION


//-----


func HtmlNotificationMessage(typ string, isHtml bool, msg string) string {
	//--
	typ = smart.StrToLower(smart.StrTrimWhitespaces(typ))
	//--
	if(isHtml == false) {
		msg = smart.EscapeHtml(msg)
	} //end if
	//--
	var cssClass string = ""
	switch(typ) {
		case "question":
			cssClass = "operation_question"
			break
		case "notice":
			cssClass = "operation_notice"
			break
		case "ok": fallthrough
		case "info":
			cssClass = "operation_info"
			break
		case "warn":
			cssClass = "operation_warn"
			break
		case "fail": fallthrough
		case "error":
			cssClass = "operation_error"
			break
		case "success":
			cssClass = "operation_success"
			break
		case "important":
			cssClass = "operation_important"
			break
		case "result":
			cssClass = "operation_result"
			break
		case "display":
			cssClass = "operation_display"
			break
		case "hint":
			cssClass = "operation_hint"
			break
		default:
			cssClass = "" // N/A
			log.Println("[WARNING]", smart.CurrentFunctionName(), "Invalid Type: `" + typ + "`")
	} //end switch
	//--
	return smart.RenderMarkersTpl(HTML_TPL_NOTIFICATION, map[string]string{
		"TYPE": 		typ,
		"CSS-CLASS": 	cssClass,
		"MESSAGE-HTML": msg,
	})
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
		log.Println("[WARNING]", smart.CurrentFunctionName(), "# requires a non-empty Title !")
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
		"URL-HOMEPAGE": smart.GetHttpProxyBasePath(),
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
		assetsAll = append(assetsAll, TAG_DATA_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_DATA_CSS_END)
	} //end if
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/css/toolkit/ux-toolkit.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_DATA_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_DATA_CSS_END)
	} //end if
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/css/toolkit/ux-toolkit-responsive.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_DATA_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_DATA_CSS_END)
	} //end if
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/core/css/custom.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_DATA_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_DATA_CSS_END)
	} //end if
	theCss = smart.StrTrimWhitespaces(ReadWebAsset("lib/core/css/notifications.css"))
	if(theCss != "") {
		assetsAll = append(assetsAll, TAG_DATA_CSS_START + smart.EscapeHtml(smart.EscapeUrl(theCss)) + TAG_DATA_CSS_END)
	} //end if
	theCss = "" // clear
	//-- # end: sync with app-go.css
	if(loadjs == true) {
		var jsSmarSettings string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/settings.js"))
		assetsAll = append(assetsAll, TAG_DATA_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmarSettings)) + TAG_DATA_JS_END)
		var jsSmartUtilsCore string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/core_utils.js"))
		assetsAll = append(assetsAll, TAG_DATA_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsCore)) + TAG_DATA_JS_END)
		var jsSmartUtilsDate string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/date_utils.js"))
		assetsAll = append(assetsAll, TAG_DATA_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsDate)) + TAG_DATA_JS_END)
		var jsSmartUtilsCrypt string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/crypt_utils.js"))
		assetsAll = append(assetsAll, TAG_DATA_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsCrypt)) + TAG_DATA_JS_END)
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
	TEXT_CONTENT_HEADER string = "text/plain; charset=" + smart.CHARSET 		// keep separate, can be used also by HTTP Headers: Content-Type
	HTML_CONTENT_HEADER string = "text/html; charset="  + smart.CHARSET 		// keep separate, can be used also by HTTP Headers: Content-Type
	JSON_CONTENT_HEADER string = "application/json; charset="  + smart.CHARSET 	// keep separate, can be used also by HTTP Headers: Content-Type
	XML_CONTENT_HEADER 	string = "application/xml; charset="  + smart.CHARSET 	// keep separate, can be used also by HTTP Headers: Content-Type

	HTML_META_CHAREQUIV string = `<meta charset="` + smart.CHARSET + `">` + "\n" + `<meta http-equiv="Content-Type" content="` + HTML_CONTENT_HEADER + `">`
	HTML_META_VIEWPORT 	string = `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
	HTML_META_GENERATOR string = `<meta name="generator" content="Smart.Framework.Go">`
	HTML_META_FAVICON 	string = `<link rel="icon" href="` + smart.DATA_URL_EMPTY_PREFIX + `">`

	TAG_BASE_HREF_START string = `<base href="`
	TAG_BASE_HREF_END 	string = `">`

	TAG_CSS_START 		string = `<link rel="stylesheet" type="text/css" href="`
	TAG_CSS_END 		string = `" media="all">`
	TAG_JS_START 		string = `<script src="`
	TAG_JS_END 			string = `"></script>`

	TAG_DATA_CSS_START 	string = TAG_CSS_START + smart.DATA_URL_CSS_PREFIX
	TAG_DATA_CSS_END 	string = TAG_CSS_END
	TAG_DATA_JS_START 	string = TAG_JS_START + smart.DATA_URL_JS_PREFIX
	TAG_DATA_JS_END 	string = TAG_JS_END

	TAG_COMMENT_HEAD_JS_CSS string = "<!-- Head: Css / Js -->"

	HTML_TPL_NOTIFICATION 	string = `<!-- require: notifications.css --><div title="[###TYPE|ucfirst|html###]" class="[###CSS-CLASS|html###]">[###MESSAGE-HTML###]</div>`

	HTML_TPL_STATUS string = `<!DOCTYPE html>
<!-- TPL.SmartGo.STATUS -->
<html>
<head>
` + HTML_META_CHAREQUIV + `
` + HTML_META_VIEWPORT + `
` + HTML_META_GENERATOR + `
` + HTML_META_FAVICON + `
<title>[###TITLE-TEXT|html###]</title>
<style>
* { font-family: 'IBM Plex Sans', 'Noto Sans', arial, sans-serif; font-smooth: always; }
body { background-color: #FFFFFF; color: #333333; }
a { color: #333333; text-decoration-line: dotted !important; text-decoration-thickness: 0.5px !important; text-decoration-skip-ink: auto !important; }
hr { height: 1px; border: none 0; border-top: 1px solid #CCCCCC; }
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
<div align="left">&nbsp;<a href="[###URL-HOMEPAGE|html###]">Return to MainPage</a>&nbsp;</div>
<div align="right">&nbsp;<small id="server-signature"><b>Smart.Framework.Go</b> :: WebApp</small>&nbsp;</div>
<br>
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
` + HTML_META_VIEWPORT + `
` + HTML_META_GENERATOR + `
<title>[###TITLE|html###]</title>
` + HTML_META_FAVICON + `
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
` + HTML_META_VIEWPORT + `
` + HTML_META_GENERATOR + `
<title>[###TITLE|html###]</title>
` + `<link rel="icon" href="[###FAVICON|html###]">` + `
[:::HEAD-CSS-JS:::]
[###HEAD-HTML###]
</head>
<body>
[###BODY-HTML###]
</body>
</html>
<!-- #end TPL -->
`

	// sync with default-dark.css
	HTML_CSS_STYLE_PREFER_COLOR_DARK 	string = `<style>@media (prefers-color-scheme: dark) { body { background-color: #2E2E2E; color: #F8F8F8; } a, a:link, a:visited, a:hover { color: #F8F8F8; } hr { height: 1px; border: none 0; border-top: 1px dashed #888888; } }</style>`

	HTML_META_ROBOTS_NOINDEX 			string = `<meta name="robots" content="noindex">`
	HTML_META_ROBOTS_NOINDEX_NOFOLLOW 	string = `<meta name="robots" content="noindex, nofollow">`

	HTML_META_ROBOTS_INDEX 				string = `<meta name="robots" content="index">`
	HTML_META_ROBOTS_INDEX_FOLLOW 		string = `<meta name="robots" content="index, follow">`
)


//-----


// #END
