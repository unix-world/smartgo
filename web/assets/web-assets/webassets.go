
// GO Lang :: SmartGo / Web Assets (static) :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240928.0102 :: STABLE

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
	VERSION string = "r.20240928.0102"

	LAST_MODIFIED_DATE_TIME string = "2024-09-28 01:02:58" // must be UTC time, (string) assets last modified ; UPDATE THIS AFTER EACH TIME THE ASSETS ARE MODIFIED !

	CACHED_EXP_TIME_SECONDS uint32 = 8 * 3600 // (int) cache time of assets ; 8h

	DEBUG bool = false
)

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


func HtmlStatusPage(titleText string, messageText string, displayAuthLogo bool) string {
	//--
	defer smart.PanicHandler()
	//--
	titleText = smart.StrTrimWhitespaces(titleText)
	messageText = smart.StrTrimWhitespaces(messageText)
	//--
	if(titleText == "") {
		titleText = "Untitled"
		log.Println("[ERROR] " + smart.CurrentFunctionName() + ": requires a non-empty Title !")
	} //end if
	if(messageText == "") {
		messageText = "Unknown Error ..."
	} //end if
	//--
	var authLogo string = ""
	if(displayAuthLogo == true) {
		authLogo = `<img alt="logo-unicorn" title="Smart.Unicorn Secure Authentication" style="cursor:help;" width="64" height="64" src="data:image/svg+xml,` + smart.EscapeUrl(ReadWebAsset("lib/framework/img/unicorn-auth-logo.svg")) + `">` + " &nbsp;\n"
	} //end if
	//--
	arr := map[string]string{ // no server content to avoid loops 9ex: 404 loop)
		"TITLE-TEXT": titleText,
		"MESSAGE-TEXT": messageText,
		"FOOTER-HTML": `<img alt="logo-server" title="Go Standalone Web Server" style="cursor:help;" width="64" height="64" src="data:image/svg+xml,` + smart.EscapeUrl(ReadWebAsset("lib/core/img/app/globe.svg")) + `">` + " &nbsp;\n" +
							`<img alt="logo-runtime" title="Built with Go Lang" style="cursor:help;" width="64" height="64" src="data:image/svg+xml,` + smart.EscapeUrl(ReadWebAsset("lib/framework/img/golang-logo.svg")) + `">` + " &nbsp;\n" +
							authLogo +
							`<img alt="logo-framework" title="Smart.Framework.Go" style="cursor:help;" width="64" height="64" src="data:image/svg+xml,` + smart.EscapeUrl(ReadWebAsset("lib/framework/img/sf-logo.svg")) + `">` + "\n",
	}
	//--
	return smart.RenderMainHtmlMarkersTpl(HTML_TPL_STATUS, arr, nil) + "\n" + "<!-- TPL:Static.Status -->" + "\n"
	//--
} //END FUNCTION


//-----

func HtmlStandaloneTemplate(titleText string, headHtml string, bodyHtml string) string { // OK: can be used as standalone
	//--
	return htmlStandaloneChooseTemplate(titleText, headHtml, bodyHtml, "")
	//--
} //END FUNCTION


func HtmlStandaloneFaviconTemplate(titleText string, headHtml string, bodyHtml string, favicon string) string { // OK: can be used as standalone with a static favicon as data
	//--
	return htmlStandaloneChooseTemplate(titleText, headHtml, bodyHtml, favicon)
	//--
} //END FUNCTION


func htmlStandaloneChooseTemplate(titleText string, headHtml string, bodyHtml string, favicon string) string {
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
	var jsSmarSettings string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/settings.js"))
	assetsAll = append(assetsAll, TAG_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmarSettings)) + TAG_JS_END)
	var jsSmartUtilsCore string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/core_utils.js"))
	assetsAll = append(assetsAll, TAG_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsCore)) + TAG_JS_END)
	var jsSmartUtilsDate string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/date_utils.js"))
	assetsAll = append(assetsAll, TAG_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsDate)) + TAG_JS_END)
	var jsSmartUtilsCrypt string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/crypt_utils.js"))
	assetsAll = append(assetsAll, TAG_JS_START + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsCrypt)) + TAG_JS_END)
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

	HTML_META_FAVICON   string = `<link rel="icon" href="data:,">`
	HTML_META_VIEWPORT  string = `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
	HTML_META_CHAREQUIV string = `<meta charset="` + smart.CHARSET + `"><meta http-equiv="Content-Type" content="` + HTML_CONTENT_HEADER + `">`

	TAG_CSS_START string = `<link rel="stylesheet" type="text/css" href="data:text/css,`
	TAG_CSS_END string = `">`
	TAG_JS_START string = `<script src="data:application/javascript,`
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
div.message { line-height: 36px; text-align: left; font-size: 1.25rem; font-weight: bold; font-style: normal; padding-left: 16px; padding-right: 16px; padding-top: 12px; padding-bottom: 8px; margin-top: 8px; margin-bottom: 8px; max-width: calc(100% - 10px) !important; min-width: 100px; min-height: 40px; height: auto !important; border-radius: 5px; box-sizing: content-box !important; opacity: 1 !important; background-color: #C62828 !important; color: #FFFFFF !important; }
</style>
</head>
<body>
<h1 style="display:inline; font-size:4rem; color:#333333;">[###TITLE-TEXT|html###]</h1>
<br>
<br>
<hr>
<div class="message">[###MESSAGE-TEXT|html|nl2br###]</div>
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
)


//-----


// #END
