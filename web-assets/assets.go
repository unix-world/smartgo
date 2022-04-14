
// GO Lang :: SmartGo / Web Assets (static) :: Smart.Go.Framework
// (c) 2020-2022 unix-world.org
// r.20220415.0128 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
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
	VERSION string = "r.20220415.0128"

	LAST_MODIFIED_DATE_TIME string = "2022-04-07 23:28:00" 	// (string) assets last modified ; UPDATE THIS AFTER EACH TIME THE ASSETS ARE MODIFIED !

	DEBUG bool = false
)

//-----


func ReadWebAsset(path string) string { // OK
	//--
	if(DEBUG == true) {
		log.Println("[DEBUG] Trying to Read the Asset: `" + path + "` ...")
	} //end if
	//--
	if(smart.PathIsBackwardUnsafe(path) == true) {
		log.Println("[WARNING] Failed to Read Asset: `" + path + "` # unsafe backward path")
		return ""
	} //end if
	path = smart.StrTrimWhitespaces(smart.StrTrim(path, "/"))
	if(path == "") {
		log.Println("[WARNING] Failed to Read Asset: `" + path + "` # empty path")
		return ""
	} //end if
	if(!smart.StrStartsWith(path, "lib/")) {
		log.Println("[WARNING] Failed to Read Asset: `" + path + "` # path must start with `lib/`")
		return ""
	} //end if
	path = smart.StrTrimWhitespaces(smart.StrTrim(path, "/"))
	if((path == "") || (path == ".") || (path == "..") || (path == "/")) {
		log.Println("[WARNING] Failed to Read Asset: `" + path + "` # unsupported path")
		return ""
	} //end if
	if(smart.PathIsAbsolute(path) == true) {
		log.Println("[WARNING] Failed to Read Asset: `" + path + "` # not a relative path")
		return ""
	} //end if
	//--
	content, err := assets.ReadFile(path)
	if(err != nil) {
		log.Println("[WARNING] Failed to Read Asset: `" + path + "`")
		return ""
	} //end if
	//--
	if(DEBUG == true) {
		log.Println("[DATA] Reading Asset: `" + path + "` [DONE] :: ContentLength=", len(content), "bytes")
	} //end if
	//--
	return string(content)
	//--
} //END FUNCTION


//-----


func HtmlErrorPage(titleText string, messageText string, displayAuthLogo bool) string {
	//--
	titleText = smart.StrTrimWhitespaces(titleText)
	messageText = smart.StrTrimWhitespaces(messageText)
	//--
	if(titleText == "") {
		titleText = "Untitled"
		log.Println("[ERROR] Smart Assets: HtmlErrorPage requires a non-empty Title !")
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
	return smart.RenderMainMarkersTpl(HTML_TPL_ERR, arr, nil) + "\n" + "<!-- TPL:Static.Err -->" + "\n"
	//--
} //END FUNCTION


//-----


func HtmlStandaloneTemplate(titleText string, headHtml string, bodyHtml string) string { // OK: can be used as standalone
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
	var arr = map[string]string{
		"TITLE": 		titleText,
		"HEAD-HTML": 	headHtml,
		"BODY-HTML": 	bodyHtml,
	}
	//--
	const cssStartTag = `<link rel="stylesheet" type="text/css" href="data:text/css,`
	const cssEndTag = `">`
	const jsStartTag = `<script src="data:application/javascript,`
	const jsEndTag = `"></script>`
	//--
	var headCssJs string = "<!-- Head: Css / Js -->"
	var assetsAll []string
	assetsAll = append(assetsAll, headCssJs)
	//--
	var cssBase string = smart.StrTrimWhitespaces(ReadWebAsset("lib/core/css/base.css"))
	if(cssBase != "") {
		assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(smart.EscapeUrl(cssBase)) + cssEndTag)
	} //end if
	var cssNotif string = smart.StrTrimWhitespaces(ReadWebAsset("lib/core/css/notifications.css"))
	if(cssNotif != "") {
		assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(smart.EscapeUrl(cssNotif)) + cssEndTag)
	} //end if
	//--
	var cssToolkit string = smart.StrTrimWhitespaces(ReadWebAsset("lib/css/toolkit/ux-toolkit.css"))
	if(cssToolkit != "") {
		assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(smart.EscapeUrl(cssToolkit)) + cssEndTag)
	} //end if
	var cssResponsiveToolkit string = smart.StrTrimWhitespaces(ReadWebAsset("lib/css/toolkit/ux-toolkit-responsive.css"))
	if(cssResponsiveToolkit != "") {
		assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(smart.EscapeUrl(cssResponsiveToolkit)) + cssEndTag)
	} //end if
	//--
	var jsSmarSettings string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/settings.js"))
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(smart.EscapeUrl(jsSmarSettings)) + jsEndTag)
	var jsSmartUtilsCore string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/core_utils.js"))
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsCore)) + jsEndTag)
	var jsSmartUtilsDate string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/date_utils.js"))
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsDate)) + jsEndTag)
	var jsSmartUtilsCrypt string = smart.StrTrimWhitespaces(ReadWebAsset("lib/js/framework/src/crypt_utils.js"))
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(smart.EscapeUrl(jsSmartUtilsCrypt)) + jsEndTag)
	//--
	if(len(assetsAll) > 0) {
		headCssJs = smart.Implode("\n", assetsAll)
	} //end if
	//--
	var parr = map[string]string{
		"HEAD-CSS-JS": headCssJs,
	}
	//--
	return smart.RenderMainMarkersTpl(HTML_TPL_DEF, arr, parr) + "\n" + "<!-- TPL:static -->" + "\n"
	//--
} //END FUNCTION


//-----

const (
	TEXT_CONTENT_HEADER string = "text/plain; charset=" + smart.CHARSET // keep separate, can be used also by HTTP Headers: Content-Type
	HTML_CONTENT_HEADER string = "text/html; charset="  + smart.CHARSET // keep separate, can be used also by HTTP Headers: Content-Type

	HTML_META_FAVICON   string = `<link rel="icon" href="data:,">`
	HTML_META_VIEWPORT  string = `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
	HTML_META_CHAREQUIV string = `<meta charset="` + smart.CHARSET + `"><meta http-equiv="Content-Type" content="` + HTML_CONTENT_HEADER + `">`

	HTML_TPL_ERR string = `<!DOCTYPE html>
<!-- TPL.SmartGo.ERR -->
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
<div class="message">[###MESSAGE-TEXT|html###]</div>
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
)

//-----


// #END
