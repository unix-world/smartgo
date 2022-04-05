
// GO Lang :: SmartGo / Web Assets (static) :: Smart.Go.Framework
// (c) 2020-2022 unix-world.org
// r.20220405.0608 :: STABLE

package webassets

import (
	"log"

	smart "github.com/unix-world/smartgo"

	"embed"
)
//go:embed lib/*
var assets embed.FS

//-----


func ReadWebAsset(path string) string { // OK
	//--
	//log.Println("[DEBUG] Trying to Read the Asset: `" + path + "` ...")
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
	//log.Println("[DEBUG] Reading Asset: `" + path + "`")
	//--
	return string(content)
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
	return smart.RenderMainMarkersTpl(smart.HTML_TPL, arr, parr) + "\n" + "<!-- TPL:static -->" + "\n"
	//--
} //END FUNCTION


//-----


// #END
