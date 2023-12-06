
// GO Lang :: SmartGo / Web Assets (server) :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231204.1852 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package assetsserver

import (
	"log"
	"net/http"

	smart  			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web-assets"
	smarthttputils 	"github.com/unix-world/smartgo/web-httputils"
)


//-----

const(
	VERSION string = "r.20231204.1852"

	DEBUG bool = false
)

//-----


type uxmAjaxFormReply struct {
	Completed 			string 		`json:"completed"`
	Status 				string 		`json:"status"`
	Action 				string 		`json:"action"`
	Title  				string 		`json:"title"`
	Message 			string 		`json:"message"`
	JsEvalCode 			string 		`json:"js_evcode"`
	RedirectUrl 		string 		`json:"redirect"`
	ReplaceDiv 			string 		`json:"replace_div"`
	ReplaceHtml 		string 		`json:"replace_html"`
	HideFormOnSuccess	string 		`json:"hide_form_on_success"`
}


func JsonAjaxFormReply(status string, action string, title string, message string, isHtmlMessage bool, js_evcode string, redirect string, replace_div string, replace_html string, hide_form_on_success bool) string {
	//--
	title = smart.EscapeHtml(title)
	if(!isHtmlMessage) {
		message = smart.StrNl2Br(smart.EscapeHtml(message))
	} //end if
	//--
	var hideFormOnSuccess string = ""
	if(hide_form_on_success) {
		hideFormOnSuccess = "hide"
	} //end if
	//--
	data := uxmAjaxFormReply{}
	//--
	data.Completed 			= "DONE"
	data.Status 			= smart.StrTrimWhitespaces(status)
	data.Action 			= smart.StrTrimWhitespaces(action)
	data.Title 				= smart.StrTrimWhitespaces(title)
	data.Message 			= smart.StrTrimWhitespaces(message)
	data.JsEvalCode 		= smart.StrTrimWhitespaces(js_evcode)
	data.RedirectUrl 		= smart.StrTrimWhitespaces(redirect)
	data.ReplaceDiv 		= smart.StrTrimWhitespaces(replace_div)
	data.ReplaceHtml 		= smart.StrTrimWhitespaces(replace_html)
	data.HideFormOnSuccess 	= smart.StrTrimWhitespaces(hideFormOnSuccess)
	//--
	return smart.JsonNoErrChkEncode(data, false, true)
	//--
} //END FUNCTION


//-----


func WebAssetsHttpHandler(w http.ResponseWriter, r *http.Request, contentDisposition string, cacheMode string) { // serves the assets for a HTTP(S) server under the path: `/lib/*`
	//--
	var path string = r.URL.Path
	path = smart.StrTrimWhitespaces(path)
	//--
	var assetContent string = ""
	if(smart.StrStartsWith(path, "/lib/")) {
		path = smart.StrTrim(path, "/")
		if(len(path) > 4) {
			if(smart.StrStartsWith(path, "lib/")) {
				assetContent = assets.ReadWebAsset(path)
			} //end if
		} //end if
	} //end if
	//--
	if(assetContent == "") {
		log.Println("StatusCode: 404 # Failed to Serve Asset: `" + path + "`", "# Not Found", "::", smart.CurrentFunctionName())
		smarthttputils.HttpStatus404(w, r, "Asset Not Found: `" + path + "`", true) // html
		return
	} //end if
	//--
	var cExp int = -1
	var cMod string = ""
	var cCtl string = smarthttputils.CACHE_CONTROL_NOCACHE
	switch(cacheMode) {
		case "cache:public": fallthrough
		case "cache:private":
			cExp = int(assets.CACHED_EXP_TIME_SECONDS)
			cMod = assets.LAST_MODIFIED_DATE_TIME
			if(cacheMode == "cache:public") {
				cCtl = smarthttputils.CACHE_CONTROL_PUBLIC
			} else {
				cCtl = smarthttputils.CACHE_CONTROL_PRIVATE
			} //end if else
			break
		case "cache:no": fallthrough
		default:
			// as defaults (no cache)
	} //end switch
	//--
	if(DEBUG == true) {
		log.Println("[DATA] " + smart.CurrentFunctionName() + ": Served Asset: `" + path + "` :: ContentLength:", len(assetContent), "bytes ; contentDisposition: `" + contentDisposition + "` ; lastModified: `" + cMod + "` ; cacheControl: `" + cCtl + "` ; cacheExpires:", cExp)
	} //end if
	log.Println("[NOTICE] " + smart.CurrentFunctionName() + ": Serving Asset: `" + path + "` ;", len(assetContent), "bytes")
	//--
	smarthttputils.HttpStatus200(w, r, assetContent, path, contentDisposition, cExp, cMod, cCtl, nil)
	//--
} //END FUNCTION


//-----

func HtmlServerTemplate(titleText string, headHtml string, bodyHtml string) string { // require: a HTTP or HTTPS service, serving assets as: /lib/*
	//--
	return htmlServerChooseTemplate(titleText, headHtml, bodyHtml, "")
	//--
} //END FUNCTION


func HtmlServerFaviconTemplate(titleText string, headHtml string, bodyHtml string, favicon string) string { // require: a HTTP or HTTPS service, serving assets as: /lib/* and a favicon
	//--
	return htmlServerChooseTemplate(titleText, headHtml, bodyHtml, favicon)
	//--
} //END FUNCTION


func htmlServerChooseTemplate(titleText string, headHtml string, bodyHtml string, favicon string) string {
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
	var theTpl string = assets.HTML_TPL_DEF
	if(favicon != "") {
		arr["FAVICON"] = favicon
		theTpl = assets.HTML_TPL_FAVICON_DEF
	}
	//--
	var headCssJs string = "<!-- Head: Css / Js -->"
	var assetsAll []string
	assetsAll = append(assetsAll, headCssJs)
	//--
	const cssStartTag = `<link rel="stylesheet" type="text/css" href="`
	const cssEndTag = `">`
	const jsStartTag = `<script src="`
	const jsEndTag = `"></script>`
	//--
	const cssAppGo = "lib/app-go.css"
	assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(cssAppGo) + cssEndTag)
	//--
	const jsJQueryBase = "lib/js/jquery/jquery.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQueryBase) + jsEndTag)
	const jsJQuerySettings = "lib/js/jquery/settings-jquery.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQuerySettings) + jsEndTag)
	const jsJQuerySmartCompat = "lib/js/jquery/jquery.smart.compat.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQuerySmartCompat) + jsEndTag)
	//--
	const cssJQueryGrowl = "lib/js/jquery/growl/jquery.toastr.css"
	assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(cssJQueryGrowl) + cssEndTag)
	const jsJQueryGrowl = "lib/js/jquery/growl/jquery.toastr.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQueryGrowl) + jsEndTag)
	//--
	const cssJQueryAlertable = "lib/js/jquery/jquery.alertable.css"
	assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(cssJQueryAlertable) + cssEndTag)
	const jsJQueryAlertable = "lib/js/jquery/jquery.alertable.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQueryAlertable) + jsEndTag)
	//--
	const jsSfSettings = "lib/js/framework/smart-framework-settings.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsSfSettings) + jsEndTag)
	const jsSfPak = "lib/js/framework/smart-framework.pak.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsSfPak) + jsEndTag)
	//--
	if(len(assetsAll) > 0) {
		headCssJs = smart.Implode("\n", assetsAll)
	} //end if
	//--
	parr := map[string]string{
		"HEAD-CSS-JS": headCssJs,
	}
	//--
	return smart.RenderMainHtmlMarkersTpl(theTpl, arr, parr) + "\n" + "<!-- TPL:Dynamic -->" + "\n"
	//--
} //END FUNCTION


//-----


// #END
