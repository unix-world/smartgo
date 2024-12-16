
// GO Lang :: SmartGo / Web Assets (server) :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241216.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package srvassets

import (
	"log"
	"net/http"

	smart  			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web/assets/web-assets"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)


//-----

const(
	VERSION string = "r.20241216.2358"
)

var (
	DEBUG bool = smart.DEBUG
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
	defer smart.PanicHandler()
	//--
	title = smart.EscapeHtml(title)
	if(!isHtmlMessage) {
		message = smart.Nl2Br(smart.EscapeHtml(message))
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


func WebAssetsHttpHandler(w http.ResponseWriter, r *http.Request, cacheMode string) uint16 { // serves the assets for a HTTP(S) server under the path: `/lib/*`
	//--
	defer smart.PanicHandler()
	//--
	var path string = smart.GetHttpPathFromRequest(r)
	//--
	if((r.Method != "GET") && (r.Method != "HEAD")) {
		log.Println("StatusCode: 405 # Failed to Serve Asset: `" + path + "`", "# Invalid Method:", r.Method, "::", smart.CurrentFunctionName())
		smarthttputils.HttpStatus405(w, r, "Invalid Request Method [" + r.Method + "] for Asset: `" + path + "`", true) // html
		return 405
	} //end if
	//--
	var assetContent string = ""
	if(smart.StrStartsWith(path, "/lib/")) {
		path = smart.StrTrimWhitespaces(smart.StrTrim(path, "/ ")) // remove `/` and space + all whitespaces
		if(len(path) > 4) {
			if(smart.StrStartsWith(path, "lib/")) {
				if(smart.StrStartsWith(path, "lib/tpl/")) { // no-serve.http-access
					log.Println("StatusCode: 410 # Inaccessible Asset: `" + path + "`", "# Protected", "::", smart.CurrentFunctionName())
					smarthttputils.HttpStatus410(w, r, "Inaccessible Asset: `" + path + "`", true) // html
					return 410
				} else {
					assetContent = assets.ReadWebAsset(path)
				} //end if
			} //end if
		} //end if
	} //end if
	//--
	if(assetContent == "") {
		log.Println("StatusCode: 404 # Failed to Serve Asset: `" + path + "`", "# Not Found", "::", smart.CurrentFunctionName())
		smarthttputils.HttpStatus404(w, r, "Asset Not Found: `" + path + "`", true) // html
		return 404
	} //end if
	//--
	var cExp int = -1
	var cMod string = ""
	var cCtl string = smarthttputils.CACHE_CONTROL_NOCACHE
	switch(cacheMode) {
		case "cache:private": fallthrough
		case "cache:public": fallthrough
		case "cache:default":
			cExp = int(assets.CACHED_EXP_TIME_SECONDS)
			cMod = assets.LAST_MODIFIED_DATE_TIME
			if(cacheMode == "cache:private") {
				cCtl = smarthttputils.CACHE_CONTROL_PRIVATE
			} else if(cacheMode == "cache:public") {
				cCtl = smarthttputils.CACHE_CONTROL_PUBLIC
			} else {
				cCtl = smarthttputils.CACHE_CONTROL_DEFAULT
			} //end if else
			break
		case "cache:no": fallthrough
		default:
			// as defaults (no cache)
	} //end switch
	//--
	if(DEBUG == true) {
		log.Println("[DATA] " + smart.CurrentFunctionName() + ": Served Asset: `" + path + "` :: ContentLength:", len(assetContent), "bytes ; lastModified: `" + cMod + "` ; cacheControl: `" + cCtl + "` ; cacheExpires:", cExp)
	} //end if
	log.Println("[NOTICE] " + smart.CurrentFunctionName() + ": Serving Asset: `" + path + "` ;", len(assetContent), "bytes")
	//--
	smarthttputils.HttpStatus200(w, r, assetContent, path, "", cExp, cMod, cCtl, nil)
	//--
	return 200
	//--
} //END FUNCTION


//-----

func HtmlServerTemplate(titleText string, headHtml string, bodyHtml string, loadjs bool) string { // require: a HTTP or HTTPS service, serving assets as: /lib/*
	//--
	return htmlServerChooseTemplate(titleText, headHtml, bodyHtml, "", loadjs)
	//--
} //END FUNCTION


func HtmlServerFaviconTemplate(titleText string, headHtml string, bodyHtml string, loadjs bool, favicon string) string { // require: a HTTP or HTTPS service, serving assets as: /lib/* and a favicon
	//--
	return htmlServerChooseTemplate(titleText, headHtml, bodyHtml, favicon, loadjs)
	//--
} //END FUNCTION


func htmlServerChooseTemplate(titleText string, headHtml string, bodyHtml string, favicon string, loadjs bool) string {
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
	var theTpl string = assets.HTML_TPL_DEF
	if(favicon != "") {
		arr["FAVICON"] = favicon
		theTpl = assets.HTML_TPL_FAVICON_DEF
	}
	//--
	var headCssJs string = TAG_COMMENT_HEAD_JS_CSS
	headCssJs += TAG_BASE_HREF_START + smart.EscapeHtml(smart.GetHttpProxyBasePath()) + TAG_BASE_HREF_END // {{{SYNC-SRV-ASSETS-BASEPATH}}} ; must use HTML BasePath as prefix (default is /), to work with advanced tail dirs routing
	//--
	var assetsAll []string
	assetsAll = append(assetsAll, headCssJs)
	//--
	var cssStartTag string 	= TAG_CSS_START // {{{SYNC-SRV-ASSETS-BASEPATH}}} ; must use ONLY relative paths, because Base Tag will fix them
	var cssEndTag string 	= TAG_CSS_END
	var jsStartTag string 	= TAG_JS_START // {{{SYNC-SRV-ASSETS-BASEPATH}}} ; must use ONLY relative paths, because Base Tag will fix them
	var jsEndTag string		= TAG_JS_END
	//--
	const cssAppGo string = "lib/app-go.css"
	assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(cssAppGo) + cssEndTag)
	//--
	if(loadjs == true) {
		const jsJQueryBase string = "lib/js/jquery/jquery.js"
		assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQueryBase) + jsEndTag)
		const jsJQuerySettings string = "lib/js/jquery/settings-jquery.js"
		assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQuerySettings) + jsEndTag)
		const jsJQuerySmartCompat string = "lib/js/jquery/jquery.smart.compat.js"
		assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQuerySmartCompat) + jsEndTag)
		//--
		const cssJQueryGrowl string = "lib/js/jquery/growl/jquery.toastr.css"
		assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(cssJQueryGrowl) + cssEndTag)
		const jsJQueryGrowl string = "lib/js/jquery/growl/jquery.toastr.js"
		assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQueryGrowl) + jsEndTag)
		//--
		const cssJQueryAlertable string = "lib/js/jquery/jquery.alertable.css"
		assetsAll = append(assetsAll, cssStartTag + smart.EscapeHtml(cssJQueryAlertable) + cssEndTag)
		const jsJQueryAlertable string = "lib/js/jquery/jquery.alertable.js"
		assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsJQueryAlertable) + jsEndTag)
		//--
		const jsSfSettings string = "lib/js/framework/smart-framework-settings.js"
		assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsSfSettings) + jsEndTag)
		const jsSfPak string = "lib/js/framework/smart-framework.pak.js"
		assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsSfPak) + jsEndTag)
	} else {
		assetsAll = append(assetsAll, `<!-- JS: skip -->`)
	} //end if else
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


const (
	TAG_COMMENT_HEAD_JS_CSS string 	= "<!-- Head: Css / Js -->"
	TAG_BASE_HREF_START string 		= `<base href="`
	TAG_BASE_HREF_END string 		= `">`
	TAG_CSS_START string 			= `<link rel="stylesheet" type="text/css" href="`
	TAG_CSS_END string 				= `">`
	TAG_JS_START string 			= `<script src="`
	TAG_JS_END string 				= `"></script>`
)

//-----


// #END
