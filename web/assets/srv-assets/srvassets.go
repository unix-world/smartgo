
// GO Lang :: SmartGo / Web Assets (server) :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260903.2358 :: STABLE

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
	VERSION string = "r.20260903.2358"
)

var (
	DEBUG bool = smart.DEBUG
)

//-----


type uxmAjaxFormReply struct {
	Completed 			string 		`json:"completed"` 				// this should be always `DONE`
	Status 				string 		`json:"status"` 				// `OK` | `INFO` | `HINT` | `NOTICE` | `WARN` | `ERROR` | `FAIL` | `FATAL` | `UNKNOWN` (cannot be empty)
	Action 				string 		`json:"action"` 				// action button label ; if status is OK, button label is OK, otherwise it is set to Cancel
	Title  				string 		`json:"title"` 					// text
	Message 			string 		`json:"message"` 				// html code
	JsEvalCode 			string 		`json:"js_evcode"` 				// js code
	RedirectUrl 		string 		`json:"redirect"` 				// redirect url
	ReplaceDiv 			string 		`json:"replace_div"` 			// div element id, to be replaced by replace html
	ReplaceHtml 		string 		`json:"replace_html"` 			// html code
	HideFormOnSuccess	string 		`json:"hide_form_on_success"` 	// flag: `` | `hide`
}


func JsonAjaxFormStdReply(status string, title string, message string, isHtmlMessage bool, redirect string, hideFormOnSuccess bool, jsEvalCode string) string {
	//--
	return JsonAjaxFormReply(status, "", title, message, isHtmlMessage, jsEvalCode, redirect, "", "", hideFormOnSuccess)
	//--
} //END FUNCTION


func JsonAjaxFormReply(status string, action string, title string, message string, isHtmlMessage bool, jsEvalCode string, redirect string, replaceDivId string, replaceDivHtml string, hideFormOnSuccess bool) string {
	//--
	// sync with SF.PHP/ViewHelpers
	//--
	defer smart.PanicHandler()
	//--
	status = smart.StrToUpper(smart.StrTrimWhitespaces(status))
	//--
	switch(status) {
		case "OK": 			fallthrough
		case "INFO": 		fallthrough
		case "HINT": 		fallthrough
		case "NOTICE": 		fallthrough
		case "WARN": 		fallthrough
		case "WARNING": 	fallthrough
		case "ERR": 		fallthrough
		case "ERROR": 		fallthrough
		case "FAIL": 		fallthrough
		case "FAILED":
			break
		case "FATAL": 		fallthrough
		case "": 			fallthrough
		default:
			status = "FATAL"; // cannot be empty or anything else
	} //end switch
	//--
	action = smart.StrTrimWhitespaces(action)
	if(action == "") {
		if(status == "OK") {
			action = "OK"
		} else {
			action = "Cancel"
		} //end if else
	} //end if
	//--
	title = smart.EscapeHtml(title)
	if(!isHtmlMessage) {
		message = smart.Nl2Br(smart.EscapeHtml(message))
	} //end if
	//--
	var strHideFormOnSuccess string = ""
	if(hideFormOnSuccess) {
		strHideFormOnSuccess = "hide"
	} //end if
	//--
	data := uxmAjaxFormReply{}
	//--
	data.Completed 			= "DONE"
	data.Status 			= smart.StrTrimWhitespaces(status)
	data.Action 			= smart.StrTrimWhitespaces(action)
	data.Title 				= smart.StrTrimWhitespaces(title)
	data.Message 			= smart.StrTrimWhitespaces(message)
	data.JsEvalCode 		= smart.StrTrimWhitespaces(jsEvalCode)
	data.RedirectUrl 		= smart.StrTrimWhitespaces(redirect)
	data.ReplaceDiv 		= smart.StrTrimWhitespaces(replaceDivId)
	data.ReplaceHtml 		= smart.StrTrimWhitespaces(replaceDivHtml)
	data.HideFormOnSuccess 	= smart.StrTrimWhitespaces(strHideFormOnSuccess)
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
	if((r.Method != smarthttputils.HTTP_METHOD_GET) && (r.Method != smarthttputils.HTTP_METHOD_HEAD)) {
		log.Println("[META]", smart.CurrentFunctionName(), "# StatusCode: 405 # Failed to Serve Asset: `" + path + "`", "# Invalid Method:", r.Method)
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
					log.Println("[META]", smart.CurrentFunctionName(), "# StatusCode: 410 # Inaccessible Asset: `" + path + "`", "# Protected")
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
		log.Println("[META]", smart.CurrentFunctionName(), "# StatusCode: 404 # Failed to Serve Asset: `" + path + "`", "# Not Found")
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
		log.Println("[DATA]", smart.CurrentFunctionName(), "# Served Asset: `" + path + "` :: ContentLength:", len(assetContent), "bytes ; lastModified: `" + cMod + "` ; cacheControl: `" + cCtl + "` ; cacheExpires:", cExp)
	} //end if
	log.Println("[NOTICE]", smart.CurrentFunctionName(), "# Serving Asset: `" + path + "` ;", len(assetContent), "bytes")
	//--
	smarthttputils.HttpStatus200(w, r, assetContent, path, "", cExp, cMod, cCtl, nil)
	//--
	return 200
	//--
} //END FUNCTION


//-----


func HtmlPdfIframe(pdfRaw []byte, docName string, closeModalOrPopup bool, ifrmId string) string {
	//--
	// this needs server template not standalone ; in standalone mode the PDF download does not work and also SFIcons are N/A
	//--
	if(pdfRaw == nil) {
		return assets.HtmlNotificationMessage("warn", false, "PDF is Empty") // text
	} //end if
	if(!smart.BytStartsWith(pdfRaw, []byte("%PDF-"))) { // {{{SYNC-PDF-FILE-TEST}}}
		return assets.HtmlNotificationMessage("error", false, "PDF is Invalid") // text
	} //end if
	//--
	docName = smart.StrTrimWhitespaces(docName)
	if(docName != "") {
		docName = smart.StrCreateSlug(docName)
	} //end if
	if(len(docName) > 128) {
		docName = "" // invalid
	} //end if
	//--
	var closeMP string = "0"
	if(closeModalOrPopup == true) {
		closeMP = "1"
	} //end if
	//--
	ifrmId = smart.StrTrimWhitespaces(ifrmId)
	if(ifrmId == "") {
		ifrmId = "smart-pdf-view"
	} //end if
	//--
	return smart.RenderMarkersTpl(assets.ReadWebAsset("lib/tpl/iframe-pdf-view-download.inc.mtpl.htm"), map[string]string{
		//--
		"CLOSE-MP": 	closeMP, // if set to 1 will close modal/popup on download
		"IFRM-ID": 		ifrmId,
		//--
		"WIDTH": 		"98vw",
		"HEIGHT": 		"98vh",
		//--
		"TOP": 			"75px",
		"RIGHT": 		"75px",
		//--
		"DOC-NAME": 	docName, // skip .pdf extension
		"PDF-B64": 		string(smart.Base64BytEncode(pdfRaw)), // B64 of PDF raw data
		//--
	})
	//--
} //END FUNCTION


//-----


func HtmlServerTemplate(titleText string, headHtml string, bodyHtml string, loadjs bool) string { // require: a HTTP or HTTPS service, serving assets as: /lib/*
	//--
	return htmlServerSelectTemplate(titleText, headHtml, bodyHtml, "", loadjs)
	//--
} //END FUNCTION


func HtmlServerFaviconTemplate(titleText string, headHtml string, bodyHtml string, loadjs bool, favicon string) string { // require: a HTTP or HTTPS service, serving assets as: /lib/* and a favicon
	//--
	return htmlServerSelectTemplate(titleText, headHtml, bodyHtml, favicon, loadjs)
	//--
} //END FUNCTION


func htmlServerSelectTemplate(titleText string, headHtml string, bodyHtml string, favicon string, loadjs bool) string {
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
	//-- {{{SYNC-SRV-ASSETS-BASEPATH}}} ; must use HTML BasePath as prefix (default is /), to work with advanced tail dirs routing
	var headCssJs string = assets.TAG_COMMENT_HEAD_JS_CSS + "\n" + assets.TAG_BASE_HREF_START + smart.EscapeHtml(smart.GetHttpProxyBasePath()) + assets.TAG_BASE_HREF_END
	//--
	var assetsAll []string
	assetsAll = append(assetsAll, headCssJs)
	//--
	const cssAppGo string = "lib/app-go.css"
	assetsAll = append(assetsAll, assets.TAG_CSS_START + smart.EscapeHtml(cssAppGo) + assets.TAG_CSS_END)
	//--
	if(loadjs == true) {
		//--
		const jsJQueryBase string = "lib/js/jquery/jquery.js"
		assetsAll = append(assetsAll, assets.TAG_JS_START + smart.EscapeHtml(jsJQueryBase) + assets.TAG_JS_END)
		const jsJQuerySettings string = "lib/js/jquery/settings-jquery.js"
		assetsAll = append(assetsAll, assets.TAG_JS_START + smart.EscapeHtml(jsJQuerySettings) + assets.TAG_JS_END)
		const jsJQuerySmartCompat string = "lib/js/jquery/jquery.smart.compat.js"
		assetsAll = append(assetsAll, assets.TAG_JS_START + smart.EscapeHtml(jsJQuerySmartCompat) + assets.TAG_JS_END)
		//--
		const cssJQueryGrowl string = "lib/js/jquery/growl/jquery.toastr.css"
		assetsAll = append(assetsAll, assets.TAG_CSS_START + smart.EscapeHtml(cssJQueryGrowl) + assets.TAG_CSS_END)
		const jsJQueryGrowl string = "lib/js/jquery/growl/jquery.toastr.js"
		assetsAll = append(assetsAll, assets.TAG_JS_START + smart.EscapeHtml(jsJQueryGrowl) + assets.TAG_JS_END)
		//--
		const cssJQueryAlertable string = "lib/js/jquery/jquery.alertable.css"
		assetsAll = append(assetsAll, assets.TAG_CSS_START + smart.EscapeHtml(cssJQueryAlertable) + assets.TAG_CSS_END)
		const jsJQueryAlertable string = "lib/js/jquery/jquery.alertable.js"
		assetsAll = append(assetsAll, assets.TAG_JS_START + smart.EscapeHtml(jsJQueryAlertable) + assets.TAG_JS_END)
		//--
		const jsSfSettings string = "lib/js/framework/smart-framework-settings.js"
		assetsAll = append(assetsAll, assets.TAG_JS_START + smart.EscapeHtml(jsSfSettings) + assets.TAG_JS_END)
		const jsSfPak string = "lib/js/framework/smart-framework.pak.js"
		assetsAll = append(assetsAll, assets.TAG_JS_START + smart.EscapeHtml(jsSfPak) + assets.TAG_JS_END)
		//--
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


// #END
