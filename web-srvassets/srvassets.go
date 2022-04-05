
// GO Lang :: SmartGo / Web Assets (server) :: Smart.Go.Framework
// (c) 2020-2022 unix-world.org
// r.20220405.0608 :: STABLE

package assetsserver

import (
	"net/http"

	smart  "github.com/unix-world/smartgo"
	assets "github.com/unix-world/smartgo/web-assets"
)


//-----


func WebAssetsHttpHandler (w http.ResponseWriter, r *http.Request) { // OK: serves the assets for a HTTP(S) server under the path: `/lib/*`
	//--
	var path string = r.URL.Path
	path = smart.StrTrimWhitespaces(path)
	//--
	//log.Println("[DEBUG] Trying to Serve the Asset: `" + path + "` ...")
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
		w.Header().Set("Content-Type", smart.HTML_CONTENT_HEADER)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(smart.HtmlErrorPage("404 Not Found", "Asset Not Found:`<small>" + smart.EscapeHtml(path) + "</small>`")))
		return
	} //end if
	//--
	var mime string = smart.MimeTypeByFilePath(path)
	//--
	//log.Println("[DEBUG] Serving Asset: `" + path + "` as:", mime)
	//--
	w.Header().Add("Content-Type", mime)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(assetContent))
	//--
} //END FUNCTION


//-----


func HtmlServerTemplate(titleText string, headHtml string, bodyHtml string) string { // require: a HTTP or HTTPS service, serving assets as: /lib/*
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
	const jsES6Check = "lib/js/check-es-runtime.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsES6Check) + jsEndTag)
	const jsSfSettings = "lib/js/framework/smart-framework-settings.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsSfSettings) + jsEndTag)
	const jsSfPak = "lib/js/framework/smart-framework.pak.js"
	assetsAll = append(assetsAll, jsStartTag + smart.EscapeHtml(jsSfPak) + jsEndTag)
	//--
	if(len(assetsAll) > 0) {
		headCssJs = smart.Implode("\n", assetsAll)
	} //end if
	//--
	var parr = map[string]string{
		"HEAD-CSS-JS": headCssJs,
	}
	//--
	return smart.RenderMainMarkersTpl(smart.HTML_TPL, arr, parr) + "\n" + "<!-- TPL:Dynamic -->" + "\n"
	//--
} //END FUNCTION


//-----


// #END
