
// GO Lang :: SmartGo / Web Assets (server) :: Smart.Go.Framework
// (c) 2020-2022 unix-world.org
// r.20220416.1958 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package assetsserver

import (
	"log"
	"net/http"

	smart  			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web-httputils"
	assets 			"github.com/unix-world/smartgo/web-assets"
)


//-----

const(
	VERSION string = "r.20220416.1958"

	CACHED_EXP_TIME_SECONDS uint32 = 3600 // (int) cache time of assets

	DEBUG bool = false
)

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
		log.Println("[WARNING] 404 :: Cannot Serve Asset: `" + path + "` ...")
		smarthttputils.HttpStatus404(w, r, "Asset Not Found: `" + path + "`", true) // html
		return
	} //end if
	//--
	var cExp int = -1
	var cMod string = ""
	var cCtl string = "no-cache"
	switch(cacheMode) {
		case "cache:public": fallthrough
		case "cache:private":
			cExp = int(CACHED_EXP_TIME_SECONDS)
			cMod = assets.LAST_MODIFIED_DATE_TIME
			if(cacheMode == "cache:public") {
				cCtl = "public"
			} else {
				cCtl = "private"
			} //end if else
			break
		case "cache:no": fallthrough
		default:
			// as defaults (no cache)
	} //end switch
	//--
	if(DEBUG == true) {
		log.Println("[DATA] Served Asset: `" + path + "` :: ContentLength:", len(assetContent), "bytes ; contentDisposition: `" + contentDisposition + "` ; lastModified: `" + cMod + "` ; cacheControl: `" + cCtl + "` ; cacheExpires:", cExp)
	} //end if
	log.Println("[NOTICE] Serving Asset: `" + path + "` ;", len(assetContent), "bytes")
	//--
	smarthttputils.HttpStatus200(w, r, assetContent, path, contentDisposition, cExp, cMod, cCtl, nil)
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
	arr := map[string]string{
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
	parr := map[string]string{
		"HEAD-CSS-JS": headCssJs,
	}
	//--
	return smart.RenderMainMarkersTpl(assets.HTML_TPL_DEF, arr, parr) + "\n" + "<!-- TPL:Dynamic -->" + "\n"
	//--
} //END FUNCTION


//-----


// #END
