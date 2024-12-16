
// GO Lang :: SmartGo / Web Server / Auth :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241216.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"net/http"

	smart 			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web/assets/web-assets"
	srvassets 		"github.com/unix-world/smartgo/web/assets/srv-assets"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
	qrsvg 			"github.com/unix-world/smartgo/markup/svg-qrcode/qrsvg"
)

const (
	DEBUG_AUTH bool = false // DO NOT SET this to TRUE in production environments ! it is meant just for development purposes
)


type authStatusNfo struct {
	Authenticated 		bool   				`json:"authenticated"`
	AuthErrors 			string 				`json:"authErrors"`
	AuthMethodID 		uint8  				`json:"authMethodId"`
	AuthMethodName 		string 				`json:"authMethodName"`
	AuthArea 			string 				`json:"authArea"`
	AuthRealm 			string 				`json:"authRealm"`
	AuthUserName 		string 				`json:"authUserName"`
	AuthUserID 			string 				`json:"authUserId"`
	AuthPassHash 		string              `json:"authPassHash"`
	AuthPassAlgoID 		uint8  				`json:"authPassAlgoId"`
	AuthPassAlgoName    string 				`json:"authPassAlgoName"`
	AuthTokenSize 		uint64              `json:"authTokenSize"`
	AuthTokenType 		string              `json:"authTokenType"`
	AuthEmailAddr 		string 				`json:"authEmailAddr"`
	AuthFullName 		string 				`json:"authFullName"`
	AuthPrivileges 		string 				`json:"authPrivileges"`
	AuthRestrictions 	string 				`json:"authRestrictions"`
	AuthPrivKeySize 	uint64 				`json:"authPrivKeySize"`
	AuthQuota 			uint64 				`json:"authQuota"`
	AuthMetaData 		map[string]string 	`json:"authMetaData"`
}

type authMetaNfo struct {
	Auth2FAEnabled 			bool   `json:"auth2FAEnabled"`
	AuthBasicEnabled 		bool   `json:"authBasicEnabled"`
	AuthCookieEnabled 		bool   `json:"authCookieEnabled"`
	AuthBearerEnabled 		bool   `json:"authBearerEnabled"`
	AuthTokenEnabled 		bool   `json:"authTokenEnabled"`
	AuthSignedTokensType 	string `json:"authSignedTokensType,omitempty"`
	AuthOpaqueTokensType 	string `json:"authOpaqueTokensType,omitempty"`
}

type authNfo struct {
	Status    *authStatusNfo 		`json:"status,omitempty"`
	MetaInfo  *authMetaNfo 			`json:"metaInfo,omitempty"`
	DebugData *smart.AuthDataStruct  `json:"debugData,omitempty"`
}

//-- auth token api
var RouteHandlerAuthApi HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (response HttpResponse) {
	//--
	// routes:
	// 			/auth
	// 			/auth/2fatotp
	// 			/auth/jwt
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if(len(tailPaths) > 1) {
		response.StatusCode = 400
		response.ContentBody = "Auth Api: Requested Route is Too Long"
		response.ContentFileName = "400.html"
		return
	} //end if
	//--
	var subRoute string = ""
	if(len(tailPaths) > 0) {
		subRoute = tailPaths[0]
	} //end if else
	//--
	response.StatusCode = 208
	response.ContentFileName = "error.json"
	//--
	var jwtSignMethod string = AuthTokenJwtAlgoGet()
	//--
	switch(subRoute) { // must be as: `/auth` | `/auth/2fatotp` | `auth/jwt` | `auth/jwt?expMinutes=2880`
		case "": // OK: handle: `/auth`
			if((!IsAjaxRequest(r)) && (RequestHaveQueryString(r))) { // dissalow query string, except ajax requests (ex: jQuery) which are appending a query string like `?12345` (timestamp) to the url get redirected with 302 before going to the route ...
				response.StatusCode = 302
				response.ContentBody = GetCurrentBrowserPath(r) // for 3xx the content is the redirect URL
				response.ContentFileName = "" // reset on 3xx
				return
			} //end if
			if(r.Method != "GET") {
				response.LogMessage = "Unsupported Request Method: `" + r.Method + "`"
				response.ContentBody = ResponseApiJsonERR(405, response.LogMessage, nil)
				return
			} //end if
			var tkTyp string = ""
			if(AuthTokenJwtIsEnabled() == true) {
				tkTyp = jwtSignMethod
				if(tkTyp != "") {
					tkTyp = "JWT:" + tkTyp
				} //end if
			} //end if
			var tkOpqTyp string = ""
			if(smart.AuthTokenIsEnabled() == true) {
				tkOpqTyp = smart.OPAQUE_TOKEN_FULL_NAME
			} //end if
			var errUserAuth string = authData.ErrMsg
			if(smart.AuthIsValidUserName(authData.UserName) != true) {
				errUserAuth = smart.StrTrimWhitespaces("ERR: UserName is Empty ; " + errUserAuth)
			} //end if
			var thePassHash string = authData.PassHash
			if(authData.PassAlgo == smart.ALGO_PASS_PLAIN) {
				thePassHash = "[Encrypted]:" + thePassHash
			} else if(authData.PassAlgo == smart.ALGO_PASS_NONE) {
				if(thePassHash != "") {
					thePassHash = "ERROR:(Not Empty)"
				} //end if
			} //end if
			metaInfo := authMetaNfo{
				Auth2FAEnabled: 		smart.Auth2FACookieIsEnabled(),
				AuthBasicEnabled: 		smart.AuthBasicIsEnabled(),
				AuthCookieEnabled: 		smart.AuthCookieIsEnabled(),
				AuthBearerEnabled: 		smart.AuthBearerIsEnabled(),
				AuthTokenEnabled: 		smart.AuthTokenIsEnabled(),
				AuthSignedTokensType: 	tkTyp,
				AuthOpaqueTokensType: 	tkOpqTyp,
			}
			status := authStatusNfo{
				Authenticated: authData.OK,
				AuthErrors: errUserAuth,
				AuthMethodID: authData.Method,
				AuthMethodName: "Auth:" + smart.AuthMethodGetNameById(authData.Method),
				AuthArea: authData.Area,
				AuthRealm: authData.Realm,
				AuthUserName: authData.UserName,
				AuthUserID: authData.UserID,
				AuthPassHash: thePassHash,
				AuthPassAlgoID: authData.PassAlgo,
				AuthPassAlgoName: smart.AuthPassHashAlgoGetNameById(authData.PassAlgo),
				AuthTokenSize: uint64(len(authData.TokenData)),
				AuthTokenType: authData.TokenAlgo,
				AuthEmailAddr: authData.EmailAddr,
				AuthFullName: authData.FullName,
				AuthPrivileges: authData.Privileges,
				AuthRestrictions: authData.Restrictions,
				AuthPrivKeySize: uint64(len(authData.PrivKey)),
				AuthQuota: authData.Quota,
				AuthMetaData: authData.MetaData,
			}
			nfo := authNfo {
				Status: &status,
				MetaInfo: &metaInfo,
			}
			if(DEBUG_AUTH) {
				nfo.DebugData = &authData // safe pointer, it is comming from current auth context (method)
			} //end if
			arrAccepts := GetClientMimeAcceptHeaders(r)
			acceptJson := smart.InListArr(smarthttputils.MIME_TYPE_JSON, arrAccepts)
			if(acceptJson) {
				response.ContentFileName = "auth.json"
				response.ContentBody = ResponseApiJsonOK(nfo)
			} else {
				var bwPath string = GetCurrentBrowserPath(r)
				var title = "Auth Info"
				var headHtml string = assets.HTML_CSS_STYLE_PREFER_COLOR_DARK + "\n"
				var bodyHtml string = "<h1>" + smart.EscapeHtml(title) + "</h1>" + "\n"
				bodyHtml += `<div class="operation_hint">API access point &nbsp;<i class="sfi sfi-lock sfi-xl" title="Requires Authentication" style="cursor:help;"></i> [Accept: ` + smart.EscapeHtml(smarthttputils.MIME_TYPE_JSON) + `]: <i>` + smart.EscapeHtml("`" + bwPath + "`") + `</i></div>` + "\n"
				bodyHtml += smart.RenderMarkersTpl(assets.ReadWebAsset("lib/tpl/syntax-highlight-init.inc.mtpl.htm"), map[string]string{
					"THEME": "", // ``, `dark`, `light`
					"AREAS": "body",
				})
				bodyHtml += smart.RenderMarkersTpl(assets.ReadWebAsset("lib/tpl/syntax-highlight-area.inc.mtpl.htm"), map[string]string{
					"SYNTAX": "json",
					"CODE": smart.JsonNoErrChkEncode(nfo, true, false),
				})
			//	bodyHtml += `<hr>` + "\n"
				response.ContentBody = srvassets.HtmlServerFaviconTemplate(title, headHtml, bodyHtml, true, assets.GetAuthLogo(false)) // load js
				response.ContentFileName = "auth.html"
			} //end if else
			response.StatusCode = 200
			return
		break
		case "2fatotp": // OK: handle: `/auth/2fatotp`
			if(RequestHaveQueryString(r)) { // dissalow query string
				response.StatusCode = 302
				response.ContentBody = GetCurrentBrowserPath(r) // for 3xx the content is the redirect URL
				response.ContentFileName = "" // reset on 3xx
				return
			} //end if
			if(r.Method != "GET") {
				response.StatusCode = 405
				response.LogMessage = "Unsupported Request Method: `" + r.Method + "`"
				response.ContentBody = response.LogMessage
				response.ContentFileName = "400.html"
				return
			} //end if
			if(authData.OK != true) {
				response.StatusCode = 403
				response.LogMessage = "Authentication is Required for this Area"
				response.ContentBody = response.LogMessage
				response.ContentFileName = "403.html"
				return
			} //end if
			if(authData.ErrMsg != "") {
				response.StatusCode = 500
				response.LogMessage = "Authentication Error: `" + authData.ErrMsg + "`"
				response.ContentBody = "Authentication Error"
				response.ContentFileName = "500.html"
				return
			} //end if
		//	if(authData.Method < 1) { // req. at least one valid auth method (min 1) ; see smart.see: HTTP_AUTH_MODE_*
			if((authData.Method != smart.HTTP_AUTH_MODE_BASIC) && (authData.Method != smart.HTTP_AUTH_MODE_COOKIE)) { // alow just Auth Basic and Cookie, they have also 2FA if enabled
				response.StatusCode = 403
				response.ContentBody = "Authentication Method is Not Accepted for this Area: [" + smart.ConvertUInt8ToStr(authData.Method) + "] / [Auth:" + smart.AuthMethodGetNameById(authData.Method) + "]"
				response.ContentFileName = "403.html"
				return
			} //end if
		//	if(smart.Auth2FACookieIsEnabled() != true) {
		//		response.StatusCode = 501
		//		response.ContentBody = "2FA Authentication is Disabled"
		//		response.ContentFileName = "501.html"
		//		return
		//	} //end if
			if(smart.AuthIsValidUserName(authData.UserName) != true) {
				response.StatusCode = 422
				response.ContentBody = "Authentication UserName is Empty or Invalid: `" + authData.UserName + "`"
				response.ContentFileName = "422.html"
				return
			} //end if
			rndSecret, totp, errTotp := Get2FATotp("") // random secret
			if((totp == nil) || (errTotp != nil)) {
				response.StatusCode = 500
				response.ContentBody = "TOTP Error"
				if(errTotp != nil) {
					response.ContentBody += ": `" + errTotp.Error() + "`"
				} //end if
				response.ContentFileName = "500.html"
				return
			} //end if
			var qrUrl string = totp.GenerateBarcodeUrl(authData.UserName, "SmartGoOTP2FA")
			//totpNum := totp.Now() // totp.At(time.Now().Unix())
			//var totpVfy bool = totp.Verify(totpNum, time.Now().Unix())
			svgQR, errSvgQR := qrsvg.New(qrUrl, "M", "#685A8B", "none", true, 4, 2) // use `none` instead of `#FFFFFF` for transparent background
			if(errSvgQR != nil) {
				response.StatusCode = 500
				response.ContentBody = "QR Code Error: `" + errSvgQR.Error() + "`"
				response.ContentFileName = "500.html"
				return
			} //end if
			var title = "Auth 2FA TOTP Code Generator"
		//	var headHtml string = "<style>img.svg { margin:10px; border:1px #EFEFEF solid; }</style>" + "\n"
			var headHtml string = assets.HTML_CSS_STYLE_PREFER_COLOR_DARK + "\n" + "<style>img.svg { margin:10px; }</style>" + "\n"
			var bodyHtml string = "<h1>" + smart.EscapeHtml(title) + "</h1>" + "\n"
			bodyHtml += `<hr>` + "\n"
			bodyHtml += `<h5>2FA Setup QRCode to use with <i style="color:#ED2839;">FreeOTP App</i> or similar 2FA authenticator apps:</h5><img class="svg" src="` + smart.EscapeHtml(smart.DATA_URL_SVG_IMAGE_PREFIX + smart.EscapeUrl(svgQR.Svg)) + `" title="` + smart.EscapeHtml(qrUrl) + `">` + "\n"
			bodyHtml += `<hr>` + "\n"
			bodyHtml += `<textarea id="area-secret" class="ux-field" style="width:320px; height:25px; font-size:0.625rem !important; color:#CDCDCD !important;" readonly>` + smart.EscapeHtml(rndSecret) + `</textarea>` + `&nbsp; <span style="color:#685A8B;">[&nbsp;username:&nbsp;` + "`<b>" + smart.EscapeHtml(authData.UserName) + "</b>`" + `&nbsp;]</span>` + "\n"
			bodyHtml += `<br>` + "\n"
			bodyHtml += `<script>const copyElemToClipboard = () => { const err = smartJ$Browser.copyToClipboard('area-secret'); const txt = 'Copy to Clipboard'; const img = '<br><i class="sfi sfi-clipboard"></i>'; if(!!err) { console.error('ERR: copyElemToClipboard:', err); smartJ$Browser.GrowlNotificationAdd(txt, 'FAILED to Copy the Secret to Clipboard' + img, null, 3500, false, 'pink'); } else { smartJ$Browser.GrowlNotificationAdd(txt, 'Secret has been Copied to Clipboard' + img, null, 1500, false, 'blue'); } };</script>` + "\n"
			bodyHtml += `<button class="ux-button ux-button-small ux-button-details" onclick="copyElemToClipboard(); return false;"><i class="sfi sfi-stack"></i>&nbsp; Copy Secret to Clipboard</button>`
			bodyHtml += `<br>` + "\n"
			bodyHtml += `<button class="ux-button ux-button-primary" onclick="self.location = self.location; return false;"><i class="sfi sfi-lg sfi-spinner9"></i>&nbsp; Generate New 2FA TOTP Code</button>`
			response.ContentBody = srvassets.HtmlServerFaviconTemplate(title, headHtml, bodyHtml, true, assets.GetAuthLogo(false)) // load js
			response.StatusCode = 200
			response.ContentFileName = "auth-2fatotp.html"
			return
		break
		case "jwt": // OK: handle: `/auth/jwt`
			if(r.Method != "GET") {
				response.LogMessage = "Unsupported Request Method: `" + r.Method + "`"
				response.ContentBody = ResponseApiJsonERR(405, response.LogMessage, nil)
				return
			} //end if
			if(authData.OK != true) {
				response.LogMessage = "Authentication is Required for this Area"
				response.ContentBody = ResponseApiJsonERR(403, response.LogMessage, nil)
				return
			} //end if
			if(authData.ErrMsg != "") {
				response.LogMessage = "Authentication Error: `" + authData.ErrMsg + "`"
				response.ContentBody = ResponseApiJsonERR(500, "Authentication Error", nil)
				return
			} //end if
		//	if(authData.Method < 1) { // req. at least one valid auth method (min 1) ; see smart.see: HTTP_AUTH_MODE_*
			if((authData.Method != smart.HTTP_AUTH_MODE_BASIC) && (authData.Method != smart.HTTP_AUTH_MODE_COOKIE) && (authData.Method != smart.HTTP_AUTH_MODE_BEARER)) { // alow just: Auth Basic, Cookie, Bearer ; the first two may have also 2FA if enabled, and the last one must be able to re-generate the token before expiration
				response.ContentBody = ResponseApiJsonERR(403, "Authentication Method is Not Accepted for this Area: [" + smart.ConvertUInt8ToStr(authData.Method) + "] / [Auth:" + smart.AuthMethodGetNameById(authData.Method) + "]", nil)
				return
			} //end if
			if(AuthTokenJwtIsEnabled() != true) {
				response.ContentBody = ResponseApiJsonERR(501, "Authentication JWT is Disabled", nil)
				return
			} //end if
			if(smart.StrTrimWhitespaces(jwtSignMethod) == "") {
				response.ContentBody = ResponseApiJsonERR(501, "Authentication JWT Algo is Empty or N/A", nil)
				return
			} //end if
			if(smart.AuthIsValidUserName(authData.UserName) != true) {
				response.ContentBody = ResponseApiJsonERR(422, "Authentication UserName is Empty or Invalid: `" + authData.UserName + "`", nil)
				return
			} //end if
			if(smart.AuthIsValidPrivKey(authData.PrivKey) != true) {
				response.ContentBody = ResponseApiJsonERR(422, "Authenticated User`s Private Key is Empty or Invalid: [" + smart.ConvertIntToStr(len(authData.PrivKey)) + " bytes]", nil)
				return
			} //end if
			//--
			var expMinutesStr string = GetUrlQueryParam(r, "expMinutes")
			var expMinutes int64 = 0
			if((expMinutesStr != "") && (len(expMinutesStr) <= 7)) { // max: 9999999 minutes ~ 19 years
				expMinutes = smart.ParseStrAsInt64(expMinutesStr)
			} //end if
			if((expMinutes < JwtMinExpirationMinutes) || (expMinutes > JwtMaxExpirationMinutes)) {
				expMinutes = JwtDefaultExpirationMinutes
			} //end if
			//--
			basedom, dom, port, errDomPort := GetBaseDomainDomainPort(r)
			if(errDomPort != nil) {
				response.ContentBody = ResponseApiJsonERR(502, "Authentication Domain:Port Failed: `" + errDomPort.Error() +  "`", nil)
				return
			} //end if
			if((basedom == "") || (dom == "") || (port == "")) {
				response.ContentBody = ResponseApiJsonERR(502, "Authentication Domain:Port is Invalid: `" + dom + ":" + port + "` ; base domain is: `" + basedom + "`", nil)
				return
			} //end if
			//--
			data, errData := JwtNew(jwtSignMethod, expMinutes, dom, port, authData.UserName, authData.PrivKey)
			if(errData != nil) {
				response.ContentBody = ResponseApiJsonERR(500, "JWT ERR: " + errData.Error(), nil)
				return
			} //end if
			//--
			arrAccepts := GetClientMimeAcceptHeaders(r)
			acceptJson := smart.InListArr(smarthttputils.MIME_TYPE_JSON, arrAccepts)
			if(acceptJson) {
				response.ContentBody = ResponseApiJsonOK(data)
				response.ContentFileName = "auth-token.json"
			} else {
				var bwPath string = GetCurrentBrowserPath(r)
				var title = "JWT Access Token"
				var headHtml string = assets.HTML_CSS_STYLE_PREFER_COLOR_DARK + "\n"
				var bodyHtml string = "<h1>" + smart.EscapeHtml(title) + "</h1>" + "\n"
				bodyHtml += `<hr>` + "\n"
				bodyHtml += `<div class="operation_hint">API access point &nbsp;<i class="sfi sfi-lock sfi-xl" title="Requires Authentication" style="cursor:help;"></i> [Accept: ` + smart.EscapeHtml(smarthttputils.MIME_TYPE_JSON) + `]: <i>` + smart.EscapeHtml("`" + bwPath + "`") + `</i> ; Query Parameters: (<i>?expMinutes=` + smart.ConvertInt64ToStr(JwtMinExpirationMinutes) + `..` + smart.ConvertInt64ToStr(JwtMaxExpirationMinutes) + `</i>)</div>` + "\n"
				bodyHtml += smart.RenderMarkersTpl(assets.ReadWebAsset("lib/tpl/syntax-highlight-init.inc.mtpl.htm"), map[string]string{
					"THEME": "", // ``, `dark`, `light`
					"AREAS": "body",
				})
				bodyHtml += smart.RenderMarkersTpl(assets.ReadWebAsset("lib/tpl/syntax-highlight-area.inc.mtpl.htm"), map[string]string{
					"SYNTAX": "json",
					"CODE": smart.JsonNoErrChkEncode(data, true, false),
				})
			//	bodyHtml += `<hr>` + "\n"
				bodyHtml += `<br>` + "\n"
				bodyHtml += `<b>LifeTime&nbsp;(minutes):</b>&nbsp;<input id="mins" class="ux-field" type="number" value="` + smart.ConvertInt64ToStr(expMinutes) + `" min="` + smart.ConvertInt64ToStr(JwtMinExpirationMinutes) + `" max="` + smart.ConvertInt64ToStr(JwtMaxExpirationMinutes) + `" autocomplete="off">` + "\n"
				bodyHtml += `<button class="ux-button ux-button-regular" onclick="let mins = smartJ$Utils.format_number_int(jQuery('input#mins').val(), false); if((!mins) || (!smartJ$Utils.isFiniteNumber(mins)) || (mins <= 0)) { smartJ$Browser.GrowlNotificationAdd('Error', '&lt;h5&gt;Invalid or Non-Numeric Expression&lt;/h5&gt;', '', 3500, false, 'pink'); } else { setTimeout(() => { self.location = '` + smart.EscapeJs(bwPath) + `?expMinutes=' + smartJ$Utils.escape_url(mins); }, 50); }"><i class="sfi sfi-lg sfi-spinner10"></i>&nbsp; Generate New JWT Access Token</button>` + "\n"
				response.ContentBody = srvassets.HtmlServerFaviconTemplate(title, headHtml, bodyHtml, true, assets.GetAuthLogo(false)) // load js
				response.ContentFileName = "auth.html"
			} //end if else
			response.StatusCode = 200
			return
		break
		default:
			// N/A
	} //end switch
	//--
	response.StatusCode = 404
	response.LogMessage = "Invalid Auth Api Request Sub-Path"
	response.ContentBody = response.LogMessage
	response.ContentFileName = "404.html"
	return
	//--
} //end fx


// #END
