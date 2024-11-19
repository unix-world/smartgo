
// GO Lang :: SmartGo / Web Server / Auth :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241116.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"net/http"

	smart 			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web/assets/web-assets"
	srvassets 		"github.com/unix-world/smartgo/web/assets/srv-assets"
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
	AuthPassHashSize    uint64              `json:"authPassHashSize"`
	AuthPassAlgoID 		uint8  				`json:"authPassAlgoId"`
	AuthTokenSize       uint64              `json:"authTokenSize"`
	AuthTokenAlgo       string              `json:"authTokenAlgo"`
	AuthEmailAddr 		string 				`json:"authEmailAddr"`
	AuthFullName 		string 				`json:"authFullName"`
	AuthPrivileges 		string 				`json:"authPrivileges"`
	AuthRestrictions 	string 				`json:"authRestrictions"`
	AuthPrivKeySize 	uint64 				`json:"authPrivKeySize"`
	AuthQuota 			uint64 				`json:"authQuota"`
	AuthMetaData 		map[string]string 	`json:"authMetaData"`
}

type authMetaNfo struct {
	Auth2FAEnabled    bool   `json:"auth2FAEnabled"`
	AuthBasicEnabled  bool   `json:"authBasicEnabled"`
	AuthBearerEnabled bool   `json:"authBearerEnabled"`
	AuthCookieEnabled bool   `json:"authCookieEnabled"`
	AuthTokenEnabled  bool   `json:"authTokenEnabled"`
	AuthTokensAlgo    string `json:"AuthTokensAlgo,omitempty"`
}

type authNfo struct {
	Status    authStatusNfo 		`json:"status,omitempty"`
	MetaInfo  authMetaNfo 			`json:"metaInfo,omitempty"`
	DebugData *smart.AuthDataStruct `json:"debugData,omitempty"`
}

//-- auth token api
var RouteHandlerAuthApi HttpHandlerFunc = func(r *http.Request, headPath string, tailPaths []string, authData smart.AuthDataStruct) (response HttpResponse) {
	//--
	// routes:
	// 			/auth
	// 			/auth/2fatotp
	// 			/auth/token
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
	var jwtSignMethod string = smart.AuthTokenJwtAlgoGet()
	//--
	switch(subRoute) { // must be as: `/auth` | `/auth/2fatotp` | `auth/token` | `auth/token?expMinutes=2880`
		case "": // OK: handle: `/auth`
			if(RequestHaveQueryString(r)) { // dissalow query string
				response.StatusCode = 302
				response.ContentBody = GetCurrentBrowserPath(r) // for 3xx the content is the redirect URL
				return
			} //end if
			if(r.Method != "GET") {
				response.LogMessage = "Unsupported Request Method: `" + r.Method + "`"
				response.ContentBody = ResponseApiJsonErr(405, response.LogMessage, nil)
				return
			} //end if
			var tkTyp string = ""
			if(smart.AuthTokenJwtIsEnabled() == true) {
				tkTyp = jwtSignMethod
				if(tkTyp != "") {
					tkTyp = "JWT:" + tkTyp
				} //end if
			} //end if
			var errUserAuth string = authData.ErrMsg
			if(smart.AuthIsValidUserName(authData.UserName) != true) {
				errUserAuth = smart.StrTrimWhitespaces("ERR: UserName is Empty ; " + errUserAuth)
			} //end if
			metaInfo := &authMetaNfo{
				Auth2FAEnabled:    smart.Auth2FACookieIsEnabled(),
				AuthBasicEnabled:  smart.AuthBasicIsEnabled(),
				AuthBearerEnabled: smart.AuthBearerIsEnabled(),
				AuthTokenEnabled:  smart.AuthTokenIsEnabled(),
				AuthCookieEnabled: smart.AuthCookieIsEnabled(),
				AuthTokensAlgo:    tkTyp,
			}
			status := &authStatusNfo{
				Authenticated: authData.OK,
				AuthErrors: errUserAuth,
				AuthMethodID: authData.Method,
				AuthMethodName: smart.AuthMethodGetNameById(authData.Method),
				AuthArea: authData.Area,
				AuthRealm: authData.Realm,
				AuthUserName: authData.UserName,
				AuthUserID: authData.UserID,
				AuthPassHashSize: uint64(len(authData.PassHash)),
				AuthPassAlgoID: authData.PassAlgo,
				AuthTokenSize: uint64(len(authData.TokenData)),
				AuthTokenAlgo: authData.TokenAlgo,
				AuthEmailAddr: authData.EmailAddr,
				AuthFullName: authData.FullName,
				AuthPrivileges: authData.Privileges,
				AuthRestrictions: authData.Restrictions,
				AuthPrivKeySize: uint64(len(authData.PrivKey)),
				AuthQuota: authData.Quota,
				AuthMetaData: authData.MetaData,
			}
			nfo := &authNfo {
				Status: *status,
				MetaInfo: *metaInfo,
			}
			if(DEBUG_AUTH) {
				nfo.DebugData = &authData
			} //end if
			response.StatusCode = 200
			response.ContentFileName = "auth.json"
			response.ContentBody = ResponseApiJsonOK(nfo)
			return
		break
		case "2fatotp": // OK: handle: `/auth/2fatotp`
			if(RequestHaveQueryString(r)) { // dissalow query string
				response.StatusCode = 302
				response.ContentBody = GetCurrentBrowserPath(r) // for 3xx the content is the redirect URL
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
			if(authData.Method < 1) { // req. at least one valid auth method (min 1) ; see smart.see: HTTP_AUTH_MODE_*
				response.StatusCode = 500
				response.ContentBody = "Authentication Method is Invalid: [" + smart.ConvertUInt8ToStr(authData.Method) + "]"
				response.ContentFileName = "500.html"
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
			var qrUrl string = totp.GenerateBarcodeUrl("user", "SmartGoOTP2FA")
			//totpNum := totp.Now() // totp.At(time.Now().Unix())
			//var totpVfy bool = totp.Verify(totpNum, time.Now().Unix())
			svgQR, errSvgQR := qrsvg.New(qrUrl, "M", "#ED2839", "#FFFFFF", true, 4, 2)
			if(errSvgQR != nil) {
				response.StatusCode = 500
				response.ContentBody = "QR Code Error: `" + errSvgQR.Error() + "`"
				response.ContentFileName = "500.html"
				return
			} //end if
			var title = "2FA QrCode"
		//	var headHtml string = assets.HTML_CSS_STYLE_PREFER_COLOR_DARK + "\n" + "<style>img.svg { margin:10px; border:1px #EFEFEF solid; }</style>"
			var headHtml string = "<style>img.svg { margin:10px; border:1px #EFEFEF solid; }</style>"
			var bodyHtml string = "<h1>Auth 2FA TOTP Code Generator</h1>" + "\n"
			bodyHtml += `<hr>` + "\n"
			bodyHtml += `<h5>2FA Setup QRCode to use with <i>FreeOTP App</i> or similar:</h5><img src="` + smart.EscapeHtml(smart.DATA_URL_SVG_IMAGE_PREFIX + smart.EscapeUrl(svgQR.Svg)) + `" title="` + smart.EscapeHtml(qrUrl) + `">` + "\n"
			bodyHtml += `<hr>` + "\n"
			bodyHtml += `<textarea id="area-secret" class="ux-field" style="width:320px; height:25px; font-size:0.625rem !important; color:#CDCDCD !important;" readonly>` + smart.EscapeHtml(rndSecret) + `</textarea>` + "\n"
			bodyHtml += `<br>` + "\n"
			bodyHtml += `<script>const copyElemToClipboard = () => { const err = smartJ$Browser.copyToClipboard('area-secret'); const txt = 'Copy to Clipboard'; const img = '<br><i class="sfi sfi-clipboard"></i>'; if(!!err) { console.error('ERR: copyElemToClipboard:', err); smartJ$Browser.GrowlNotificationAdd(txt, 'FAILED to Copy the Secret to Clipboard' + img, null, 3500, false, 'pink'); } else { smartJ$Browser.GrowlNotificationAdd(txt, 'Secret has been Copied to Clipboard' + img, null, 1500, false, 'blue'); } };</script>` + "\n"
			bodyHtml += `<button class="ux-button ux-button-primary" onclick="copyElemToClipboard(); return false;">Copy Secret to Clipboard</button>`
			response.ContentBody = srvassets.HtmlServerFaviconTemplate(title, headHtml, bodyHtml, true, assets.GetAuthLogo(false)) // load js
			response.StatusCode = 200
			response.ContentFileName = "auth-2fatotp.html"
			return
		break
		case "token": // OK: handle: `/auth/token`
			if(r.Method != "GET") {
				response.LogMessage = "Unsupported Request Method: `" + r.Method + "`"
				response.ContentBody = ResponseApiJsonErr(405, response.LogMessage, nil)
				return
			} //end if
			if(authData.OK != true) {
				response.LogMessage = "Authentication is Required for this Area"
				response.ContentBody = ResponseApiJsonErr(403, response.LogMessage, nil)
				return
			} //end if
			if(authData.ErrMsg != "") {
				response.LogMessage = "Authentication Error: `" + authData.ErrMsg + "`"
				response.ContentBody = ResponseApiJsonErr(500, "Authentication Error", nil)
				return
			} //end if
			if(authData.Method < 1) { // req. at least one valid auth method (min 1) ; see smart.see: HTTP_AUTH_MODE_*
				response.ContentBody = ResponseApiJsonErr(500, "Authentication Method is Invalid: [" + smart.ConvertUInt8ToStr(authData.Method) + "]", nil)
				return
			} //end if
			if(smart.AuthTokenJwtIsEnabled() != true) {
				response.ContentBody = ResponseApiJsonErr(501, "Authentication JWT is Disabled", nil)
				return
			} //end if
			if(smart.StrTrimWhitespaces(jwtSignMethod) == "") {
				response.ContentBody = ResponseApiJsonErr(501, "Authentication JWT Algo is Empty or N/A", nil)
				return
			} //end if
			if(smart.AuthIsValidUserName(authData.UserName) != true) {
				response.ContentBody = ResponseApiJsonErr(422, "Authentication UserName is Empty or Invalid: `" + authData.UserName + "`", nil)
				return
			} //end if
			if(smart.AuthIsValidPrivKey(authData.PrivKey) != true) {
				response.ContentBody = ResponseApiJsonErr(422, "Authenticated User`s Private Key is Empty or Invalid: [" + smart.ConvertIntToStr(len(authData.PrivKey)) + " bytes]", nil)
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
				response.ContentBody = ResponseApiJsonErr(502, "Authentication Domain:Port Failed: `" + errDomPort.Error() +  "`", nil)
				return
			} //end if
			if((basedom == "") || (dom == "") || (port == "")) {
				response.ContentBody = ResponseApiJsonErr(502, "Authentication Domain:Port is Invalid: `" + dom + ":" + port + "` ; base domain is: `" + basedom + "`", nil)
				return
			} //end if
			//--
			data, errData := JwtNew(jwtSignMethod, expMinutes, dom, port, authData.UserName, authData.PrivKey)
			if(errData != nil) {
				response.ContentBody = ResponseApiJsonErr(500, "JWT ERR: " + errData.Error(), nil)
				return
			} //end if
			//--
			response.StatusCode = 200
			response.ContentBody = ResponseApiJsonOK(data)
			response.ContentFileName = "auth-token.json"
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
