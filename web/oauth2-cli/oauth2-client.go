
// SmartGo Web OAuth2 :: Client API
// (c) 2026-present unix-world.org
// v.20260817.2358
// license: BSD

package oauth2cli

import (
	"fmt"
	"log"

//	"net/http"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)

const (
	OAUTH2_REQUEST_TIMEOUT 			uint32 =    15 // default timeout
	OAUTH2_REQUEST_MAX_TIMEOUT 		uint32 =    60 // default max timeout
	OAUTH2_REQUEST_MAX_REDIRECTS 	 uint8 =     2 // max number of allowed redirects
	OAUTH2_REQUEST_MAX_BODY_SIZE 	uint64 = 65535 // max allowed response body size in bytes
	OAUTH2_REQUEST_MAX_INPUT_SIZE 	uint16 =  4096 // max input value size ; normally the max allowed value by UI is the code, 3072, but let it flexible, 4096

	OAUTH2_AUTHORIZE_URL_CHPART 	string = `&code_challenge=[###CODE-CHALLENGE|trim|url###]&code_challenge_method=[###METHOD-CHALLENGE|trim|url###]` // ex: code_challenge_method=S256 as 'sha256' which is currently wide supported ; github does not support others
	OAUTH2_AUTHORIZE_URL_PARAMS 	string = `response_type=code&client_id=[###CLIENT-ID|trim|url###]&scope=[###SCOPE|trim|url###]&redirect_uri=[###REDIRECT-URI|trim|url###]&state=[###STATE|trim|url###]`
	OAUTH2_STANDALONE_REDIRECT_URL 	string = `urn:ietf:wg:oauth:2.0:oob`

	OAUTH2_PATTERN_VALID_ID 		string = `^[_a-zA-Z0-9,@\#\/\-\:\.]{5,127}$`; // OK

	DEBUG bool = false
)


// #method-PKCE=S224|S256|S384|S512|3S224|3S256|3S384|3S512 ; optional ; if not specified will use the default one: S256
// #skip-PKCE=authorize|refresh ; optional ; if set will skip sending the PKCE code challenge part: OAUTH2_AUTHORIZE_URL_CHPART
// #post-PARAMS=rawurlencode('a=b&c=d') ; ex: #post-PARAMS=token_content_type%3Djwt ; extra POST parameters


//-----


func OAuth2DataKeys() []string { // OAuth2 Input
	//--
	return []string{
		"id",
		"description",
		"client_id",
		"client_secret",
		"scope",
		"url_redirect",
		"url_auth",
		"url_token",
		"code", // this code must come from the Authorize sequence steps, using a browser
	}
	//--
} //END FUNCTION


type oauth2Record struct { // OAuth2 Output
	Error 				string 		`json:"error,omitempty"`

	TypeToken 			string 		`json:"token_type"` 		// ex: bearer
	AccessToken 		string 		`json:"access_token"`
	ExpiresIn 			uint64 		`json:"expires_in,string"` 	// expires in seconds for the Access Token ; if a Refresh Token is provided this is mandatory, otherwise if zero or not provided may not expire
	RefreshToken 		string 		`json:"refresh_token"` 		// optional, expiration time is not provided an may vary a lot by provider
	IdToken 			string 		`json:"id_token"` 			// this is completely optional and only provided if supports OpenID
	Scope 				string 		`json:"scope"`
}


func GetTokensFromServer(grantRefresh bool, data map[string]string, timeout uint32, allowRedirects bool, authUser string, authPass string) oauth2Record {
	//--
	o2Rec := oauth2Record{}
	//--
	if(data == nil) {
		o2Rec.Error = "Data is Null"
		return o2Rec
	} //end if
	if(len(data) <= 0) {
		o2Rec.Error = "Invalid Data Format"
		return o2Rec
	} //end if else
	//--
	var requiredKeys []string = OAuth2DataKeys()
	if(requiredKeys == nil) {
		o2Rec.Error = "Required Data Keys is Null"
		return o2Rec
	} //end if
	if(len(requiredKeys) <= 0) {
		o2Rec.Error = "Required Data Keys is Empty"
		return o2Rec
	} //end if
	for _, key := range requiredKeys {
		val, ok := data[key]
		if(!ok) {
			o2Rec.Error = "Invalid Data Structure"
			return o2Rec
		} else if(len(val) > int(OAUTH2_REQUEST_MAX_INPUT_SIZE)) {
			o2Rec.Error = "Data Value is Oversized: " + key
			return o2Rec
		} else if(val != "") { // do not throw here is valud is empty, some values may be empty for authorize or refresh and will be checked below
			if(!smart.StrRegexMatch(smart.REGEX_ASCII_ANDSPACE_CHARACTERS, val)) { // safety
				o2Rec.Error = "Data Value is Invalid: " + key
				return o2Rec
			} //end if
		} //end if else
	} //end for
	//--
	var dataId string = smart.StrTrimWhitespaces(data["id"]) // trim, code verifier uses trimmed id
	if(dataId == "") {
		o2Rec.Error = "Empty ID for the Token API Initialization"
		return o2Rec
	} //end if
	if(!smart.StrRegexMatch(OAUTH2_PATTERN_VALID_ID, dataId)) { // // {{{SYNC-OAUTH2-REGEX-ID}}}
		o2Rec.Error = "Invalid ID for the Token API Initialization"
		return o2Rec
	} //end if
	//--
	var dataDesc string = smart.StrTrimWhitespaces(data["description"]) // trim
	//--
	var urlToken string = smart.StrTrimWhitespaces(data["url_token"])
	if(urlToken == "") {
		o2Rec.Error = "Token URL is Empty"
		return o2Rec
	} //end if
	if(!smart.StrStartsWith(urlToken, "https://")) { // {{{SYNC-OAUTH2-VALIDATE-URL}}} ; {{{SYNC-OAUTH2-TOKEN-URL-IS-HTTPS}}} ; this is mandatory, otherwise is not secure
		o2Rec.Error = "Invalid Token URL, must start with https:// ..."
		return o2Rec
	} //end if
	//--
	var urlAuth string = smart.StrTrimWhitespaces(data["url_auth"])
	if(urlAuth == "") {
		o2Rec.Error = "Auth URL is Empty"
		return o2Rec
	} //end if
	//--
	var urlStr string = urlToken // cast to a new variable, will be modified below
	uarrT := parseUrlAndSettings(urlStr)
	if(uarrT.Error != "") {
		o2Rec.Error = "Parse Token URL Failed: " + uarrT.Error
		return o2Rec
	} //end if
	urlStr = smart.StrTrimWhitespaces(uarrT.Url) // settings for init have to be used from auth URL
	if(urlStr == "") {
		o2Rec.Error = "Parse Token URL Failed, Empty URL"
		return o2Rec
	} //end if
	//--
	var aurl string = urlAuth // cast to a new variable, will be modified below
	uarrA := parseUrlAndSettings(aurl)
	if(uarrA.Error != "") {
		o2Rec.Error = "Parse Auth URL Failed: " + uarrA.Error
		return o2Rec
	} //end if
	//--
	var settings map[string]string = nil // must be initialized as null, verified below
	if(grantRefresh) { // refresh token
		settings = uarrT.Settings // use the settings from token URL
	} else { // access token
		settings = uarrA.Settings // use the settings from auth URL
	} //end if else
	if(settings == nil) {
		o2Rec.Error = "Settings are Null"
		return o2Rec
	} //end if
	//--
	var urlRedirect string = smart.StrTrimWhitespaces(data["url_redirect"])
	if(urlRedirect == "") {
		o2Rec.Error = "Redirect URL is Empty"
		return o2Rec
	} //end if
	//--
	var clientSecret string = smart.StrTrimWhitespaces(data["client_secret"])
	if(clientSecret == "") {
		o2Rec.Error = "Client Secret is Empty"
		return o2Rec
	} //end if
	//--
	var clientId string = smart.StrTrimWhitespaces(data["client_id"])
	if(clientId == "") {
		o2Rec.Error = "Client ID is Empty"
		return o2Rec
	} //end if
	//--
	var code string = smart.StrTrimWhitespaces(data["code"])
	if(!grantRefresh) { // access token only
		if(code == "") {
			o2Rec.Error = "Code is Empty"
			return o2Rec
		} //end if
	} //end if
	//--
	var cVfy string = smart.StrTrimWhitespaces(CodeVerifier(dataId, clientId))
	if(cVfy == "") {
		o2Rec.Error = "Invalid Code Verifier, Failed"
		return o2Rec
	} //end if
	//--
	var refreshToken string = smart.StrTrimWhitespaces(data["refresh_token"])
	if(grantRefresh) { // refresh token only
		if(refreshToken == "") {
			o2Rec.Error = "Refresh Token is Empty"
			return o2Rec
		} //end if
	} //end if
	//--
	var hdrsArr map[string][]string = map[string][]string{
		smarthttputils.HTTP_HEADER_ACCEPT_MIMETYPE: { "application/json" }, // this is mandatory for this implementation, below it only parses a json answer
	}
	var ckyArr map[string]string = map[string]string{}
	var postArr map[string][]string = map[string][]string{}
	if(grantRefresh) { // refresh token
		postArr = map[string][]string{
			"grant_type":    { "refresh_token" },
			"refresh_token": { refreshToken },
			"client_id":     { clientId },
			"client_secret": { clientSecret },
		}
	} else { // access token
		postArr = map[string][]string{
			"grant_type":    { "authorization_code" },
			"client_id":     { clientId },
			"client_secret": { clientSecret },
			"redirect_uri":  { urlRedirect },
			"code":          { code },
		}
	} //end if else
	const allowPostFiles bool = false // SECURITY: this must be explicit disallowed and set as CONSTANT to prevent modifications ; POST params below come from untrusted source (client input) so avoid by mistake use @File POST Type Parameters ... ;-)
	//--
	var timeoutSec uint32 = OAUTH2_REQUEST_TIMEOUT
	if((timeout >= OAUTH2_REQUEST_TIMEOUT) && (timeout <= OAUTH2_REQUEST_MAX_TIMEOUT)) {
		timeoutSec = timeout // {{{SYNC-OAUTH2-REQUEST-TIMEOUT}}}
	} //end if
	//--
	skipPKCE, issetSkipPKCE := settings["skip-PKCE"]
	skipPKCE = smart.StrTrimWhitespaces(skipPKCE)
	methodPKCE, issetMethodPKCE := settings["method-PKCE"]
	methodPKCE = smart.StrTrimWhitespaces(methodPKCE)
	if(issetSkipPKCE == true) {
		if(issetMethodPKCE == true) {
			o2Rec.Error = "PKCE Method and PKCE Skip cannot be used together, use either"
			return o2Rec
		} //end if
	} else {
		if(issetMethodPKCE == true) {
			if(getValidPKCEMethod(methodPKCE) == "") {
				o2Rec.Error = "Invalid PKCE Method: `" + methodPKCE + "`"
				return o2Rec
			} //end if
		} //end if
		if(!grantRefresh) { // access token only
			postArr["code_verifier"] = []string{ cVfy } // code verifier should not be posted or required when using a refresh token, it is only used once during the initial exchange of the authorization code for tokens
		} //end if
	} //end if
	//--
	postParams, issetPostParams := settings["post-PARAMS"]
	postParams = smart.StrTrimWhitespaces(postParams)
	if(issetPostParams == true) { // ex: the /authorize url when open in browser must send some params by get and after by post ...
		extraParams := smart.ParseUrlRawQuery(postParams)
		if(len(extraParams) > 0) {
			removeParams := []string{}
			for kk, vv := range extraParams {
				kk = smart.StrTrimWhitespaces(kk)
				if(kk != "") {
					if _, exists := postArr[kk]; !exists {
						if(smarthttputils.IsPostFormFileUploadTypeParameterName(kk)) { // ensure not using by mistake @file type params, they come from untrusted source
							o2Rec.Error = "@File POST Form PARAM is Disallowed, Key: `" + kk + "`"
							return o2Rec
						} //end if
						if(!smarthttputils.IsValidPostFormParameterName(kk)) { // ensure kei is valid + redundant check for using by mistake @file type params, they come from untrusted source
							o2Rec.Error = "Invalid POST Form PARAM, Key: `" + kk + "`"
							return o2Rec
						} //end if
						removeParams = append(removeParams, kk) // must be removed from URL by GET method ; will be sent below with POST method
						postArr[kk] = vv // may be string ([0]) or array ([0..n])
					} //end if
				} //end if
			} //end foreach
			if(len(removeParams) > 0) {
				urlStr = smart.UrlRemoveQueryParams(urlStr, removeParams)
			} //end if
		} //end if
	} //end if
	//--
	var tlsInsecureSkipVerify bool = true
	if(allowInsecureHTTPS(urlStr) != true) {
		tlsInsecureSkipVerify = false // enable SSL/TLS Strict Secure Mode
	} //end if
	//--
	var maxRedirects uint8 = 0
	if(allowRedirects == true) {
		maxRedirects = OAUTH2_REQUEST_MAX_REDIRECTS
	} //end if
	//--
	httpResult := smarthttputils.HttpClientDoRequestPOST(
		urlStr,
		"", // tlsServerPEM
		tlsInsecureSkipVerify,
		hdrsArr,
		ckyArr,
		allowPostFiles,
		postArr,
		timeoutSec,
		OAUTH2_REQUEST_MAX_BODY_SIZE,
		maxRedirects,
		authUser,
		authPass,
	)
	if(httpResult.BodyDataSize > 0) { // this step is necessary to ensure a positive integer as below is compared with uint64
		if(httpResult.BodyDataSize > OAUTH2_REQUEST_MAX_BODY_SIZE) {
			httpResult.BodyData = smart.StrSubstr(httpResult.BodyData, 0, int(OAUTH2_REQUEST_MAX_BODY_SIZE))
		} //end if
	} //end if
	if(DEBUG) {
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "DEBUG.Post-Vars:", postArr)
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "DEBUG.Server-Response:", fmt.Sprintf("%#v\n", httpResult))
	} //end if
	if(httpResult.HttpStatus != 200) {
		o2Rec.Error = "Invalid HTTP(S) Answer / Status Code: `" + smart.ConvertIntToStr(httpResult.HttpStatus) + "`"
		if(len(httpResult.BodyData) > 0) {
			o2Rec.Error += "\n" + parseErrAnswer(httpResult.BodyData)
		} //end if
		return o2Rec
	} //end if
	//--
	o2Rec = parseAccessTokenAnswer(httpResult.BodyData, httpResult.MimeType)
	if(DEBUG) {
		log.Println("[DEBUG]", smart.CurrentFunctionName(), "DEBUG.oAuth2.Data", fmt.Sprintf("%#v\n", o2Rec), "Details:", dataDesc)
	} //end if
	//--
	return o2Rec
	//--
} //END FUNCTION


//-----


func CodeVerifier(id string, cid string) string { // {{{SYNC-OAUTH2-CODE-VERIFIER}}}
	//--
	// this have to be public as a backup to the Javascript Code Verifier method for testing purposes only
	//--
	defer smart.PanicHandler()
	//--
	id = smart.StrTrimWhitespaces(id)
	if(id == "") {
		return ""
	} //end if
	//--
	cid = smart.StrTrimWhitespaces(cid)
	if(cid == "") {
		return ""
	} //end if
	//-- must contain only: A-Z a-z 0-9 - . _ ~
	hmcHex, errHmc := smart.HashHmac("sha3-384", smart.DataRot13(smart.Base64sEncode(id)), cid, false)
	if(errHmc != nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "# OAuth2: HMac Failed:", errHmc)
		return ""
	} //end if
	var cVfy string = smart.BaseEncode([]byte(smart.Hex2Bin(hmcHex)), "b62")
	//--
	if((smart.StrTrimWhitespaces(cVfy) == "") || (len(cVfy) < 43) || (len(cVfy) > 128)) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "# OAuth2: Code Verifier is Empty or Invalid !")
		return ""
	} //end if
	//--
	return cVfy
	//--
} //END FUNCTION


//-----


func parseAccessTokenAnswer(body string, mimeType string) oauth2Record {
	//--
	o2Rec := oauth2Record{}
	//--
	body = smart.StrTrimWhitespaces(body)
	if(body == "") {
		o2Rec.Error = "Parse AccessToken Data: Body is Empty"
		return o2Rec
	} //end if
	//--
	mimeType = smart.StrToLower(smart.StrTrimWhitespaces(mimeType))
	switch(mimeType) {
		case "application/json": fallthrough
		case "text/json":        fallthrough
		case "text/plain":       fallthrough
		case "":
			// OK
			break
		case "text/html":        fallthrough
		default:
			o2Rec.Error = "Parse AccessToken Data: Body is Not JSON MimeType: " + mimeType
			return o2Rec
	} //end switch
	//--
	jsonObj := smart.JsonGetValueByKeyPath(body, "")
	if(jsonObj == nil) {
		o2Rec.Error = "Parse AccessToken Data: JSON is Null"
		return o2Rec
	} //end if
	if(jsonObj.Value() == nil) {
		o2Rec.Error = "Parse AccessToken Data: JSON is Invalid [" + mimeType + "]:" + "\n" + smart.HTMLCodeStripTags(body)
		return o2Rec
	} //end if
	//--
	var err []string = []string{}
	//--
	var theErr string = parseErrAnswer(body)
	if(theErr != "") {
		o2Rec.Error = "ERROR: " + theErr
		return o2Rec
	} //end if
	//--
	o2Rec.TypeToken 		= smart.StrToLower(smart.StrTrimWhitespaces(jsonObj.Get("token_type").String()))
	if(o2Rec.TypeToken == "") {
		err = append(err, "Token Type is Empty")
	} else if(o2Rec.TypeToken != "bearer") {
		err = append(err, "Invalid Token Type, expected `bearer`")
	} //end if
	//--
	o2Rec.AccessToken 		= smart.StrTrimWhitespaces(jsonObj.Get("access_token").String())
	if(o2Rec.AccessToken == "") {
		err = append(err, "Access Token is Empty")
	} //end if
	//--
	var expiresIn int64 	= jsonObj.Get("expires_in").Int()
	if(expiresIn >= 0) { // avoid pass negative to UInt64
		o2Rec.ExpiresIn 	= uint64(expiresIn)
	} else {
		err = append(err, "Access Token is Invalid: `" + jsonObj.Get("expires_in").String() + "`")
	} //end if else
	//--
	o2Rec.RefreshToken 		= smart.StrTrimWhitespaces(jsonObj.Get("refresh_token").String()) 	// optional
	if(expiresIn <= 0) {
		if(o2Rec.RefreshToken != "") {
			err = append(err, "The Refresh Token has been provided but the Expire In is invalid")
		} //end if
	} //end if
	//--
	o2Rec.IdToken 			= smart.StrTrimWhitespaces(jsonObj.Get("id_token").String()) 		// this is completely optional and only provided in some cases when the Access Token is opaque and this will be the OpenID JWT type of token
	o2Rec.Scope 			= smart.StrTrimWhitespaces(jsonObj.Get("scope").String()) 			// optional
	//--
	if(len(err) > 0) {
		o2Rec.Error = smart.Implode("\n", err)
	} //end if
	//--
	return o2Rec
	//--
} //END FUNCTION


func parseErrAnswer(body string) string {
	//--
	// this method try to get the "error" and "error_description" from JSON Body
	// if fails will return an empty answer
	//--
	body = smart.StrTrimWhitespaces(body)
	if(body == "") {
		return ""
	} //end if
	//--
	jsonObj := smart.JsonGetValueByKeyPath(body, "")
	if(jsonObj == nil) {
		return ""
	} //end if
	if(jsonObj.Value() == nil) {
		return ""
	} //end if
	//--
	var errMsg string = smart.StrTrimWhitespaces(smart.StrNormalizeSpaces(jsonObj.Get("error").String())) 				// normalize spaces, below separator is `\n`
	var errDet string = smart.StrTrimWhitespaces(smart.StrNormalizeSpaces(jsonObj.Get("error_description").String())) 	// normalize spaces, below separator is `\n`
	//--
	if((errMsg == "") && (errDet == "")) {
		return ""
	} //end if
	//--
	var theErr string = "Error-Code: `" + errMsg + "`"
	if(errDet != "") {
		theErr += "\n" + "Error-Description: `" + errDet + "`"
	} //end if
	//--
	return theErr
	//--
} //END FUNCTION


//-----


func allowInsecureHTTPS(url string) bool {
	//--
	defer smart.PanicHandler()
	//--
	url = smart.StrTrimWhitespaces(url)
	if(url == "") {
		return false
	} //end if
	//--
	objUrl, errUrl := smart.ParseUrl(url)
	if(errUrl != nil) {
		return false
	} //end if
	if(objUrl == nil) {
		return false
	} //end if
	//--
	if(objUrl.Scheme == "https") {
		hostNameOrIp, port, errSplit := smart.GetHttpDomainAndPortFromHostOrHostPort(objUrl.Host)
		if(DEBUG) {
			log.Println("[DEBUG]", smart.CurrentFunctionName(), hostNameOrIp, port, errSplit)
		} //end if
		if(errSplit == nil) {
			if(hostNameOrIp != "") {
				if(smart.IsNetValidIpAddr(hostNameOrIp)) { // if host is an IP address
					return true
				} //end if
			} //end if
		} //end if
	} //end if
	//--
	return false
	//--
} //END FUNCTION


//-----


type urlAndSettings struct {
	Error 		string
	Url 		string
	Settings 	map[string]string
}


func parseUrlAndSettings(url string) urlAndSettings {
	//--
	defer smart.PanicHandler()
	//--
	data := urlAndSettings{}
	//--
	url = smart.StrTrimWhitespaces(url)
	if(url == "") {
		data.Error = "URL is Empty"
		return data
	} //end if
	//--
	objUrl, errUrl := smart.ParseUrl(url)
	if(errUrl != nil) {
		data.Error = "URL Parse Failed: " + errUrl.Error()
		return data
	} //end if
	if(objUrl == nil) {
		data.Error = "URL Parse Failed, Null"
		return data
	} //end if
	//--
	var theUrl string = ""
	theUrl += objUrl.Scheme + "://" 		// protocol: http | https
	theUrl += objUrl.Host 					// `host` or `host:port`
	theUrl += objUrl.Path 					// path
	if(objUrl.RawQuery != "") {
		theUrl += "?" + objUrl.RawQuery 	// url query, if any
	} //end if
	//--
	var theSettings map[string]string = map[string]string{}
	var theFragment string = smart.StrTrimWhitespaces(objUrl.RawFragment)
	if(theFragment != "") {
		parsedFrag := smart.ParseUrlRawQuery(theFragment)
		if(DEBUG) {
			log.Println("[DEBUG]", smart.CurrentFunctionName(), "parsedFrag", parsedFrag)
		} //end if
		if(parsedFrag != nil) {
			if(len(parsedFrag) > 0) {
				for key, val := range parsedFrag {
					if(len(val) == 1) { // must be not empty, must be not array, so in this case have to use value from [0]
						theSettings[key] = val[0]
					} //end if
				} //end for
			} //end if
		} //end if
	} //end if
	//--
	data.Url = theUrl
	data.Settings = theSettings
	//--
	return data
	//--
} //END FUNCTION


//-----


func getValidPKCEMethod(method string) string {
	//--
	method = smart.StrToUpper(smart.StrTrimWhitespaces(method))
	if(method == "") {
		method = "S256" // {{{SYNC-OAUTH2-CHALLENGE-DEFAULT-METHOD}}}
	} //end if
	//--
	switch(method) { // {{{SYNC-OAUTH2-CHALLENGE-METHODS}}}
		case "S224":  fallthrough // sha224
		case "S256":  fallthrough // sha256 ; wide supported, default
		case "S384":  fallthrough // sha384
		case "S512":  fallthrough // sha512
		case "3S224": fallthrough // sha3-224
		case "3S256": fallthrough // sha3-256
		case "3S384": fallthrough // sha3-384
		case "3S512": fallthrough // sha3-512
		case "PLAIN":             // plain
			break
		default:
			return ""
	} //end switch
	//--
	return method
	//--
} //END FUNCTION


//-----


// #END
