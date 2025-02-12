
// GO Lang :: SmartGo / Web Server / JWT :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250210.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"time"

	smart 	"github.com/unix-world/smartgo"
	uid 	"github.com/unix-world/smartgo/crypto/uuid"
	jwt 	"github.com/unix-world/smartgo/web/jwt"
)


const (
	JwtDefaultExpirationMinutes int64 = 60 * 24 		//   1440 m =   1 d
	JwtMaxExpirationMinutes 	int64 = 60 * 24 * 360 	// 518400 m = 360 d
	JwtMinExpirationMinutes 	int64 = 1 				//      1 m

	JwtMinLength 				uint16 =  128 			// {{{SYNC-AUTH-JWT-MIN-ALLOWED-LEN}}}
	JwtMaxLength 				uint16 = 1280 			// {{{SYNC-AUTH-JWT-MAX-ALLOWED-LEN}}}

	JwtRegexSerial 				string = `^[A-Z0-9]{10}\-[A-Z0-9]{10}$`
)

var (
	authJwtAlgo string = "" // if this is empty, will dissalow JWT use ; allowed values: "Edx448" ; "Ed448" ; "Edx25519" ; "Ed25519" ; "H3S512" ; "H3S384" ; "H3S256" ; "H3S224" ; "HS384" ; "HS224"
)

type JwtClaims struct {
	Username string `json:"usr"`
	jwt.RegisteredClaims
}

type JwtData struct {
	Type  		string 		`json:"type"`
	Size 		uint64 		`json:"size"`
	Token 		string 		`json:"token"`
	TimeNow     int64 		`json:"timeNow"`
	ExpMinutes 	int64 		`json:"expMinutes"`
	ExpAt 		string 		`json:"expAt"`
	PublicKey 	string 		`json:"publicKey,omitempty"`
	MetaInfo 	JwtClaims 	`json:"metaInfo"`
}

type JwtTokenData struct {
	Error      error  `json:"error,omitempty"`
	Type       string `json:"-"`
	Algo       string `json:"algo"`
	ID         string `json:"serial,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	Created    string `json:"created,omitempty"`
	ICreated   int64  `json:"-"`
	IExpires   int64  `json:"-"`
	Expires    string `json:"expires,omitempty"`
	UserName   string `json:"userName"`
	Audience []string `json:"audience"`
}

type JwtAudience struct {
	Error        error
	IpList       string
	Area         string
	Privileges   string
	Restrictions string
	Xtras        string
}

//-----


func JwtExtractData(tokenString string) JwtTokenData {
	//--
	defer smart.PanicHandler() // req. by base64 decode with malformed data
	//--
	jwtData := JwtTokenData{}
	jwtData.Error = smart.NewError("Unknown Error")
	//--
	tokenString = smart.StrTrimWhitespaces(tokenString)
	if(tokenString == "") {
		jwtData.Error = smart.NewError("Token is Empty")
		return jwtData
	} //end if
	if(len(tokenString) < int(JwtMinLength)) {
		jwtData.Error = smart.NewError("Token is Too Short")
		return jwtData
	} //end if
	if(len(tokenString) > int(JwtMaxLength)) {
		jwtData.Error = smart.NewError("Token is Too Long")
		return jwtData
	} //end if
	if(!smart.StrRegexMatch(smart.REGEX_SAFE_B64S_STR, tokenString)) {
		jwtData.Error = smart.NewError("Token Contains Invalid Characters")
		return jwtData
	} //end if
	//--
	arrParts := smart.ExplodeWithLimit(".", tokenString, 4)
	if(len(arrParts) != 3) { // expects: header.data.signature
		jwtData.Error = smart.NewError("Token must have 3 segments")
		return jwtData
	} //end if
	//--
	var jsonPartHdr string = smart.StrTrimWhitespaces(arrParts[0])
	if(jsonPartHdr == "") {
		jwtData.Error = smart.NewError("Token Header segment is Empty B64")
		return jwtData
	} //end if
	jsonPartByteHdr, errJwtB64SegDecode := jwt.DecodeSegment(jsonPartHdr)
	if(errJwtB64SegDecode != nil) {
		jwtData.Error = smart.NewError("Token Header segment is Invalid B64")
		return jwtData
	} //end if
	jsonPartHdr = smart.StrTrimWhitespaces(string(jsonPartByteHdr))
	jsonPartByteHdr = nil
	if(jsonPartHdr == "") {
		jwtData.Error = smart.NewError("Token Header segment is Empty")
		return jwtData
	} //end if
	//--
	var tkType string = smart.StrTrimWhitespaces(smart.JsonGetValueByKeyPath(jsonPartHdr, "typ").String())
	var tkAlgo string = smart.StrTrimWhitespaces(smart.JsonGetValueByKeyPath(jsonPartHdr, "alg").String())
	//--
	if(tkType != "JWT") {
		jwtData.Error = smart.NewError("Invalid Token Type: Not JWT")
		return jwtData
	} //end if
	if(tkAlgo == "") {
		jwtData.Error = smart.NewError("Invalid Token Algo: Empty")
		return jwtData
	} //end if
	//--
	jwtData.Type = tkType
	jwtData.Algo = tkAlgo
	//--
	var jsonPartTxt string = smart.StrTrimWhitespaces(arrParts[1])
	if(jsonPartTxt == "") {
		jwtData.Error = smart.NewError("Token Data segment is Empty B64")
		return jwtData
	} //end if
	jsonPartByteTxt, errJwtB64SegDecode := jwt.DecodeSegment(jsonPartTxt)
	if(errJwtB64SegDecode != nil) {
		jwtData.Error = smart.NewError("Token Data segment is Invalid B64")
		return jwtData
	} //end if
	jsonPartTxt = smart.StrTrimWhitespaces(string(jsonPartByteTxt))
	jsonPartByteTxt = nil
	if(jsonPartTxt == "") {
		jwtData.Error = smart.NewError("Token Data segment is Empty")
		return jwtData
	} //end if
	//--
	gjsonObj := smart.JsonGetValueByKeyPath(jsonPartTxt, "")
	//--
	var serial string = smart.StrTrimWhitespaces(gjsonObj.Get("jti").String())
	if((serial == "") || (len(serial) != 21) || (!smart.StrRegexMatch(JwtRegexSerial, serial))) { // {{{SYNC-JWT-SMART-SERIAL-VALIDATION}}}
		jwtData.Error = smart.NewError("Token Data contains an Invalid Serial")
		return jwtData
	} //end if
	//--
	arrAudience := gjsonObj.Get("aud").Array()
	var audience []string = []string{}
	if(len(arrAudience) > 0) {
		for i:=0; i<len(arrAudience); i++ {
			audience = append(audience, arrAudience[i].String())
		} //end for
	} //end if
	jwtAudience := JwtParseAudience(audience)
	if(jwtAudience.Error != nil) {
		jwtData.Error = smart.NewError("Token Data contains an Invalid Audience: " + jwtAudience.Error.Error())
		return jwtData
	} //end if
	var isDefaultArea bool = JwtAudienceIsDefaultArea(jwtAudience)
	//--
	var issuer string = smart.StrTrimWhitespaces(gjsonObj.Get("iss").String())
	if(issuer == "") {
		jwtData.Error = smart.NewError("Token Data contains an Empty Issuer")
		return jwtData
	} //end if
	//--
	var created string = ""
	var createdAt int64 = gjsonObj.Get("iat").Int()
	if(createdAt > 0) {
		created = smart.DateFromUnixTimeUtc(createdAt)
	} //end if
	//--
	var expires string = ""
	var expireAt int64 = gjsonObj.Get("exp").Int()
	if(expireAt > 0) {
		expires = smart.DateFromUnixTimeUtc(expireAt)
	} //end if
	//--
	var userName string = smart.StrTrimWhitespaces(gjsonObj.Get("usr").String())
	if((userName == "") || (smart.AuthIsValidExtUserName(userName) != true)) { // allow extended user name check for further developments ; if more restricted us needed use after checks
		jwtData.Error = smart.NewError("Token Data contains an Empty or Invalid UserName")
		return jwtData
	} //end if
	if(isDefaultArea == true) {
		if(smart.AuthIsValidUserName(userName) != true) {
			jwtData.Error = smart.NewError("Token Data contains a Non-Valid UserName")
			return jwtData
		} //end if
	} //end if
	//--
	jwtData.Error = nil
	jwtData.ID = serial
	jwtData.Issuer = issuer
	jwtData.Created = created
	jwtData.ICreated = createdAt
	jwtData.IExpires = expireAt
	jwtData.Expires = expires
	jwtData.UserName = userName
	jwtData.Audience = audience
	//--
	//log.Println("[DEBUG]", jwtData)
	//--
	return jwtData
	//--
} //END FUNCTION


func JwtVerifyWithUserPrivKey(tokenString string, jwtSignMethod string, clientIP string, dom string, port string, userName string, userPrivKey string) error {
	//--
	defer smart.PanicHandler() // req. by base64 decode, inside JWT with malformed data
	//-- works for both: Ed* and HS*
	return jwtVerify(tokenString, jwtSignMethod, clientIP, dom, port, userName, userPrivKey, "")
	//--
} //END FUNCTION


func JwtVerifyWithPublicKey(tokenString string, jwtSignMethod string, clientIP string, dom string, port string, userName string, publicKey string) error {
	//--
	defer smart.PanicHandler() // req. by base64 decode, inside JWT with malformed data
	//-- works just for: Ed*
	return jwtVerify(tokenString, jwtSignMethod, clientIP, dom, port, userName, "", publicKey)
	//--
} //END FUNCTION


func JwtGetFullNameSigningAlgo(jwtSignMethod string) string {
	//--
	return "JWT:" + jwtSignMethod
	//--
} //END FUNCTION


func JwtNewAudience(ipList string, area string, privs string, restr string, cliSign string) []string {
	//--
	ipList = smart.StrTrimWhitespaces(ipList)
	if(ipList != "") {
		if(ipList != "*") { // validate, except wildcard
			errValidateAllowedIpList := smart.ValidateIPAddrList(ipList) // verify the IP list and if invalid make it empty as invalid !
			if(errValidateAllowedIpList != nil) {
				ipList = "" // set to empty, as invalid, to fail verification
			} //end if
		} //end if
	} //end if
	//--
	area = smart.StrTrimWhitespaces(area)
	privs = smart.StrTrimWhitespaces(privs)
	restr = smart.StrTrimWhitespaces(restr)
	cliSign = smart.StrTrimWhitespaces(cliSign)
	//--
	audience := []string{
		"I:" + ipList,  // ip address (list): any = * ; or: <127.0.0.1>,<::1>
		"A:" + area,    // area: default = @
		"P:" + privs,   // privileges: default = @
		"R:" + restr,   // restrictions: default = @
		"X:" + cliSign, // xtras: none = - ; this is a custom field to be used for external validations (ex: cookie bind to cli/browser signature)
	}
	//--
	jwtTestAudience := JwtParseAudience(audience) // must test this because some extra validations like max string lengths are in this method
	if(jwtTestAudience.Error != nil) {
		audience = []string{ // set as invalid, to fail verification (must be non-null, because nil means default and some methods will issue default audience on nil)
			"I:",
			"A:",
			"P:",
			"R:",
			"X:",
		}
	} //end if
	//--
	return audience
	//--
} //END FUNCTION


func JwtParseAudience(audience []string) JwtAudience {
	//--
	jwtAudience := JwtAudience{}
	//--
	if(audience == nil) {
		jwtAudience.Error = smart.NewError("Is Null")
		return jwtAudience
	} //end if
	if(len(audience) != 5) {
		jwtAudience.Error = smart.NewError("Size is Invalid")
		return jwtAudience
	} //end if
	//--
	if((!smart.StrStartsWith(audience[0], "I:")) || (len(audience[0]) < 3) || (len(audience[0]) > 255)) { // ip list
		jwtAudience.Error = smart.NewError("IP List is Invalid")
		return jwtAudience
	} //end if
	if((!smart.StrStartsWith(audience[1], "A:")) || (len(audience[1]) < 3) || (len(audience[1]) > 255)) { // area
		jwtAudience.Error = smart.NewError("Area is Invalid")
		return jwtAudience
	} //end if
	if((!smart.StrStartsWith(audience[2], "P:")) || (len(audience[2]) < 3) || (len(audience[2]) > 255)) { // privileges
		jwtAudience.Error = smart.NewError("Privileges are Invalid")
		return jwtAudience
	} //end if
	if((!smart.StrStartsWith(audience[3], "R:")) || (len(audience[3]) < 3) || (len(audience[3]) > 255)) { // restrictions
		jwtAudience.Error = smart.NewError("Restrictions are Invalid")
		return jwtAudience
	} //end if
	if((!smart.StrStartsWith(audience[4], "X:")) || (len(audience[4]) < 3) || (len(audience[4]) > 512)) { // xtras
		jwtAudience.Error = smart.NewError("Xtras are Invalid")
		return jwtAudience
	} //end if
	//--
	jwtAudience.IpList       = smart.StrTrimWhitespaces(smart.StrSubstr(audience[0], 2, 0))
	jwtAudience.Area         = smart.StrTrimWhitespaces(smart.StrSubstr(audience[1], 2, 0))
	jwtAudience.Privileges   = smart.StrTrimWhitespaces(smart.StrSubstr(audience[2], 2, 0))
	jwtAudience.Restrictions = smart.StrTrimWhitespaces(smart.StrSubstr(audience[3], 2, 0))
	jwtAudience.Xtras        = smart.StrTrimWhitespaces(smart.StrSubstr(audience[4], 2, 0))
	//--
	if(jwtAudience.IpList == "") {
		jwtAudience.Error = smart.NewError("IP List is Empty")
		return jwtAudience
	} //end if
	if(jwtAudience.Area == "") {
		jwtAudience.Error = smart.NewError("Area is Empty")
		return jwtAudience
	} //end if
	if(jwtAudience.Privileges == "") {
		jwtAudience.Error = smart.NewError("Privileges are Empty")
		return jwtAudience
	} //end if
	if(jwtAudience.Restrictions == "") {
		jwtAudience.Error = smart.NewError("Restrictions are Empty")
		return jwtAudience
	} //end if
	if(jwtAudience.Xtras == "") {
		jwtAudience.Error = smart.NewError("Xtras are Empty")
		return jwtAudience
	} //end if
	//--
	if((len(jwtAudience.IpList) == 1) && (jwtAudience.IpList != "*")) {
		jwtAudience.Error = smart.NewError("IP List Def. is Invalid")
		return jwtAudience
	} //end if
	if((len(jwtAudience.Area) == 1) && (jwtAudience.Area != "@")) {
		jwtAudience.Error = smart.NewError("Area Def. is Invalid")
		return jwtAudience
	} //end if
	if((len(jwtAudience.Privileges) == 1) && (jwtAudience.Privileges != "@")) {
		jwtAudience.Error = smart.NewError("Privileges Def. are Invalid")
		return jwtAudience
	} //end if
	if((len(jwtAudience.Restrictions) == 1) && (jwtAudience.Restrictions != "@")) {
		jwtAudience.Error = smart.NewError("Restrictions Def. are Invalid")
		return jwtAudience
	} //end if
	// do not check for jwtAudience.Xtras ; may contain: - / + ...
	//--
	return jwtAudience
	//--
} //END FUNCTION


func JwtAudienceIsDefaultArea(jwtAudience JwtAudience) bool {
	//--
	var isDefaultArea bool = false
	if(jwtAudience.Area == "@") { // for default area
		isDefaultArea = true
	} //end if
	//--
	return isDefaultArea
	//--
} //END FUNCTION


func JwtAudienceIsDefaultPrivs(jwtAudience JwtAudience) bool {
	//--
	var isDefaultPrivs bool = false
	if(jwtAudience.Privileges == "@") { // for default privileges
		isDefaultPrivs = true
	} //end if
	//--
	return isDefaultPrivs
	//--
} //END FUNCTION


func JwtAudienceIsDefaultRestr(jwtAudience JwtAudience) bool {
	//--
	var isDefaultRestr bool = false
	if(jwtAudience.Restrictions == "@") { // for default restrictions
		isDefaultRestr = true
	} //end if
	//--
	return isDefaultRestr
	//--
} //END FUNCTION


func JwtNew(jwtSignMethod string, expirationMinutes int64, clientIP string, dom string, port string, userName string, userPrivKey string, audience []string) (JwtData, error) {
	//--
	defer smart.PanicHandler() // req. by base64 decode, inside JWT with malformed data
	//--
	noData := JwtData{}
	//--
	if(expirationMinutes < JwtMinExpirationMinutes) {
		return noData, smart.NewError("Expiration Minutes is Lower than Minimum Allowed")
	} //end if
	if(expirationMinutes > JwtMaxExpirationMinutes) {
		return noData, smart.NewError("Expiration Minutes is Higher than Maximum Allowed")
	} //end if
	//--
	secKey, secErr := smart.AppGetSecurityKey()
	if(secErr != nil) {
		return noData, smart.NewError("App Security Key ERR: " + secErr.Error())
	} //end if
	if(smart.StrTrimWhitespaces(secKey) == "") {
		return noData, smart.NewError("App Security Key is Empty")
	} //end if
	//--
	clientIP = smart.StrTrimWhitespaces(clientIP)
	if(clientIP != "*") { // {{{SYNC-JWT-CLIENT-IP-WILDCARD}}} ; if wildcard, it is mandatory below the audience to be wildcard, else error
		if((clientIP == "") || (!smart.IsNetValidIpAddr(clientIP))) {
			return noData, smart.NewError("Invalid Client IP Address (required for the JWT verification process, after the JWT token is created)")
		} //end if
	} //end if
	//--
	dom = smart.StrTrimWhitespaces(dom)
	if(dom == "") {
		return noData, smart.NewError("Server Domain is Empty")
	} //end if
	port = smart.StrTrimWhitespaces(port)
	if(port == "") {
		return noData, smart.NewError("Server Port is Empty")
	} //end if
	var issuer string = dom + ":" + port
	if((len(issuer) < 7) || (len(issuer) > 69)) {
		return noData, smart.NewError("Issuer is Invalid")
	} //end if
	//--
	if((audience == nil) || (len(audience) <= 0)) {
		audience = JwtNewAudience("*", "@", "@", "@", "-")
	} //end if
	jwtAudience := JwtParseAudience(audience)
	if(jwtAudience.Error != nil) {
		return noData, smart.NewError("Audience ERR: " + jwtAudience.Error.Error())
	} //end if
	if(clientIP == "*") { // {{{SYNC-JWT-CLIENT-IP-WILDCARD}}}
		if(jwtAudience.IpList != "*") {
			return noData, smart.NewError("If the client IP is wildcard, the Audience IP List must be wildcard")
		} //end if
	} //end if
	if(smart.StrTrimWhitespaces(jwtAudience.IpList) == "") {
		return noData, smart.NewError("The Audience IP List is Empty")
	} //end if
	if(jwtAudience.IpList != "*") {
		errValidateAllowedIpList := smart.ValidateIPAddrList(jwtAudience.IpList) // {{{SYNC-VALIDATE-IP-LIST-BEFORE-VERIFY-IP}}}
		if(errValidateAllowedIpList != nil) {
			return noData, smart.NewError("The Audience IP List is Invalid, ERR: " + errValidateAllowedIpList.Error())
		} //end if
		if(!smart.StrIContains(jwtAudience.IpList, "<"+clientIP+">")) { // {{{SYNC-VALIDATE-IP-IN-A-LIST}}} ; case insensitive to cover also all Ipv4 and IPv6 (upper or lowercase)
			//log.Println("[DEBUG]", smart.CurrentFunctionName(), "#", "IP List:", jwtAudience.IpList, "does not contain:", clientIP)
			return noData, smart.NewError("Audience IP List is Invalid, does not contain the given IP Address")
		} //end if
	} //end if
	var isDefaultArea bool = JwtAudienceIsDefaultArea(jwtAudience)
	//--
	userName = smart.StrTrimWhitespaces(userName)
	if(userName == "") {
		return noData, smart.NewError("User Name is Empty")
	} //end if
	if(smart.AuthIsValidExtUserName(userName) != true) { // allow extended user name check for further developments ; if more restricted us needed use after checks
		return noData, smart.NewError("UserName is Invalid: `" + userName + "`")
	} //end if
	if(isDefaultArea == true) {
		if(smart.AuthIsValidUserName(userName) != true) {
			return noData, smart.NewError("UserName is Not Valid: `" + userName + "`")
		} //end if
	} //end if
	//--
	userPrivKey = smart.StrTrimWhitespaces(userPrivKey)
	if(userPrivKey == "") {
		return noData, smart.NewError("User Private Key is Empty")
	} //end if
	//--
	dKeyLen, safeKey, errSafeKey := jwtSafeKey(jwtSignMethod, dom, port, userName, userPrivKey)
	if(errSafeKey != nil) {
		return noData, errSafeKey
	} //end if
	if(smart.StrTrimWhitespaces(safeKey) == "") {
		return noData, smart.NewError("SafeKey is Empty")
	} //end if
	if((dKeyLen <= 0) || (len(safeKey) != int(dKeyLen))) {
		return noData, smart.NewError("SafeKey have an Invalid Length")
	} //end if
	//--
	timeNow := time.Now().UTC() // {{{SYNC-SMART-JWT-UTC-TIME}}}
	expirationTime := timeNow.Add(time.Duration(expirationMinutes) * time.Minute)
	//--
	var serial string = smart.StrRev(uid.Uuid10Seq()) + "-" + uid.Uuid10Num()
	//--
	var chksum string = smart.Base64sEncode(smart.NULL_BYTE + userName + smart.BACK_SPACE + serial + smart.ASCII_BELL + smart.ConvertInt64ToStr(expirationTime.Unix()) + smart.VERTICAL_TAB + smart.ConvertInt64ToStr(timeNow.Unix()) + smart.FORM_FEED + issuer + smart.NULL_BYTE + smart.Implode(smart.INVALID_CHARACTER, audience) + smart.BACK_SPACE + secKey + smart.NULL_BYTE)
	var subject string = smart.Crc32bB36(chksum) + "-" + smart.Crc32bB36(smart.StrRev(chksum))
	//--
	claims := JwtClaims{
		Username: userName,
		RegisteredClaims: jwt.RegisteredClaims{
			ID: serial,
			ExpiresAt: jwt.NewNumericDate(expirationTime), // In JWT, the expiry time is expressed as unix milliseconds
			IssuedAt: jwt.NewNumericDate(timeNow),
			Issuer: issuer,
			Audience: audience,
			Subject: subject,
		},
	}
	//--
	var token *jwt.Token = nil
	var tokenString string = ""
	var tokenErr error = smart.NewError("Token Not Generated")
	var publicKey string = ""
	var havePublicKey bool = false
	token = jwt.NewWithClaims(jwt.GetSigningMethod(jwtSignMethod), &claims)
	if(token == nil) {
		return noData, smart.NewError("Token is NULL")
	} //end if
	switch(jwtSignMethod) {
		case "HS224":  fallthrough // sha-224
		case "HS384":  fallthrough // sha-384
		case "H3S224": fallthrough // sha3-224
		case "H3S256": fallthrough // sha3-256
		case "H3S384": fallthrough // sha3-384
		case "H3S512": // sha3-512
			//-- {{{SYNC-JWT-HS*-KEYS}}}
			if(len(safeKey) != 64) { // {{{SYNC-JWT-HS-KEY-LEN}}}
				return noData, smart.NewError("Derived Private Key (" + jwtSignMethod + ") ERR: `Key Size must be 64 bytes`")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString([]byte(safeKey))
			break
		case "Ed25519":
			havePublicKey = true
			//-- {{{SYNC-JWT-ED25519-KEYS}}}
			pK, pbKey, errK := jwt.GenerateEdPrivateAndPublicKeys([]byte(safeKey))
			if(errK != nil) {
				return noData, smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
			} //end if
			if(pK == nil) {
				return noData, smart.NewError("Private Key is NULL")
			} //end if
			if(len(pbKey) != int(dKeyLen)) {
				return noData, smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
			} //end if
			publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
			if(publicKey == "") {
				return noData, smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString(pK)
			break
		case "Edx25519":
			havePublicKey = true
			//-- {{{SYNC-JWT-EDX25519-KEYS}}}
			pK, pbKey, errK := jwt.GenerateEdxPrivateAndPublicKeys([]byte(safeKey))
			if(errK != nil) {
				return noData, smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
			} //end if
			if(pK == nil) {
				return noData, smart.NewError("Private Key is NULL")
			} //end if
			if(len(pbKey) != int(dKeyLen)) {
				return noData, smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
			} //end if
			publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
			if(publicKey == "") {
				return noData, smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString(pK)
			break
		case "Ed448":
			havePublicKey = true
			//-- {{{SYNC-JWT-ED448-KEYS}}}
			pK, pbKey, errK := jwt.GenerateEdzPrivateAndPublicKeys([]byte(safeKey))
			if(errK != nil) {
				return noData, smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
			} //end if
			if(pK == nil) {
				return noData, smart.NewError("Private Key is NULL")
			} //end if
			if(len(pbKey) != int(dKeyLen)) {
				return noData, smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
			} //end if
			publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
			if(publicKey == "") {
				return noData, smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString(pK)
			break
		case "Edx448":
			havePublicKey = true
			//-- {{{SYNC-JWT-EDX448-KEYS}}}
			pK, pbKey, errK := jwt.GenerateEdzxPrivateAndPublicKeys([]byte(safeKey))
			if(errK != nil) {
				return noData, smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
			} //end if
			if(pK == nil) {
				return noData, smart.NewError("Private Key is NULL")
			} //end if
			if(len(pbKey) != int(dKeyLen)) {
				return noData, smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
			} //end if
			publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
			if(publicKey == "") {
				return noData, smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
			} //end if
			//-- #
			tokenString, tokenErr = token.SignedString(pK)
			break
		default:
			return noData, smart.NewError("Unsupported JWT Algorithm: `" + jwtSignMethod + "`")
	} //end switch
	//--
	if(tokenErr != nil) {
		return noData, smart.NewError("Token Creation ERR: `" + tokenErr.Error() + "`")
	} //end if
	tokenString = smart.StrTrimWhitespaces(tokenString)
	if(tokenString == "") {
		return noData, smart.NewError("Token Creation Failed, Empty Data")
	} //end if
	//--
	if(havePublicKey == true) {
		errVfyWithPubKey := JwtVerifyWithPublicKey(tokenString, jwtSignMethod, clientIP, dom, port, userName, publicKey) // verify using the current Public Key
		if(errVfyWithPubKey != nil) {
			return noData, errVfyWithPubKey
		} //end if
	} //end if
	//--
	errVfyWithoutPubKey := JwtVerifyWithUserPrivKey(tokenString, jwtSignMethod, clientIP, dom, port, userName, userPrivKey) // verify only by secret, Public Key will be derived
	if(errVfyWithoutPubKey != nil) {
		return noData, errVfyWithoutPubKey
	} //end if
	//--
	data := JwtData{
		Type: JwtGetFullNameSigningAlgo(jwtSignMethod),
		Size: uint64(len(tokenString)),
		Token: tokenString,
		TimeNow: timeNow.Unix(),
		ExpMinutes: expirationMinutes,
		ExpAt: smart.DateFromTime(expirationTime),
		PublicKey: publicKey,
		MetaInfo: claims,
	}
	//--
	return data, nil
	//--
} //END FUNCTION


func jwtVerify(tokenString string, jwtSignMethod string, clientIP string, dom string, port string, userName string, userPrivKey string, publicKey string) error {
	//--
	// publicKey is required just for Ed* ; should be empty for HS*
	//--
	defer smart.PanicHandler() // req. by base64 decode, inside JWT with malformed data
	//--
	secKey, secErr := smart.AppGetSecurityKey()
	if(secErr != nil) {
		return smart.NewError("App Security Key ERR: " + secErr.Error())
	} //end if
	if(smart.StrTrimWhitespaces(secKey) == "") {
		return smart.NewError("App Security Key is Empty")
	} //end if
	//--
	tokenString = smart.StrTrimWhitespaces(tokenString)
	if(tokenString == "") {
		return smart.NewError("Token is Empty")
	} //end if
	if(len(tokenString) < int(JwtMinLength)) {
		return smart.NewError("Token is Too Short")
	} //end if
	if(len(tokenString) > int(JwtMaxLength)) {
		return smart.NewError("Token is Too Long")
	} //end if
	if(!smart.StrRegexMatch(smart.REGEX_SAFE_B64S_STR, tokenString)) {
		return smart.NewError("Token Contains Invalid Characters")
	} //end if
	//--
	clientIP = smart.StrTrimWhitespaces(clientIP)
	if(clientIP != "*") { // {{{SYNC-JWT-CLIENT-IP-WILDCARD}}} ; if wildcard, it is mandatory below the audience to be wildcard, else error
		if((clientIP == "") || (!smart.IsNetValidIpAddr(clientIP))) {
			return smart.NewError("Invalid Client IP Address for Verification")
		} //end if
	} //end if
	//--
	dom = smart.StrTrimWhitespaces(dom)
	if(dom == "") {
		return smart.NewError("Server Domain is Empty")
	} //end if
	port = smart.StrTrimWhitespaces(port)
	if(port == "") {
		return smart.NewError("Server Port is Empty")
	} //end if
	//--
	userName = smart.StrTrimWhitespaces(userName)
	if(userName == "") {
		return smart.NewError("User Name is Empty")
	} //end if
	//--
	dKeyLen, safeKey, errSafeKey := jwtSafeKey(jwtSignMethod, dom, port, userName, userPrivKey)
	if(publicKey == "") { // if publicKey is provided, skip this verification because userPrivKey is optional
		if(errSafeKey != nil) {
			return errSafeKey
		} //end if
		if(smart.StrTrimWhitespaces(safeKey) == "") {
			return smart.NewError("SafeKey is Empty")
		} //end if
		if((dKeyLen <= 0) || (len(safeKey) != int(dKeyLen))) {
			return smart.NewError("SafeKey have an Invalid Length")
		} //end if
	} //end if
	//--
	var issuer string = dom + ":" + port
	if((len(issuer) < 7) || (len(issuer) > 69)) {
		return smart.NewError("Issuer is Invalid")
	} //end if
	//--
	vfyClms := JwtClaims{}
	//--
	var tkn *jwt.Token = nil
	var errTkn error = smart.NewError("Token Not Verified")
	//--
	switch(jwtSignMethod) {
		case "HS224":  fallthrough // sha-224
		case "HS384":  fallthrough // sha-384
		case "H3S224": fallthrough // sha3-224
		case "H3S256": fallthrough // sha3-256
		case "H3S384": fallthrough // sha3-384
		case "H3S512": // sha3-512
			//-- {{{SYNC-JWT-HS*-KEYS}}}
			if(len(safeKey) != 64) { // {{{SYNC-JWT-HS-KEY-LEN}}}
				return smart.NewError("Derived Private Key (" + jwtSignMethod + ") ERR: `Key Size must be 64 bytes`")
			} //end if
			//-- #
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
				ky := []byte(safeKey) // can be verified only with the private (secret) key, these are symmetric algos
				return ky, nil
			})
			break
		case "Ed25519":
			if(publicKey == "") {
				//-- {{{SYNC-JWT-ED25519-KEYS}}}
				_, pbKey, errK := jwt.GenerateEdPrivateAndPublicKeys([]byte(safeKey))
				if(errK != nil) {
					return smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
				} //end if
				if(len(pbKey) != int(dKeyLen)) {
					return smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
				} //end if
				publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
				if(publicKey == "") {
					return smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
				} //end if
				//-- #
			} //end if
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
			//	ky := pK // verify with private key
			//	ky := pK.Public(), nil // verify with public key
				ky := jwt.GetEdPublicKeyFromBytes([]byte(smart.Base64Decode(publicKey))) // verify with B64 public key
				return ky, nil
			})
			break
		case "Edx25519":
			if(publicKey == "") {
				//-- {{{SYNC-JWT-EDX25519-KEYS}}}
				_, pbKey, errK := jwt.GenerateEdxPrivateAndPublicKeys([]byte(safeKey))
				if(errK != nil) {
					return smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
				} //end if
				if(len(pbKey) != int(dKeyLen)) {
					return smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
				} //end if
				publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
				if(publicKey == "") {
					return smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
				} //end if
				//-- #
			} //end if
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
			//	ky := pK // verify with private key
			//	ky := pK.Public(), nil // verify with public key
				ky := jwt.GetEdxPublicKeyFromBytes([]byte(smart.Base64Decode(publicKey))) // verify with B64 public key
				return ky, nil
			})
			break
		case "Ed448":
			if(publicKey == "") {
				//-- {{{SYNC-JWT-ED448-KEYS}}}
				_, pbKey, errK := jwt.GenerateEdzPrivateAndPublicKeys([]byte(safeKey))
				if(errK != nil) {
					return smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
				} //end if
				if(len(pbKey) != int(dKeyLen)) {
					return smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
				} //end if
				publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
				if(publicKey == "") {
					return smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
				} //end if
				//-- #
			} //end if
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
			//	ky := pK // verify with private key
			//	ky := pK.Public(), nil // verify with public key
				ky := jwt.GetEdzPublicKeyFromBytes([]byte(smart.Base64Decode(publicKey))) // verify with B64 public key
				return ky, nil
			})
			break
		case "Edx448":
			if(publicKey == "") {
				//-- {{{SYNC-JWT-EDX448-KEYS}}}
				_, pbKey, errK := jwt.GenerateEdzxPrivateAndPublicKeys([]byte(safeKey))
				if(errK != nil) {
					return smart.NewError("Private Key (" + jwtSignMethod + ") ERR: `" + errK.Error() + "`")
				} //end if
				if(len(pbKey) != int(dKeyLen)) {
					return smart.NewError("Public Key has an Invalid Size [" + smart.ConvertIntToStr(len(pbKey) * 8) + " bit]")
				} //end if
				publicKey = smart.StrTrimWhitespaces(smart.Base64Encode(string(pbKey)))
				if(publicKey == "") {
					return smart.NewError("Public Key (" + jwtSignMethod + ") is Empty")
				} //end if
				//-- #
			} //end if
			tkn, errTkn = jwt.ParseWithClaims(tokenString, &vfyClms, func(token *jwt.Token) (interface{}, error) {
			//	ky := pK // verify with private key
			//	ky := pK.Public(), nil // verify with public key
				ky := jwt.GetEdzxPublicKeyFromBytes([]byte(smart.Base64Decode(publicKey))) // verify with B64 public key
				return ky, nil
			})
			break
		default:
			return smart.NewError("Unsupported JWT Algorithm: `" + jwtSignMethod + "`")
	} //end switch
	//--
	if(errTkn != nil) {
		return smart.NewError("Token Verification Error: `" + errTkn.Error() + "`")
	} //end if
	if(tkn == nil) {
		return smart.NewError("Token Verification is NULL")
	} //end if
	if(!tkn.Valid) {
		return smart.NewError("Token Verification is Not Valid")
	} //end if
	//--
	clms, okClms := tkn.Claims.(*JwtClaims)
	if((okClms != true) || (clms == nil)) {
		return smart.NewError("Token Claims are Not Valid")
	} //end if
	//--
	if(clms.RegisteredClaims.Issuer != issuer) { // verify if the issuer is dom:port
		return smart.NewError("Token Issuer is Not Valid: `" + clms.RegisteredClaims.Issuer + "`")
	} //end if
	//--
	vfyBExpAt, errVfyAt := clms.RegisteredClaims.ExpiresAt.MarshalJSON()
	if(errVfyAt != nil) {
		return smart.NewError("Token ExpiresAt Marshal Error: " + errVfyAt.Error())
	} //end if
	var vfyExpAt string = smart.StrTrimWhitespaces(string(vfyBExpAt))
	if(vfyExpAt == "") {
		return smart.NewError("Token ExpiresAt is Empty")
	} //end if
	var vfyExpInt64At int64 = smart.ParseStrAsInt64(vfyExpAt)
	if(vfyExpInt64At <= 0) {
		return smart.NewError("Token ExpiresAt is Malformed")
	} //end if
	if(vfyExpInt64At <= smart.TimeNowUnix()) { // {{{SYNC-SMART-JWT-UTC-TIME}}} ; this is an extra safety check, it is actually verified at errTkn and tkn.Valid ; here must use: <= to cmply with above verification at errTkn
		return smart.NewError("Token ExpiresAt is Expired")
	} //end if
	//--
	vfyBIssAt, errVfyAt := clms.RegisteredClaims.IssuedAt.MarshalJSON()
	if(errVfyAt != nil) {
		return smart.NewError("Token IssuedAt Marshal Error: " + errVfyAt.Error())
	} //end if
	var vfyIssAt string = smart.StrTrimWhitespaces(string(vfyBIssAt))
	if(vfyIssAt == "") {
		return smart.NewError("Token IssuedAt is Empty")
	} //end if
	var vfyIssInt64At int64 = smart.ParseStrAsInt64(vfyIssAt)
	if(vfyIssInt64At <= 0) {
		return smart.NewError("Token IssuedAt is Malformed")
	} //end if
	if(vfyIssInt64At > smart.TimeNowUnix()) { // {{{SYNC-SMART-JWT-UTC-TIME}}} ; this is an extra safety check, it is actually verified at errTkn and tkn.Valid ; here must use: <= to cmply with above verification at errTkn
		return smart.NewError("Token IssuedAt is Invalid")
	} //end if
	//--
	if(vfyIssInt64At >= vfyExpInt64At) {
		return smart.NewError("Token Mismatch: IssuedAt vs. ExpiresAt")
	} //end if
	//--
	var audience []string = clms.RegisteredClaims.Audience
	//log.Println("[DEBUG]", smart.CurrentFunctionName(), "#", "audience:", audience, "clientIP:", clientIP, "user:", clms.Username)
	jwtAudience := JwtParseAudience(audience)
	if(jwtAudience.Error != nil) {
		return smart.NewError("Token Audience ERR: " + jwtAudience.Error.Error())
	} //end if
	if(clientIP == "*") { // {{{SYNC-JWT-CLIENT-IP-WILDCARD}}}
		if(jwtAudience.IpList != "*") {
			return smart.NewError("If the client IP is wildcard, the Audience IP List must be wildcard")
		} //end if
	} //end if
	if(smart.StrTrimWhitespaces(jwtAudience.IpList) == "") {
		return smart.NewError("The Audience IP List is Empty")
	} //end if
	if(jwtAudience.IpList != "*") {
		errValidateAllowedIpList := smart.ValidateIPAddrList(jwtAudience.IpList) // {{{SYNC-VALIDATE-IP-LIST-BEFORE-VERIFY-IP}}}
		if(errValidateAllowedIpList != nil) {
			return smart.NewError("The Audience IP List is Invalid, ERR: " + errValidateAllowedIpList.Error())
		} //end if
		if(!smart.StrIContains(jwtAudience.IpList, "<"+clientIP+">")) { // {{{SYNC-VALIDATE-IP-IN-A-LIST}}} ; case insensitive to cover also all Ipv4 and IPv6 (upper or lowercase)
			//log.Println("[DEBUG]", smart.CurrentFunctionName(), "#", "IP List:", jwtAudience.IpList, "does not contain:", clientIP)
			return smart.NewError("Token is Invalid, does not contain the required Client IP Address")
		} //end if
		log.Println("[NOTICE]", smart.CurrentFunctionName(), "# IP Restricted JWT [VALID:IP] #", "audience:", audience, "clientIP:", clientIP, "user:", clms.Username)
	} //end if
	var isDefaultArea bool = JwtAudienceIsDefaultArea(jwtAudience)
	//--
	if(smart.AuthSafeCompare(clms.Username, userName) != true) { // {{{SYNC-HTTP-AUTH-CHECKS-GO-SMART}}}
		return smart.NewError("Token UserName MisMatch: `" + clms.Username + "` ; `" + userName + "`")
	} //end if
	if((smart.StrTrimWhitespaces(clms.Username) == "") || (smart.AuthIsValidExtUserName(clms.Username) != true)) { // allow extended user name check for further developments ; if more restricted us needed use after checks
		return smart.NewError("Token UserName is Empty or Invalid: `" + clms.Username + "`")
	} //end if
	if(isDefaultArea == true) {
		if(smart.AuthIsValidUserName(clms.Username) != true) {
			return smart.NewError("Token UserName is Not Valid: `" + clms.Username + "`")
		} //end if
	} //end if
	//--
	if((clms.RegisteredClaims.ID == "") || (len(clms.RegisteredClaims.ID) != 21) || (!smart.StrRegexMatch(JwtRegexSerial, clms.RegisteredClaims.ID))) { // {{{SYNC-JWT-SMART-SERIAL-VALIDATION}}}
		return smart.NewError("Token have an Invalid Serial")
	} //end if
	//--
	var chksum string = smart.Base64sEncode(smart.NULL_BYTE + clms.Username + smart.BACK_SPACE + clms.ID + smart.ASCII_BELL + smart.ConvertInt64ToStr(vfyExpInt64At) + smart.VERTICAL_TAB + smart.ConvertInt64ToStr(vfyIssInt64At) + smart.FORM_FEED + issuer + smart.NULL_BYTE + smart.Implode(smart.INVALID_CHARACTER, audience) + smart.BACK_SPACE + secKey + smart.NULL_BYTE)
	var subject string = smart.Crc32bB36(chksum) + "-" + smart.Crc32bB36(smart.StrRev(chksum))
	if(clms.RegisteredClaims.Subject != subject) {
		return smart.NewError("Token have an Invalid Subject (Checksum)")
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func jwtSafeKey(jwtSignMethod string, dom string, port string, userName string, userPrivKey string) (uint16, string, error) {
	//--
	defer smart.PanicHandler() // req. by key derive
	//--
	var issuer string = dom + ":" + port
	var dKeyLen uint16 = 64 // {{{SYNC-JWT-HS-KEY-LEN}}}
	switch(jwtSignMethod) { // {{{SYNC-SMARTGO-AUTH-JWT-ALGOS}}}
		//-- sha2:  sha-256 and sha-512 are unsafe to use for signature, they may be vulnerable to length attacks, not supported in this scenario ...
		// only sha-224 and sha-384 are safe from the sha2 !
		// https://crypto.stackexchange.com/questions/89561/known-text-attack-on-hash-function-sha-256-or-sha512
		case "HS224":   fallthrough  // sha-224
		case "HS384":   fallthrough  // sha-384
		//-- sha3: all safe
		case "H3S224":  fallthrough  // sha3-224
		case "H3S256":  fallthrough  // sha3-256
		case "H3S384":  fallthrough  // sha3-384
		case "H3S512":               // sha3-512 ; best symmetric security level
			break
		case "Ed25519": fallthrough
		case "Edx25519":
			dKeyLen = 32
			break
		case "Ed448":   fallthrough
		case "Edx448":               // best asymmetric security level
			dKeyLen = 57
			break
		default:
			return 0, "", smart.NewError("Unsupported Algorithm: `" + jwtSignMethod + "`")
	} //end switch
	//--
	safeKey, errSafeKey := smart.Pbkdf2DerivedKey("sha3-512", userPrivKey, userName + "#" + issuer, dKeyLen, smart.DERIVE_CENTITER_TK, true) // b92
	if(errSafeKey != nil) {
		return dKeyLen, "", smart.NewError("Derived Key ERR: `" + errSafeKey.Error() + "`")
	} //end if
	if((len(safeKey) != int(dKeyLen)) || (len(safeKey) != len(smart.StrTrimWhitespaces(safeKey)))) {
		return dKeyLen, "", smart.NewError("Derived Key Length is Invalid: [" + smart.ConvertIntToStr(len(safeKey) * 8) + " bit]")
	} //end if
	//--
	return dKeyLen, safeKey, nil
	//--
} //END FUNCTION


//-----


func AuthTokenJwtIsEnabled() bool {
	//--
	if(smart.StrTrimWhitespaces(authJwtAlgo) == "") {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func AuthTokenJwtAlgoValidGet(algo string) string {
	//--
	switch(algo) { // {{{SYNC-SMARTGO-AUTH-JWT-ALGOS}}}
		//-- sha2:  sha-256 and sha-512 are unsafe to use for signature, they may be vulnerable to length attacks, not supported in this scenario ...
		// only sha-224 and sha-384 are safe from the sha2 !
		// https://crypto.stackexchange.com/questions/89561/known-text-attack-on-hash-function-sha-256-or-sha512
		case "HS224":    fallthrough  // sha-224
		case "HS384":    fallthrough  // sha-384
		//-- sha3: all safe
		case "H3S224":   fallthrough  // sha3-224
		case "H3S256":   fallthrough  // sha3-256
		case "H3S384":   fallthrough  // sha3-384
		case "H3S512":   fallthrough  // sha3-512 ; best symmetric security level
		case "Ed25519":  fallthrough
		case "Edx25519": fallthrough
		case "Ed448":    fallthrough
		case "Edx448":                // best asymmetric security level
			return algo
			break
		default:
			// N/A
	} //end switch
	//--
	return ""
	//--
} //END FUNCTION


func AuthTokenJwtAlgoGet() string {
	//--
	return AuthTokenJwtAlgoValidGet(authJwtAlgo)
	//--
} //END FUNCTION


func AuthTokenJwtAlgoSet(jwtAlgo string) bool {
	//--
	var ok bool = false
	//--
	if(authJwtAlgo != "") {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Failed to Set JWT Algo to: `" + jwtAlgo + "`, already set")
		return false
	} //end if
	//--
	if(jwtAlgo == "") {
		if(authJwtAlgo == "") {
			return true // no change
		} else {
			return false // dissalow unset
		} //end if else
	} //end if
	//--
	algo := smart.StrTrimWhitespaces(AuthTokenJwtAlgoValidGet(jwtAlgo))
	if(algo != "") {
		authJwtAlgo = algo
		ok = true
	} //end if else
	//--
	if(ok) {
		log.Println("[INFO]", smart.CurrentFunctionName(), "JWT Algo was Set to `" + authJwtAlgo + "`: Success")
	} else {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Failed to Set JWT Algo to: `" + jwtAlgo + "`")
	} //end if else
	//--
	return ok
	//--
} //END FUNCTION


//-----


// #END
