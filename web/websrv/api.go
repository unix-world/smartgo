
// GO Lang :: SmartGo / Web Server / API :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250118.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"time"
	"sync"

	"net/http"

	smart 		"github.com/unix-world/smartgo"
	smartcache 	"github.com/unix-world/smartgo/data-structs/simplecache"
)

const (
	API_FLOOD_CACHE_CLEANUP_INTERVAL uint32 = 5 // 5 seconds

	REGEX_SAFE_API_FLOOD_AREA string = `^[a-z0-9\.\:]+$`
)

var (
	DEBUG_API_CACHE bool = smart.DEBUG
)

var memApiFloodMutex sync.Mutex
var memApiFloodCache *smartcache.InMemCache = nil

type apiMsgStruct struct {
	ErrCode uint16 `json:"errCode,omitempty"`
	ErrMsg  string `json:"errMsg,omitempty"`
	Data       any `json:"data,omitempty"`
}


func ApiAuthNewBearerTokenJwt(r *http.Request, expMinutes int64, userName string, userSecKey string, allowedIpList string, clientIP string, audienceXtras string) (JwtData, error) {
	//--
	// allowedIpList can be: 	"" or "*" or "ip0" or "<ip1>, <ip2>"
	// clientIP can be: 		"" or "*" or ip0   or one of ip1, ip2
	//--
	emptyToken := JwtData{}
	//--
	if(AuthTokenJwtIsEnabled() != true) {
		return emptyToken, smart.NewError("JWT is Disabled")
	} //end if
	//--
	var jwtSignMethod string = AuthTokenJwtAlgoGet()
	if(smart.StrTrimWhitespaces(jwtSignMethod) == "") {
		return emptyToken, smart.NewError("JWT Algo is Not Set")
	} //end if
	//--
	if(expMinutes < JwtMinExpirationMinutes) {
		return emptyToken, smart.NewError("Expiration Minutes value is Too Low")
	} //end if
	if(expMinutes > JwtMaxExpirationMinutes) {
		return emptyToken, smart.NewError("Expiration Minutes value is Too High")
	} //end if
	//--
	userName = smart.StrTrimWhitespaces(userName)
	if(userName == "") {
		return emptyToken, smart.NewError("UserName is Empty")
	} //end if
	if(smart.AuthIsValidUserName(userName) != true) {
		return emptyToken, smart.NewError("UserName is Invalid")
	} //end if
	//--
	userSecKey = smart.StrTrimWhitespaces(userSecKey)
	if(userSecKey == "") {
		return emptyToken, smart.NewError("User Security Key is Empty")
	} //end if
	if(smart.AuthIsValidSecurityKey(userSecKey) != true) {
		return emptyToken, smart.NewError("User Security Key is Invalid")
	} //end if
	//--
	basedom, dom, port, errDomPort := GetBaseDomainDomainPort(r)
	if(errDomPort != nil) {
		return emptyToken, smart.NewError("Failed to get BaseDomain:Port: `" + errDomPort.Error() +  "`")
	} //end if
	if((smart.StrTrimWhitespaces(basedom) == "") || (smart.StrTrimWhitespaces(dom) == "") || (smart.StrTrimWhitespaces(port) == "")) {
		return emptyToken, smart.NewError("Invalid BaseDomain:Port / Domain, at least one of them is empty: `" + basedom + ":" + port + "` ; Domain: `" + dom + "`")
	} //end if
	//--
	allowedIpList = smart.StrTrimWhitespaces(allowedIpList)
	if(allowedIpList == "") {
		allowedIpList = "*"
	} //end if
	if(allowedIpList != "*") {
		arrAllowedIps := smart.Explode(",", allowedIpList)
		if(len(arrAllowedIps) <= 0) {
			return emptyToken, smart.NewError("IP Allowed List is Invalid")
		} else if(len(arrAllowedIps) > 4) {
			return emptyToken, smart.NewError("IP Allowed List is Oversized")
		} //end if
		for i:=0; i<len(arrAllowedIps); i++ {
			arrAllowedIps[i] = smart.StrTrimWhitespaces(arrAllowedIps[i])
			arrAllowedIps[i] = smart.StrTrim(arrAllowedIps[i], "<>")
			arrAllowedIps[i] = smart.StrTrimWhitespaces(arrAllowedIps[i])
			if(arrAllowedIps[i] == "") {
				return emptyToken, smart.NewError("IP Allowed List contains an Empty IP Address")
			} //end if
			if(smart.IsNetValidIpAddr(arrAllowedIps[i]) != true) {
				return emptyToken, smart.NewError("IP Allowed List contains an Invalid IP Address")
			} //end if
		} //end for
	} //end if
	//--
	clientIP = smart.StrTrimWhitespaces(clientIP)
	if(clientIP == "") {
		clientIP = "*"
	} //end if
	if(clientIP != "*") {
		if(smart.IsNetValidIpAddr(clientIP) != true) {
			return emptyToken, smart.NewError("Client IP is Invalid")
		} //end if
	} //end if
	//--
	audienceXtras = smart.StrTrimWhitespaces(audienceXtras)
	if(audienceXtras == "") {
		audienceXtras = "-" // default
	} //end if
	//--
	jwtBearerAudience := JwtNewAudience(allowedIpList, "@", "@", "@", audienceXtras)
	token, errToken := JwtNew(jwtSignMethod, expMinutes, clientIP, basedom, port, userName, userSecKey, jwtBearerAudience) // {{{SYNC-JWT-TOKEN-USE-BASE-DOMAIN}}}
	if(errToken != nil) {
		return emptyToken, smart.NewError("JWT ERR: " + errToken.Error())
	} //end if
	//--
	return token, nil
	//--
} //END FUNCTION


func ApiResponseJsonERR(errCode uint16, errMsg string, data any) string {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	if(errCode <= 0) {
		errCode = apiErrorDefaultCode
	} //end if
	errMsg = smart.StrTrimWhitespaces(errMsg)
	if(errMsg == "") {
		errMsg = apiErrorDefaultMsg
	} //end if
	//--
	resp := apiMsgStruct{
		ErrCode: errCode,
		ErrMsg:  errMsg,
		Data:    data,
	}
	//--
	return smart.JsonNoErrChkEncode(resp, true, false) // pretty format when err, for better readability
	//--
} //END FUNCTION


func ApiResponseJsonOK(data any) string {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	resp := apiMsgStruct{
		ErrCode: 0,
		ErrMsg:  "",
		Data:    data,
	}
	//--
	return smart.JsonNoErrChkEncode(resp, false, false) // do not format on OK answer to preserve bandwidth, these may be much longer answers than err above
	//--
} //END FUNCTION


func ApiFloodControlRegisterClientIPVisit(r *http.Request, area string, factor uint8) int64 {
	//--
	// per area: will register the client visit per IP multiplied with the factor ; the life of a registration entry is 1 minute
	// the factor can be used to control how much to consider a visit ; example: if error factor can be 5 ; otherwise factor can be 1
	//--
	if(factor <= 0) {
		factor = 1 // register at least one visit
	} //end if
	//--
	return apiFloodControlPerMinute(r, area, factor, false) // register visits by factor
	//--
} //END FUNCTION


func ApiFloodControlClearVisitFactorsPerClientIP(r *http.Request, area string) int64 {
	//--
	// per area: will clear the client visit factors per IP in the cache
	//--
	return apiFloodControlPerMinute(r, area, 0, true) // clear
	//--
} //END FUNCTION


func ApiFloodControlCountVisitFactorsPerClientIP(r *http.Request, area string) int64 {
	//--
	// per area: use this method to count the number of visits per IP address in one minute, so you can decide if this is too high then can block the request
	//--
	return apiFloodControlPerMinute(r, area, 0, false) // skip register visit
	//--
} //END FUNCTION


func apiFloodControlPerMinute(r *http.Request, area string, factor uint8, clear bool) (numEntries int64) {
	//--
	area = smart.StrToLower(smart.StrTrimWhitespaces(area))
	if((area == "") || (len(area) < 3) || (len(area) > 20) || (!smart.StrRegexMatch(REGEX_SAFE_API_FLOOD_AREA, area))) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Area is Empty or Too Short or Too Long or contains Invalid Characters")
		numEntries = -1
		return
	} //end if
	//--
	okClientIP, clientIP := GetVisitorRealIpAddr(r)
	if(okClientIP != true) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Failed to Get Real Client IP: `" + clientIP + "` [", okClientIP, "]")
		numEntries = -2
		return
	} //end if
	//--
	clientIP = smart.StrTrimWhitespaces(clientIP)
	if(clientIP == "") {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Real Client IP is Empty: `" + clientIP + "` [", okClientIP, "]")
		numEntries = -3
		return
	} //end if
	if(!smart.IsNetValidIpAddr(clientIP)) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Real Client IP is Invalid:", clientIP)
		numEntries = -4
		return
	} //end if
	//--
	apiFloodMemcacheInit()
	//--
	if(DEBUG_API_CACHE == true) {
		log.Println("[DATA]", smart.CurrentFunctionName(), ": [smartgo.webserver] :: memApiFloodCache:", memApiFloodCache)
	} //end if
	//--
	var objectID string = area + "(" + clientIP + ")"
	//--
	cacheExists, cachedObj, _ := memApiFloodCache.Get(objectID)
	//--
	if(factor < 0) {
		factor = 0
	} else if(factor > 255) {
		factor = 255
	} //end if
	//--
	numEntries = 0
	if(cacheExists == true) {
		if(cachedObj.Id == objectID) {
			numEntries = int64(len(cachedObj.Data))
		} //end if
		cachedObj.Data += smart.StrRepeat(".", int(factor))
	} else {
		cachedObj.Id = objectID
		cachedObj.Data = smart.StrRepeat(".", int(factor))
	} //end if
	//--
	if(clear == true) {
		memApiFloodCache.Unset(objectID) // unset from cache
		numEntries = 0
	} else if(factor > 0) {
		memApiFloodCache.Set(cachedObj, int64(60)) // expiration time is 1 minute
	} //end if
	//--
	return
	//--
} //END FUNCTION


func apiFloodMemcacheInit() {
	//--
	memApiFloodMutex.Lock()
	if(memApiFloodCache == nil) { // start cache just on 1st auth ... otherwise all scripts using this library will run the cache in background, but is needed only by this method !
		memApiFloodCache = smartcache.NewCache("smart.webserver.api.flood.inMemCache", time.Duration(API_FLOOD_CACHE_CLEANUP_INTERVAL) * time.Second, DEBUG_API_CACHE)
	} //end if
	memApiFloodMutex.Unlock()
	//--
} //END FUNCTION


// #END
