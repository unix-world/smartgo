
// GO Lang :: SmartGo / Web Server / Session-UUID :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260829.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"
	"net/http"

	uid 			"github.com/unix-world/smartgo/crypto/uuid"
	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)


const (
	REGEX_SESS_UUID_COOKIE_VALID_VALUE string = `^[A-Za-z0-9\.]+` // B62
)


func GetUuidCookieName() string {
	//--
	if(!smart.HttpSessionUUIDCookieIsEnabled()) {
		return ""
	} //end if
	//--
	return smart.HttpSessionUUIDCookieNameGet()
	//--
} //END FUNCTION


func GetUuidCookieValue(r *http.Request) string {
	//--
	if(!smart.HttpSessionUUIDCookieIsEnabled()) {
		return ""
	} //end if
	//--
	var sessUUIDCookieName string = smart.StrTrimWhitespaces(GetUuidCookieName())
	if(sessUUIDCookieName == "") {
		return ""
	} //end if
	//--
	var crrUUIDCookieVal string = smart.StrTrimWhitespaces(smarthttputils.HttpRequestGetCookie(r, sessUUIDCookieName))
	//--
	if((crrUUIDCookieVal == "") || (IsSessUUIDCookieValid(crrUUIDCookieVal, HashCrc64ClientIdent(r)) != true)) {
		return ""
	} //end if
	//--
	return crrUUIDCookieVal
	//--
} //END FUNCTION


func IsSessUUIDCookieValid(crrUUIDCookieVal string, clientIdentCrc64 string) bool {
	//--
	if(!smart.HttpSessionUUIDCookieIsEnabled()) {
		return false
	} //end if
	//--
	clientIdentCrc64 = smart.StrTrimWhitespaces(clientIdentCrc64)
	if(len(clientIdentCrc64) != 13) {
		return false
	} //end if
	//--
	if((smart.StrTrimWhitespaces(crrUUIDCookieVal) == "") || (len(crrUUIDCookieVal) < 40) || (len(crrUUIDCookieVal) > 70) || (!smart.StrRegexMatch(REGEX_SESS_UUID_COOKIE_VALID_VALUE, crrUUIDCookieVal))) { // if sh3a224 (b62) is mostly ~ 38 characters ; be flexible as +/- 4 characters (34..52 bytes)
		return false
	} //end if
	//--
	if(!smart.StrStartsWith(crrUUIDCookieVal, clientIdentCrc64 + ".")) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func HashCrc64ClientIdent(r *http.Request) string { // this creates a CRC64 hash based on client safe signature that will be used as prefix to ensure other client can't use the same cookie that in combination with the auth cookie to allow login forgery
	//--
	return smart.Crc64eB36(smart.DateNowNoTimeUtc() + smart.INVALID_CHARACTER + GetClientIdentAppSafeSignature(r)) // max 13 chars
	//--
} //END FUNCTION


func manageSessUUIDCookie(w http.ResponseWriter, r *http.Request) {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	var sessUUIDCookieName string = ""
	if(smart.HttpSessionUUIDCookieIsEnabled()) {
		sessUUIDCookieName = smart.StrTrimWhitespaces(smart.HttpSessionUUIDCookieNameGet())
	} //end if
	//--
	if(sessUUIDCookieName != "") {
		//--
		crrUUIDCookieVal := smart.StrTrimWhitespaces(GetUuidCookieValue(r))
		//--
		if(DEBUG) {
			log.Println("[DEBUG]", "Web Server: Found Previous UUID Sess Cookie", crrUUIDCookieVal)
		} //end if
		//--
		var crc54ClientIdentHash string = HashCrc64ClientIdent(r)
		//--
		if((crrUUIDCookieVal == "") || (IsSessUUIDCookieValid(crrUUIDCookieVal, crc54ClientIdentHash) != true)) {
			//--
			if(DEBUG) {
				log.Println("[DEBUG]", "Web Server: New UUID Sess Cookie", crrUUIDCookieVal)
			} //end if
			//--
			crrUUIDCookieVal = smart.Sh3a224B64(uid.Uuid17Seq() + "-" + uid.Uuid13Str() + "-" + uid.Uuid10Seq() + "-" + uid.Uuid10Str() + "-" + uid.Uuid10Num())
			crrUUIDCookieVal = smart.BaseEncode([]byte(smart.Base64Decode(crrUUIDCookieVal)), "b62") // max 52 chars
			//--
			crrUUIDCookieVal = crc54ClientIdentHash + "." + crrUUIDCookieVal
			//--
			errSessUUIDCookie := smarthttputils.HttpRequestSetCookieWithDefaults(w, r, sessUUIDCookieName, crrUUIDCookieVal, 0)
			if(errSessUUIDCookie != nil) {
				log.Println("[ERROR]", "Web Server: Failed to Set Session UUID Cookie:", errSessUUIDCookie)
			} else {
				if(DEBUG) {
					log.Println("[DEBUG]", "Web Server: New UUID Sess Cookie was Set")
				} //end if
			} //end if else
			//--
		} //end if
		//--
	} //end if
	//--
} //END FUNCTION


// #END
