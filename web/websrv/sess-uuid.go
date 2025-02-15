
// GO Lang :: SmartGo / Web Server / Session-UUID :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250214.2358 :: STABLE

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
	REGEX_SESS_UUID_COOKIE_VALID_VALUE string = `^[A-Za-z0-9]+` // B62
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
	name := GetUuidCookieName()
	if(name == "") {
		return ""
	} //end if
	//--
	value := smart.StrTrimWhitespaces(smarthttputils.HttpRequestGetCookie(r, name))
	//--
	if(IsSessUUIDCookieValid(value) != true) {
		return ""
	} //end if
	//--
	return value
	//--
} //END FUNCTION


func IsSessUUIDCookieValid(crrUUIDCookieVal string) bool {
	//--
	if((smart.StrTrimWhitespaces(crrUUIDCookieVal) == "") || (len(crrUUIDCookieVal) < 34) || (len(crrUUIDCookieVal) > 52) || (!smart.StrRegexMatch(REGEX_SESS_UUID_COOKIE_VALID_VALUE, crrUUIDCookieVal))) { // if sh3a224 (b62) is mostly ~ 38 characters ; be flexible as +/- 4 characters (34..52 bytes)
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func manageSessUUIDCookie(w http.ResponseWriter, r *http.Request) {
	//--
	defer smart.PanicHandler() // safe recovery handler
	//--
	var sessUUIDCookieName string = ""
	if(smart.HttpSessionUUIDCookieIsEnabled()) {
		sessUUIDCookieName = smart.HttpSessionUUIDCookieNameGet()
	} //end if
	//--
	if(sessUUIDCookieName != "") {
		//--
		crrUUIDCookieVal := smart.StrTrimWhitespaces(smarthttputils.HttpRequestGetCookie(r, sessUUIDCookieName))
		//--
		if(DEBUG) {
			log.Println("[DEBUG]", "Web Server: Found Previous UUID Sess Cookie", crrUUIDCookieVal)
		} //end if
		//--
		if(IsSessUUIDCookieValid(crrUUIDCookieVal) != true) {
			//--
			if(DEBUG) {
				log.Println("[DEBUG]", "Web Server: New UUID Sess Cookie", crrUUIDCookieVal)
			} //end if
			//--
			crrUUIDCookieVal = smart.Sh3a224B64(uid.Uuid17Seq() + "-" + uid.Uuid13Str() + "-" + uid.Uuid10Seq() + "-" + uid.Uuid10Str() + "-" + uid.Uuid10Num())
			crrUUIDCookieVal = smart.BaseEncode([]byte(smart.Base64Decode(crrUUIDCookieVal)), "b62")
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
	} //end if
	//--
} //END FUNCTION


// #END
