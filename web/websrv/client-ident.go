
// GO Lang :: SmartGo / Web Server / Client-Ident :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250214.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"net/http"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
	otp 			"github.com/unix-world/smartgo/web/2fa-totp"
)


func Is2FATotpSecretValid(secret string) bool {
	//--
	if(secret == "") {
		return false
	} //end if
	//--
	return otp.IsSecretValid(secret, otp.DEFAULT_LENGTH)
	//--
} //END FUNCTION


func Get2FATotp(secret string) (string, *otp.TOTP, error) {
	//--
	secret = smart.StrTrimWhitespaces(secret)
	if(secret == "") {
		secret = otp.RandomSecret(otp.DEFAULT_LENGTH)
	} //end if
	//--
	if(Is2FATotpSecretValid(secret) != true) {
		return "", nil, smart.NewError("Invalid TOTP Secret")
	} //end if
	//--
	totp := otp.NewTOTP(secret, otp.DEFAULT_DIGITS, otp.DEFAULT_INTERVAL, otp.DEFAULT_ALGO)
	if(totp == nil) {
		return "", nil, smart.NewError("Invalid TOTP")
	} //end if
	//--
	return secret, totp, nil
	//--
} //END FUNCTION


func GetClientIdentAppSafeSignature(r *http.Request) string {
	//--
	return smarthttputils.GetClientIdentAppSafeSignature(r)
	//--
} //END FUNCTION


func GetClientIdentUidHash(r *http.Request) string { // used for captcha and other specific purposes
	//--
	return smarthttputils.GetClientIdentUidHash(r, GetUuidCookieValue(r))
	//--
} //END FUNCTION


// #END
