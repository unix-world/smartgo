
// GO Lang :: SmartGo / Web Server / Client-Ident :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241123.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"net/http"

	smart 			"github.com/unix-world/smartgo"
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


func GetClientIdentUidHash(r *http.Request) string {
	//--
	pk := GetClientIdentPrivateKey(r)
	//--
	ckUid := GetUuidCookieValue(r)
	if(ckUid != "") {
		pk += smart.FORM_FEED + ckUid
	} //end if
	//--
	return smart.Base64ToBase64s(smart.Sh3a512B64(pk))
	//--
} //END FUNCTION


func GetClientIdentPrivateKey(r *http.Request) string {
	//--
	ns, _ := smart.AppGetNamespace()
	sk, _ := smart.CryptoGetSecurityKey()
	//--
	return getClientIdentSignature(r) + " [#] " + ns + "*" + smart.Base64ToBase64s(smart.Sh3a512B64(sk)) + "." // use a hash of security key to avoid expose by mistake !
	//--
} //END FUNCTION


func getClientIdentSignature(r *http.Request) string {
	//--
	signature := smart.GetHttpUserAgentFromRequest(r)
	//--
	isOk, clientRealIp := GetVisitorRealIpAddr(r)
	//--
	var cliType string = "Client"
	if(isOk != true) {
		cliType = "Fake-Client"
	} //end if
	//--
	return cliType + " // " + clientRealIp + " :: " + signature // fix: do not use Proxy client IP here ... if using DNS load balancing + multiple load balancers with multiple backends switching the load balancer (aka reverse proxy) when browsing and changing between web pages will change this signature which will change the client_ident_private_key() and then may lead to user session expired ...
	//--
} //END FUNCTION


// #END
