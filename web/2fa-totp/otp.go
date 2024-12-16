
// (c) 2024-present unix-world.org
// v.20241216.2358
// license: BSD

// based on: github.com/xlzd/gotp # license: MIT

package otp

import (
	"fmt"
	"log"

	"strings"
	"encoding/base32"

	"math"
	crand "crypto/rand"

	smart "github.com/unix-world/smartgo"
)


const (
	DEFAULT_LENGTH uint8 = 256 / 8
	DEFAULT_ALGO string = "sha384"
	DEFAULT_DIGITS uint8 = 8
	DEFAULT_INTERVAL uint16 = 30

	URL_OTPAUTH string = "otpauth://totp/" // just for TOTP ...
)

var (
	DEBUG bool = smart.DEBUG
)


type OTP struct {
	secret string // secret in base32 format
	digits uint8  // number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
	algo   string // algo
}


func currentTimestamp() int64 {
	//--
	return smart.TimeNowLocal()
	//--
} //END FUNCTION


func newOTP(secret string, digits uint8, algo string) OTP {
	//--
	return OTP {
		secret: secret,
		digits: digits,
		algo:   algo,
	}
	//--
} //END FUNCTION


//-----


//--
// Returns the provisioning URI for the OTP; only works for TOTP.
// This can then be encoded in a QR Code and used to provision the Google Authenticator app.
// For module-internal use.
// See also:
//     https://github.com/google/google-authenticator/wiki/Key-Uri-Format
// params:
//     secret:       the totp secret used to generate the URI
//     accountName:  name of the account
//     issuerName:   the name of the OTP issuer; this will be the organization title of the OTP entry in Authenticator
//     algorithm:    the algorithm used in the OTP generation
//     digits:       the length of the OTP generated code.
//     period:       the number of seconds the OTP generator is set to expire every code.
// returns: provisioning uri
//--
func buildUri(secret string, accountName string, issuerName string, algorithm string, digits uint8, period uint16) string {
	//--
	defer smart.PanicHandler()
	//--
	secret = smart.StrToLower(smart.StrTrimWhitespaces(secret)) // URIs for Tokens are Case Insensitive, use lower-case as in Input
	accountName = smart.StrToLower(smart.StrTrimWhitespaces(accountName))
	algorithm = smart.StrToUpper(smart.StrTrimWhitespaces(algorithm))
	//--
	issuerName = smart.StrTrimWhitespaces(issuerName) // camelcase
	if(issuerName != "") {
		issuerName = "SmartGoTwoFactorAuthTOTP"
	} //end if
	//--
	appNs, errNs := smart.AppGetNamespace()
	if(errNs != nil) {
		appNs = ""
	} //end if
	appNs = smart.StrTrimWhitespaces(appNs) // just in case ...
	//--
	var urlSafeAccount string = ""
	if(appNs != "") {
		urlSafeAccount = smart.EscapeUrl(appNs) + ":"
	} //end if
	urlSafeAccount += smart.EscapeUrl(accountName)
	//--
	return URL_OTPAUTH + urlSafeAccount + "?secret=" + smart.EscapeUrl(secret) + "&algorithm=" + smart.EscapeUrl(algorithm) + "&digits=" + smart.ConvertUInt8ToStr(digits) + "&period=" + smart.ConvertUInt16ToStr(period) + "&issuer=" + smart.EscapeUrl(issuerName) + "&"
	//--
} //END FUNCTION


// generate a random secret of given length (number of bytes)
// returns empty string if something bad happened
func RandomSecret(length uint8) string {
	//--
	defer smart.PanicHandler()
	//--
	if((length <= 10) || (length > 64)) { // this is for the default case, if 0 is passed, will use default ! this is the raw length (in TOTP min length of 20 is checked) !!
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Invalid Length:", length, "; Using Defaults")
		length = DEFAULT_LENGTH // use default length, as in PHP
	} //end if
	//--
	secret := make([]byte, length)
	gen, err := crand.Read(secret)
	if((err != nil) || (gen != int(length))) {
		return "" // error reading random, return empty string
	}
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	//--
	return smart.StrToLower(encoder.EncodeToString(secret)) // secret output should be case insensitive ...
	//--
} //END FUNCTION


// A non-panic way of seeing weather or not a given secret is valid
func IsSecretValid(secret string, desiredLength uint8) bool {
	//--
	defer smart.PanicHandler()
	//--
	secret = smart.StrToUpper(smart.StrTrimWhitespaces(secret)) // input is case-insensitive, convert as in Base32 standards to UpperCase
	//--
	length := len(secret)
	if((length < 20) || (length > 128)) { // should be between is 26 (128 bit) and 103 (512 bit), but be more flexible, as in PHP
		return false
	} //end if
	//--
	missingPadding := len(secret) % 8
	if(missingPadding != 0) {
		secret = secret + strings.Repeat("=", 8-missingPadding)
	} //end if
	//--
	data, err := base32.StdEncoding.DecodeString(secret)
	//--
	if(err != nil) {
		return false
	} //end if
	//--
	if(desiredLength > 0) {
		if((len(data) <= 0) || (len(data) != int(desiredLength))) {
			return false
		} //end if
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


// integer to byte array
func integerToByteArray(integer int64) []byte { // this is like the PHP equivalent: packCounter
	byteArr := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		byteArr[i] = byte(integer & 0xff)
		integer = integer >> 8
	} //end for
	return byteArr
} //END FUNCTION


func (o *OTP) generateOTP(input int64) string {
	//--
	// input: the HMAC counter value to use as the OTP input. Usually either the counter, or the computed integer based on the Unix timestamp
	//--
	defer smart.PanicHandler()
	//--
	if(input < 0) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Input must be positive int64")
		return ""
	} //end if
	//--
	secret, errS := o.getSecret()
	if((errS != nil) || (secret == "")) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Secret B32 Decode Failed", errS)
		return ""
	} //end if
	//--
	bInput := integerToByteArray(input)
	hmacStrHash, errH := smart.HashHmac(o.algo, secret, string(bInput), false)
	if(errH != nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Hmac Hashing Failed", errH)
		return ""
	} //end if
	hmacStrHash = smart.Hex2Bin(hmacStrHash)
	hmacHash := []byte(hmacStrHash)
	//--
	offset 	:= int(hmacHash[len(hmacHash)-1] & 0xf)
	code 	:= ((int(hmacHash[offset]) & 0x7f) << 24) |
				((int(hmacHash[offset+1] & 0xff)) << 16) |
				((int(hmacHash[offset+2] & 0xff)) << 8) |
				(int(hmacHash[offset+3]) & 0xff)
	code = code % int(math.Pow10(int(o.digits)))
	//--
	return fmt.Sprintf(fmt.Sprintf("%%0%dd", o.digits), code)
	//--
} //END FUNCTION


func (o *OTP) getSecret() (string, error) {
	//--
	defer smart.PanicHandler()
	//--
	secret := o.secret
	missingPadding := len(secret) % 8
	if(missingPadding != 0) {
		secret = secret + strings.Repeat("=", 8-missingPadding)
	} //end if
	//--
	bytes, err := base32.StdEncoding.DecodeString(secret)
	if(err != nil) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Secret B32 Decode Failed", err)
		return "", err
	} //end if
	//--
	return string(bytes), nil
	//--
} //END FUNCTION


// #end
