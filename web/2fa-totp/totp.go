
// (c) 2024-present unix-world.org
// v.20241216.2358
// license: BSD

// based on: github.com/xlzd/gotp # license: MIT

package otp

import (
	"log"

	smart "github.com/unix-world/smartgo"
)


// time-based OTP counters.
type TOTP struct {
	OTP
	interval uint16
}

func NewTOTP(secret string, digits uint8, interval uint16, algo string) *TOTP {
	//--
	secret = smart.StrToUpper(smart.StrTrimWhitespaces(secret)) // input is case-insensitive, convert as in Base32 standards to UpperCase
	//--
	if(IsSecretValid(secret, 0) != true) {
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Secret / Length")
		return nil
	} //end if
	//--
	if((digits < 4) || (digits > 16)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Invalid Digits:", digits, "; Using Defaults")
		digits = DEFAULT_DIGITS
	} //end if
	//--
	if((interval < 15) || (interval > 600)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Invalid Interval:", interval, "; Using Defaults")
		interval = DEFAULT_INTERVAL
	} //end if
	//--
	algo = smart.StrToLower(smart.StrTrimWhitespaces(algo))
	switch(algo) {
		case "md5":
		case "sha1":
		case "sha224":
		case "sha256":
		case "sha384":
		case "sha512":
			if(DEBUG) {
				log.Println("[DEBUG]", smart.CurrentFunctionName(), "Algo", algo, "Digits", digits)
			} //end if
			break
		default:
			algo = DEFAULT_ALGO
			log.Println("[WARNING]", smart.CurrentFunctionName(), "Algo (FALLBACK)", algo, "Digits", digits)
			break
	} //end if
	//--
	otp := newOTP(secret, digits, algo) // default is: 6 digits, 30 seconds, sha1
	//--
	return &TOTP{OTP: otp, interval: interval}
	//--
} //END FUNCTION


// Generate the current time OTP
func (t *TOTP) Now() string {
	//--
	return t.At(currentTimestamp())
	//--
} //END FUNCTION


func (t *TOTP) At(timestamp int64) string { // Generate time OTP of given timestamp
	//--
	tc := timestamp / int64(t.interval)
	//--
	return t.generateOTP(tc)
	//--
} //END FUNCTION


func (t *TOTP) Verify(otp string, timestamp int64) bool {
	//--
	return otp == t.At(timestamp)
	//--
} //END FUNCTION


func (t *TOTP) GenerateBarcodeUrl(accountName string, issuerName string) string {
	//--
	return buildUri(
		t.secret,
		accountName,
		issuerName,
		t.algo,
		t.digits,
		t.interval)
	//--
} //END FUNCTION


// #end
