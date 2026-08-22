
// SmartGo Web OAuth2 :: Client API
// (c) 2026-present unix-world.org
// v.20260817.2358
// license: BSD

package csrf

import (
//	"log"

	smart 	"github.com/unix-world/smartgo"

	uid 	"github.com/unix-world/smartgo/crypto/uuid"
)


//-----


func NewPrivateKey() (string, error) {
	//--
	defer smart.PanicHandler() // for: HexToInt64, BaseEncode
	//--
	var hexTimeNowUnix string = smart.StrTrimWhitespaces(smart.TimeNowHexUnix())
	if(hexTimeNowUnix == "") {
		return "", smart.NewError("Hex Time Now Unix is Empty")
	} //end if
	//--
	var rawTimeNowUnix int64 = smart.HexToInt64(hexTimeNowUnix, false) // disallow negatives
	if(rawTimeNowUnix <= 0) {
		return "", smart.NewError("Raw Time Now Unix is Zero or Negative")
	} //end if
	//--
	var rawStrTimeNowUnix string = smart.StrTrimWhitespaces(smart.ConvertInt64ToStr(rawTimeNowUnix))
	if(rawStrTimeNowUnix == "") {
		return "", smart.NewError("Raw Time Now Unix is Empty")
	} //end if
	//--
	var b62TimeNowUnix string = smart.StrTrimWhitespaces(smart.BaseEncode([]byte(rawStrTimeNowUnix), "b62"))
	if(b62TimeNowUnix == "") {
		return "", smart.NewError("Base62 Time Now Unix is Empty")
	} //end if
	//--
	var uuid37 string = uid.Uuid17Seq() + uid.Uuid10Num() + uid.Uuid10Str()
	//--
	var privKey string = b62TimeNowUnix + "#" + uuid37
	if(len(privKey) > 1024) { // {{{SYNC-CSRF-PRIVKEY-MAX-LEN}}}
		return "", smart.NewError("Private Key Failed, Key is Too Long")
	} //end if
	//--
	return privKey, nil
	//--
} //END FUNCTION


//-----


func GetPublicKey(privKey string, secret string) (string, error) {
	//--
	defer smart.PanicHandler() // for: SafeChecksumHashSmart
	//--
	privKey = smart.StrTrimWhitespaces(privKey)
	if(privKey == "") {
		return "", smart.NewError("Private Key is Empty")
	} //end if
	if(len(privKey) > 1024) { // {{{SYNC-CSRF-PRIVKEY-MAX-LEN}}}
		return "", smart.NewError("Private Key is Too Long")
	} //end if
	//--
	if(smart.StrTrimWhitespaces(secret) == "") { // do not trim secret, use trim only on compare
		return "", smart.NewError("Secret is Empty")
	} //end if
	if(len(secret) > 4096) { // {{{SYNC-CSRF-SECRET-MAX-LEN}}}
		return "", smart.NewError("Secret is Too Long")
	} //end if
	//--
	checksum, errChecksum := smart.SafeChecksumHashSmart(secret + smart.NULL_BYTE + privKey, "") // use default salt, no custom salt
	if(errChecksum != nil) {
		return "", smart.NewError("Checksum Failed: " + errChecksum.Error())
	} //end if
	//--
	var pubKey string = smart.StrTrimWhitespaces(checksum)
	if(pubKey == "") {
		return "", smart.NewError("Public Key Failed, Key is Empty")
	} //end if
	if(len(pubKey) > 255) { // {{{SYNC-CSRF-PUBKEY-MAX-LEN}}}
		return "", smart.NewError("Public Key Failed, Key is Too Long")
	} //end if
	//--
	return pubKey, nil
	//--
} //END FUNCTION


//-----


func VerifyKeys(pubKey string, privKey string, secret string, expireSeconds int64) bool {
	//--
	defer smart.PanicHandler() // for: BaseDecode, Int64ToHex
	//--
	if(expireSeconds == 0) {
		expireSeconds = 3600 // default
	} //end if
	if(expireSeconds < 60) {
		return false
	} else if(expireSeconds > 7200) {
		return false
	} //end if
	//--
	pubKey = smart.StrTrimWhitespaces(pubKey)
	if(pubKey == "") {
		return false
	} //end if
	if(len(pubKey) > 255) { // {{{SYNC-CSRF-PUBKEY-MAX-LEN}}}
		return false
	} //end if
	//--
	privKey = smart.StrTrimWhitespaces(privKey)
	if(privKey == "") {
		return false
	} //end if
	if(len(privKey) > 1024) { // {{{SYNC-CSRF-PRIVKEY-MAX-LEN}}}
		return false
	} //end if
	//--
	if(smart.StrTrimWhitespaces(secret) == "") { // do not trim secret, use trim only on compare
		return false
	} //end if
	if(len(secret) > 4096) { // {{{SYNC-CSRF-SECRET-MAX-LEN}}}
		return false
	} //end if
	//--
	if(!smart.StrContains(privKey, "#")) {
		return false
	} //end if
	arr := smart.ExplodeWithLimit("#", privKey, 2)
	if(len(arr) != 2) {
		return false
	} //end if
	var b62 string = smart.StrTrimWhitespaces(arr[0])
	if(b62 == "") {
		return false
	} //end if
	if(!smart.StrRegexMatch(smart.REGEX_SAFE_B62_STR, b62)) { // safety check, must contain only 0-9 a-f ; must not use the 0x prefix !
		return false
	} //end if
	//--
	var rawTime []byte = smart.BytTrimWhitespaces(smart.BaseDecode(b62, "b62"))
	if(rawTime == nil) {
		return false
	} //end if
	//--
	var rawNumTime int64 = smart.ParseStrAsInt64(string(rawTime))
	if(rawNumTime <= 0) {
		return false
	} //end if
	//--
	var hexTime string = smart.StrTrimWhitespaces(smart.Int64ToHex(rawNumTime, false)) // disallow negatives
	if(hexTime == "") {
		return false
	} //end if
	//--
	if(smart.SafeCheckTimeDifferenceFromNow(false, hexTime, expireSeconds) != true) { // the difference in seconds must not be more than expireSeconds ; must be true
		return false
	} //end if
	//--
	var ok bool = false
	if((pubKey != "") && (privKey != "") && (secret != "")) {
		chkPubKey, errChkPubKey := GetPublicKey(privKey, secret)
		if(errChkPubKey == nil) {
			if(smart.StrTrimWhitespaces(chkPubKey) != "") {
				if(pubKey == chkPubKey) {
					ok = true
				} //end if
			} //end if
		} //end if
	} //end if
	//--
	return ok
	//--
} //END FUNCTION


//-----


// #END
