
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260116.2358 :: STABLE
// [ ENCODERS / DECODERS ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"
	"fmt"

	"encoding/hex"
	"encoding/base64"

	"github.com/unix-world/smartgo/baseconv/base32"
	"github.com/unix-world/smartgo/baseconv/base36"
	"github.com/unix-world/smartgo/baseconv/base58"
	"github.com/unix-world/smartgo/baseconv/base62"
	"github.com/unix-world/smartgo/baseconv/base85"
	"github.com/unix-world/smartgo/baseconv/base92"
)

const (
	REGEX_SAFE_HEX_STR  string = `^[0-9a-f]+$` // as the go have internal, all lowercase
	REGEX_SAFE_B64_STR  string = `^[a-zA-Z0-9\+\/\=]+$`
	REGEX_SAFE_B64S_STR string = `^[a-zA-Z0-9\-_\.]+$`
)

//-----


func BaseEncode(data []byte, toBase string) string {
	//--
	defer PanicHandler()
	//--
	toBase = StrToLower(toBase)
	//--
	if(toBase == "b92") {
		return base92.Encode(data)
	} else if(toBase == "b85") {
		return base85.Encode(data)
	} else if(toBase == "b64s") {
		return Base64sEncode(string(data))
	} else if(toBase == "b64") {
		return Base64Encode(string(data))
	} else if(toBase == "b62") {
		return base62.Encode(data)
	} else if(toBase == "b58") {
		return base58.Encode(data)
	} else if(toBase == "b36") {
		return base36.Encode(data)
	} else if(toBase == "b32") {
		return base32.Encode(data)
	} else if((toBase == "b16") || (toBase == "hex")) { // hex (b16)
		return Bin2Hex(string(data))
	} //end if else
	//--
	log.Println("[ERROR]", CurrentFunctionName(), "# Failed: Invalid Encoding Base: `" + toBase + "`")
	return ""
	//--
} //END FUNCTION


func BaseDecode(data string, fromBase string) []byte {
	//--
	defer PanicHandler() // req. by hex2bin and base64
	//--
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return nil
	} //end if
	if(!StrRegexMatch(REGEX_ASCII_NOSPACE_CHARACTERS, data)) { // safety
		return nil
	} //end if
	//--
	fromBase = StrToLower(fromBase)
	//--
	var decoded []byte = nil
	var err error = nil
	//--
	if(fromBase == "b92") {
		decoded, err = base92.Decode(data)
	} else if(fromBase == "b85") {
		decoded, err = base85.Decode(data)
	} else if(fromBase == "b64s") {
		decoded = []byte(Base64sDecode(data))
	} else if(fromBase == "b64") {
		decoded = []byte(Base64Decode(data))
	} else if(fromBase == "b62") {
		decoded, err = base62.Decode(data)
	} else if(fromBase == "b58") {
		decoded, err = base58.Decode(data)
	} else if(fromBase == "b36") {
		decoded, err = base36.Decode(data)
	} else if(fromBase == "b32") {
		decoded, err = base32.Decode(data)
	} else if((fromBase == "b16") || (fromBase == "hex")) { // hex (b16)
		decoded = []byte(Hex2Bin(data))
	} else {
		err = NewError("Invalid Decoding Base: `" + fromBase + "`")
	} //end if else
	//--
	if(err != nil) {
		log.Println("[ERROR]", CurrentFunctionName(), "# Failed:", err)
		return nil
	} //end if
	//--
	return decoded
	//--
} //END FUNCTION


//-----


func Base64BytEncode(data []byte) []byte {
	//--
	defer PanicHandler() // req. by base64 enc
	//--
	var dst []byte = make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	//--
	return dst
	//--
} //END FUNCTION


func Base64BytDecode(data []byte) []byte {
	//--
	defer PanicHandler() // req. by base64 decode panic handler with malformed data
	//--
	data = BytTrimWhitespaces(data) // required, to remove extra space like characters, go b64dec is strict !
	if(data == nil) {
		return nil
	} //end if
	//--
	if(!BytRegexMatch(REGEX_SAFE_B64_STR, data)) {
		return nil
	} //end if
	//--
	var l int = len(data) % 4
	if(l > 0) {
		if(l == 1) { // {{{SYNC-B64-WRONG-PAD-3}}} ; it cannot end with 3 "=" signs ; every 4 characters of base64 encoded string represent exactly 3 bytes, because byte contains 8 bits (2^8), and 64 = 2^6 ; so 4 characters of base-64 encoding can hold up to 2^6 * 2^6 * 2^6 * 2^6 bits, which is exactly 2^8 * 2^8 * 2^8 = 3 bytes
			log.Println("[NOTICE]", CurrentFunctionName(), "# Failed: Invalid B64 Padding Length, more than 2, L =", 4 - l)
			return nil
		} //end if
		data = append(data, BytRepeat([]byte("="), 4 - l)...) // fix missing padding ; can end just with = or == (=== is INVALID, see above)
	} //end if
	//--
	var dst []byte = make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(dst, data)
	if(err != nil) { // be flexible, don't return, try to decode as much as possible, just notice
		log.Println("[NOTICE]", CurrentFunctionName(), "# Failed:", err)
		return nil
	} //end if
	dst = dst[:n]
	//--
	return dst
	//--
} //END FUNCTION


func Base64sBytEncode(data []byte) []byte {
	//--
	defer PanicHandler() // req. by base64 enc
	//--
	if(data == nil) {
		return nil
	} //end if
	//--
	data = Base64BytEncode(data)
	//--
	data = BytReplaceAll(data, []byte("+"), []byte("-"))
	data = BytReplaceAll(data, []byte("/"), []byte("_"))
	data = BytReplaceAll(data, []byte("="), []byte("."))
	//--
	return data
	//--
} //END FUNCTION


func Base64sBytDecode(data []byte) []byte {
	//--
	defer PanicHandler() // req. by base64 decode panic handler with malformed data
	//--
	if(data == nil) {
		return nil
	} //end if
	//--
	if(!BytRegexMatch(REGEX_SAFE_B64S_STR, data)) {
		return nil
	} //end if
	//--
	data = BytReplaceAll(data, []byte("."), []byte("="))
	data = BytReplaceAll(data, []byte("_"), []byte("/"))
	data = BytReplaceAll(data, []byte("-"), []byte("+"))
	//--
	data = Base64BytDecode(data)
	//--
	return data
	//--
} //END FUNCTION


func Base64BytToBase64s(data []byte) []byte {
	//--
	if(data == nil) {
		return nil
	} //end if
	//--
	data = BytReplaceAll(data, []byte("+"), []byte("-"))
	data = BytReplaceAll(data, []byte("/"), []byte("_"))
	data = BytReplaceAll(data, []byte("="), []byte("."))
	//--
	return data
	//--
} //END FUNCTION


func Base64sBytToBase64(data []byte) []byte {
	//--
	if(data == nil) {
		return nil
	} //end if
	//--
	data = BytReplaceAll(data, []byte("."), []byte("="))
	data = BytReplaceAll(data, []byte("_"), []byte("/"))
	data = BytReplaceAll(data, []byte("-"), []byte("+"))
	//--
	return data
	//--
} //END FUNCTION


func Base64BytToBase64u(data []byte) []byte {
	//--
	if(data == nil) {
		return nil
	} //end if
	//--
	data = Base64BytToBase64s(data)
	data = BytTrimRight(data, ".") // B64u have no padding
	//--
	return data
	//--
} //END FUNCTION


func Base64uBytToBase64(data []byte) []byte {
	//--
	if(data == nil) {
		return nil
	} //end if
	//--
	return Base64sBytToBase64(data) // the missing padding will be fixed inside B64 Decode
	//--
} //END FUNCTION


//-----


func Base64Encode(data string) string {
	//--
	defer PanicHandler() // req. by base64 enc
	//--
	return base64.StdEncoding.EncodeToString([]byte(data))
	//--
} //END FUNCTION


func Base64Decode(data string) string {
	//--
	defer PanicHandler() // req. by base64 decode panic handler with malformed data
	//--
	data = StrTrimWhitespaces(data) // required, to remove extra space like characters, go b64dec is strict !
	if(data == "") {
		return ""
	} //end if
	//--
	if(!StrRegexMatch(REGEX_SAFE_B64_STR, data)) {
		return ""
	} //end if
	//--
	var l int = len(data) % 4
	if(l > 0) {
		if(l == 1) { // {{{SYNC-B64-WRONG-PAD-3}}} ; it cannot end with 3 "=" signs ; every 4 characters of base64 encoded string represent exactly 3 bytes, because byte contains 8 bits (2^8), and 64 = 2^6 ; so 4 characters of base-64 encoding can hold up to 2^6 * 2^6 * 2^6 * 2^6 bits, which is exactly 2^8 * 2^8 * 2^8 = 3 bytes
			log.Println("[NOTICE]", CurrentFunctionName(), "# Failed: Invalid B64 Padding Length, more than 2, L =", 4 - l)
			return ""
		} //end if
		data += StrRepeat("=", 4 - l) // fix missing padding ; can end just with = or == (=== is INVALID, see above)
	} //end if
	//--
	decoded, err := base64.StdEncoding.DecodeString(data)
	if(err != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + "# Failed:", err)
		return ""
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


func Base64sEncode(data string) string {
	//--
	defer PanicHandler() // req. by base64 enc
	//--
	if(data == "") {
		return ""
	} //end if
	//--
	data = Base64Encode(data)
	//--
	data = StrReplaceAll(data, "+", "-")
	data = StrReplaceAll(data, "/", "_")
	data = StrReplaceAll(data, "=", ".")
	//--
	return data
	//--
} //END FUNCTION


func Base64sDecode(data string) string {
	//--
	defer PanicHandler() // req. by base64 decode panic handler with malformed data
	//--
	if(data == "") {
		return ""
	} //end if
	//--
	if(!StrRegexMatch(REGEX_SAFE_B64S_STR, data)) {
		return ""
	} //end if
	//--
	data = StrReplaceAll(data, ".", "=")
	data = StrReplaceAll(data, "_", "/")
	data = StrReplaceAll(data, "-", "+")
	//--
	data = Base64Decode(data)
	//--
	return data
	//--
} //END FUNCTION


func Base64ToBase64s(data string) string {
	//--
	if(data == "") {
		return ""
	} //end if
	//--
	data = StrReplaceAll(data, "+", "-")
	data = StrReplaceAll(data, "/", "_")
	data = StrReplaceAll(data, "=", ".")
	//--
	return data
	//--
} //END FUNCTION


func Base64sToBase64(data string) string {
	//--
	if(data == "") {
		return ""
	} //end if
	//--
	data = StrReplaceAll(data, ".", "=")
	data = StrReplaceAll(data, "_", "/")
	data = StrReplaceAll(data, "-", "+")
	//--
	return data
	//--
} //END FUNCTION


func Base64ToBase64u(data string) string {
	//--
	if(data == "") {
		return ""
	} //end if
	//--
	data = Base64ToBase64s(data)
	data = StrTrimRight(data, ".") // B64u have no padding
	//--
	return data
	//--
} //END FUNCTION


func Base64uToBase64(data string) string {
	//--
	if(data == "") {
		return ""
	} //end if
	//--
	return Base64sToBase64(data) // the missing padding will be fixed inside B64 Decode
	//--
} //END FUNCTION


//-----


func UInt64ToHex(num uint64) string {
	//--
	return fmt.Sprintf("%x", num)
	//--
} //END FUNCTION


//-----


func Bin2Hex(str string) string { // inspired from: https://www.php2golang.com/
	//--
	defer PanicHandler() // req. by hex2bin
	//--
	return hex.EncodeToString([]byte(str))
	//--
} //END FUNCTION


func Hex2Bin(str string) string { // inspired from: https://www.php2golang.com/
	//--
	defer PanicHandler() // req. by hex2bin panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str) // required, to remove extra space like characters, go hex2bin is strict !
	if(str == "") {
		return ""
	} //end if
	//--
	if(!StrRegexMatch(REGEX_SAFE_HEX_STR, str)) {
		return ""
	} //end if
	//--
	if((len(str) % 2) > 0) {
		log.Println("[NOTICE]", CurrentFunctionName(), "# Failed: odd length, not even ; L =", len(str))
		return ""
	} //end if
	//--
	decoded, err := hex.DecodeString(str)
	if(err != nil) {
		log.Println("[NOTICE]", CurrentFunctionName(), "# Failed:", err)
		return ""
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


func Bin2BytHex(src []byte) []byte {
	//--
	defer PanicHandler() // req. by hex2bin
	//--
	var dst []byte = make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	//--
	return dst
	//--
} //END FUNCTION


func Hex2BytBin(src []byte) []byte {
	//--
	defer PanicHandler() // req. by hex2bin panic handler with malformed data
	//--
	src = BytTrimWhitespaces(src) // required, to remove extra space like characters, go hex2bin is strict !
	if(src == nil) {
		return nil
	} //end if
	//--
	if(!BytRegexMatch(REGEX_SAFE_HEX_STR, src)) {
		return nil
	} //end if
	//--
	if((len(src) % 2) > 0) {
		log.Println("[NOTICE]", CurrentFunctionName(), "# Failed: odd length, not even ; L =", len(src))
		return nil
	} //end if
	//--
	var dst []byte = make([]byte, hex.DecodedLen(len(src)))
	n, err := hex.Decode(dst, src)
	if(err != nil) {
		log.Println("[NOTICE]", CurrentFunctionName(), "# Failed:", err)
		return nil
	} //end if
	dst = dst[:n]
	//--
	return dst
	//--
} //END FUNCTION


//-----


// #END
