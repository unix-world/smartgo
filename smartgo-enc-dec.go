
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241129.2358 :: STABLE
// [ ENCODERS / DECODERS ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"
	"fmt"

	"strings"

	"encoding/hex"
	"encoding/base64"

	"github.com/unix-world/smartgo/baseconv/base32"
	"github.com/unix-world/smartgo/baseconv/base36"
	"github.com/unix-world/smartgo/baseconv/base58"
	"github.com/unix-world/smartgo/baseconv/base62"
	"github.com/unix-world/smartgo/baseconv/base85"
	"github.com/unix-world/smartgo/baseconv/base92"
)

//-----


func BaseEncode(data []byte, toBase string) string {
	//--
	defer PanicHandler()
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
	log.Println("[ERROR] " + CurrentFunctionName() + ":", "Invalid Encoding Base: `" + toBase + "`")
	return ""
	//--
} //END FUNCTION


func BaseDecode(data string, fromBase string) []byte {
	//--
	defer PanicHandler() // req. by hex2bin
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
		log.Println("[ERROR] " + CurrentFunctionName() + ":", err)
		return nil
	} //end if
	//--
	return decoded
	//--
} //END FUNCTION


//-----


func Base64Encode(data string) string {
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
	if l := len(data) % 4; l > 0 {
		data += strings.Repeat("=", 4-l) // fix missing padding
	} //end if
	//--
	decoded, err := base64.StdEncoding.DecodeString(data)
	if(err != nil) { // be flexible, don't return, try to decode as much as possible, just notice
		log.Println("[NOTICE] " + CurrentFunctionName() + ": ", err)
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


func Base64sEncode(data string) string {
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
	data = StrReplaceAll(data, "+", "-")
	data = StrReplaceAll(data, "/", "_")
	data = StrReplaceAll(data, "=", ".")
	//--
	return data
	//--
} //END FUNCTION


func Base64sToBase64(data string) string {
	//--
	data = StrReplaceAll(data, ".", "=")
	data = StrReplaceAll(data, "_", "/")
	data = StrReplaceAll(data, "-", "+")
	//--
	return data
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
	src := []byte(str)
	encodedStr := hex.EncodeToString(src)
	//--
	return encodedStr
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
	decoded, err := hex.DecodeString(str)
	if(err != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + " Failed:", err)
		//return "" // be flexible, don't return, try to decode as much as possible ...
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


//-----


// #END
