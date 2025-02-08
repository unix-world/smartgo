
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250208.2358 :: STABLE
// [ CRYPTO / HASH ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"io"

	"encoding/hex"
	"encoding/base64"

	"hash/crc32"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/hmac"

	"github.com/unix-world/smartgo/crypto/sha3" // {{{SYNC-SMARTGO-SHA3}}} ; this is a better version than golang.org/x/crypto/sha3, works without amd64 ASM - non harware optimized on amd64 version ; from cloudflare: github.com/cloudflare/circl/internal/sha3

	"github.com/unix-world/smartgo/crypto/poly1305"
)


//-----


func HashHmac(algo string, key string, str string, b64 bool) (string, error) {
	//--
	var ok bool = false
	var sum string = ""
	//--
	algo = StrToLower(algo)
	switch(algo) { // {{{SYNC-HASHING-ALGOS-LIST}}}
		//--
		case "sha3-512":
			ok = true
			hmac := hmac.New(sha3.New512, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		case "sha3-384":
			ok = true
			hmac := hmac.New(sha3.New384, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		case "sha3-256":
			ok = true
			hmac := hmac.New(sha3.New256, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		case "sha3-224":
			ok = true
			hmac := hmac.New(sha3.New224, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		//--
		case "sha512":
			ok = true
			hmac := hmac.New(sha512.New, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		case "sha384":
			ok = true
			hmac := hmac.New(sha512.New384, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		case "sha256":
			ok = true
			hmac := hmac.New(sha256.New, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		case "sha224":
			ok = true
			hmac := hmac.New(sha256.New224, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		case "sha1":
			ok = true
			hmac := hmac.New(sha1.New, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		case "md5":
			ok = true
			hmac := hmac.New(md5.New, []byte(key))
			hmac.Write([]byte(str))
			if(b64 == true) {
				sum = base64.StdEncoding.EncodeToString(hmac.Sum(nil))
			} else {
				sum = hex.EncodeToString(hmac.Sum(nil))
			} //end if
			break
		//--
		default: // invalid
			ok = false
	} //end witch
	//--
	if(ok != true) {
		return "", NewError(CurrentFunctionName() + " # " + "Invalid Algo: `" + algo + "`")
	} //end if
	//--
	if(StrTrimWhitespaces(sum) == "") {
		return "", NewError(CurrentFunctionName() + " # Failed to create a HMac Sum for Algo: `" + algo + "`")
	} //end if
	//--
	if(b64 != true) {
		sum = StrToLower(sum)
	} //end if
	//--
	return sum, nil
	//--
} //END FUNCTION


//-----


func Sh3a512(str string) string {
	//--
	hash := sha3.New512()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sh3aByt512(src []byte) []byte {
	//--
	hash := sha3.New512()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sh3a512B64(str string) string {
	//--
	hash := sha3.New512()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func Sh3aByt512B64(src []byte) []byte {
	//--
	hash := sha3.New512()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----


func Sh3a384(str string) string {
	//--
	hash := sha3.New384()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sh3aByt384(src []byte) []byte {
	//--
	hash := sha3.New384()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sh3a384B64(str string) string {
	//--
	hash := sha3.New384()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func Sh3aByt384B64(src []byte) []byte {
	//--
	hash := sha3.New384()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----


func Sh3a256(str string) string {
	//--
	hash := sha3.New256()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sh3aByt256(src []byte) []byte {
	//--
	hash := sha3.New256()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sh3a256B64(str string) string {
	//--
	hash := sha3.New256()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func Sh3aByt256B64(src []byte) []byte {
	//--
	hash := sha3.New256()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----


func Sh3a224(str string) string {
	//--
	hash := sha3.New224()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sh3aByt224(src []byte) []byte {
	//--
	hash := sha3.New224()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sh3a224B64(str string) string {
	//--
	hash := sha3.New224()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func Sh3aByt224B64(src []byte) []byte {
	//--
	hash := sha3.New224()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----


func Sha512(str string) string {
	//--
	hash := sha512.New()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func ShaByt512(src []byte) []byte {
	//--
	hash := sha512.New()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha512B64(str string) string {
	//--
	hash := sha512.New()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func ShaByt512B64(src []byte) []byte {
	//--
	hash := sha512.New()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----
//-#
// SHA384 is roughly 50% faster than SHA-256 on 64-bit machines
// SHA384 has resistances to length extension attack but SHA512 doesn't have
// SHA384 128-bit resistance against the length extension attacks is because the attacker needs to guess the 128-bit to perform the attack, due to the truncation
//-#
//-----


func Sha384(str string) string {
	//--
	hash := sha512.New384()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func ShaByt384(src []byte) []byte {
	//--
	hash := sha512.New384()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha384B64(str string) string {
	//--
	hash := sha512.New384()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func ShaByt384B64(src []byte) []byte {
	//--
	hash := sha512.New384()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----


func Sha256(str string) string {
	//--
	hash := sha256.New()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func ShaByt256(src []byte) []byte {
	//--
	hash := sha256.New()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha256B64(str string) string {
	//--
	hash := sha256.New()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func ShaByt256B64(src []byte) []byte {
	//--
	hash := sha256.New()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----


func Sha224(str string) string {
	//--
	hash := sha256.New224()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func ShaByt224(src []byte) []byte {
	//--
	hash := sha256.New224()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha224B64(str string) string {
	//--
	hash := sha256.New224()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func ShaByt224B64(src []byte) []byte {
	//--
	hash := sha256.New224()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----


func Sha1(str string) string {
	//--
	hash := sha1.New()
	//--
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func ShaByt1(src []byte) []byte {
	//--
	hash := sha1.New()
	//--
	hash.Write(src)
	//--
	return BytToLower(Bin2BytHex(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha1B64(str string) string {
	//--
	hash := sha1.New()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func ShaByt1B64(src []byte) []byte {
	//--
	hash := sha1.New()
	//--
	hash.Write(src)
	//--
	return Base64BytEncode(hash.Sum(nil))
	//--
} //END FUNCTION


//-----


func Md5(str string) string {
	//--
	hash := md5.New()
	//--
	io.WriteString(hash, str)
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func MdByt5(src []byte) []byte {
	//--
	hash := md5.Sum(src)
	//--
	return BytToLower(Bin2BytHex(hash[:]))
	//--
} //END FUNCTION


func Md5B64(str string) string {
	//--
	hash := md5.New()
	//--
	io.WriteString(hash, str)
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func MdByt5B64(src []byte) []byte {
	//--
	hash := md5.Sum(src)
	//--
	return Base64BytEncode(hash[:])
	//--
} //END FUNCTION


//-----


func Crc32b(str string) string {
	//--
	hash := crc32.NewIEEE()
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Crc32bB36(str string) string {
	//--
	hash := crc32.NewIEEE()
	hash.Write([]byte(str))
	//--
	return StrPad2LenLeft(StrToLower(BaseEncode(hash.Sum(nil), "b36")), "0", 7)
	//--
} //END FUNCTION


//-----


func Poly1305(key string, str string, b64 bool) (string, error) {
	//--
	defer PanicHandler() // for: poly1305
	//--
	if(len(key) != 32) {
		return "", NewError(CurrentFunctionName() + " # " + "Key length is invalid, must be 32 bytes !")
	} //end if
	//--
	var pKey [32]byte
	var bKey []byte = []byte(key)
	copy(pKey[:], bKey[0:32])
	//--
	polySum := poly1305.GetSum(pKey, []byte(str))
	//--
	var sum string = string(polySum[:])
	//--
	if(b64 == true) {
		return Base64Encode(sum), nil
	} else { // Hex
		return StrToLower(Bin2Hex(sum)), nil
	} //end if else
	//--
} //END FUNCTION


//-----


// #END
