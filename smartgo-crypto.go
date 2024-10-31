
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241031.1532 :: STABLE
// [ CRYPTO ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"strings"

	"math"
	"math/big"

	"io"

	"encoding/hex"
	"encoding/base64"
	"encoding/pem"

	"crypto"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/ed25519"

	"hash/crc32"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/hmac"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/argon2"
//	"golang.org/x/crypto/sha3"
	"github.com/unix-world/smartgo/crypto/sha3" // this is a better version than above, works without amd64 ASM - non harware optimized on amd64 version ; from cloudflare: github.com/cloudflare/circl/internal/sha3
	"github.com/unix-world/smartgo/crypto/poly1305"
	"github.com/unix-world/smartgo/crypto/pbkdf2"
	"github.com/unix-world/smartgo/crypto/blowfish"
	"github.com/unix-world/smartgo/crypto/twofish"
	"github.com/unix-world/smartgo/crypto/threefish"
)

const (
	SEPARATOR_CRYPTO_CHECKSUM_V1 string 	= "#CHECKSUM-SHA1#" 							// compatibility, v1 ; blowfish only
	SEPARATOR_CRYPTO_CHECKSUM_V2 string 	= "#CKSUM256#" 									// compatibility, v2 ; blowfish only
	SEPARATOR_CRYPTO_CHECKSUM_V3 string 	= "#CKSUM512V3#" 								// current, v3 ; threefish, twofish, blowfish

	SIGNATURE_BFISH_V1 string 				= "bf384.v1!" 									// compatibility, v1 ; decrypt only
	SIGNATURE_BFISH_V2 string 				= "bf448.v2!" 									// compatibility, v2 ; decrypt only
	SIGNATURE_BFISH_V3 string 				= "bf448.v3!" 									// current, v3 ; encrypt + decrypt

	SIGNATURE_2FISH_V1_DEFAULT string 		= "2f256.v1!" 									// current, v1 (default)   ; encrypt + decrypt
	SIGNATURE_2FISH_V1_BF_DEFAULT string 	= "2fb88.v1!" 									// current, v1 (default+blowfish) ; encrypt + decrypt ; Blowfish 56 (448) + TwoFish 32 (256) = 88 (704)

	SIGNATURE_3FISH_1K_V1_DEFAULT string  	= "3f1kD.v1!" 									// current, v1 1024 (default)  ; encrypt + decrypt
	SIGNATURE_3FISH_1K_V1_ARGON2ID string 	= "3f1kA.v1!" 									// current, v1 1024 (argon2id) ; encrypt + decrypt

	SIGNATURE_3FISH_1K_V1_2FBF_D string  	= "3ffb2kD.v1!" 								// current, v1 1024 (default+twofish/256+blowfish/448)  ; encrypt + decrypt
	SIGNATURE_3FISH_1K_V1_2FBF_A string 	= "3ffb2kA.v1!" 								// current, v1 1024 (argon2id+twofish/256+blowfish/448) ; encrypt + decrypt

	SALT_PREFIX string 						= "Smart Framework" 							// fixed salt prefix
	SALT_SEPARATOR string 					= "#" 											// fixed salt separator
	SALT_SUFFIX string 						= "スマート フレームワーク" 						// fixed salt suffix

	DERIVE_MIN_KLEN uint16 					=    3 											// Key Derive Min Length
	DERIVE_MAX_KLEN uint16 					= 4096 											// Key Derive Min Length
	DERIVE_PREKEY_LEN uint16 				=   80 											// Key Derive Pre-Key Length
	DERIVE_CENTITER_EK uint16 				=   87 											// Key Derive EK Iterations
	DERIVE_CENTITER_EV uint16 				=   78 											// Key Derive EV Iterations
	DERIVE_CENTITER_PW uint16 				=   77 											// Key Derive PW Iterations

	PASSWORD_PLAIN_MIN_LENGTH uint8 		=    7 											// Password Plain Min Lentgth
	PASSWORD_PLAIN_MAX_LENGTH uint8 		=   55 											// Password Plain Max Lentgth
	PASSWORD_HASH_LENGTH uint8 				=  128 											// fixed length ; {{{SYNC-AUTHADM-PASS-LENGTH}}} ; if lower then padd to right with * ; {{{SYNC-AUTHADM-PASS-PADD}}}
	PASSWORD_PREFIX_VERSION string 			= "$fPv3.7!" 									// {{{SYNC-AUTHADM-PASS-PREFIX}}}
	PASSWORD_PREFIX_A2ID_VERSION string 	= "a2idP37!" 									// go lang only (no PHP), curent v3, argon2id password ; must be the same length as PASSWORD_PREFIX_VERSION
)

var (
	ini_SMART_FRAMEWORK_SECURITY_KEY string = "Private-Key#0987654321" // set via CryptoSetSecurityKey
)

//-----


func CryptoSetSecurityKey(key string) bool {
	//--
	key = StrTrimWhitespaces(key)
	var kLen int = len(key)
	if((kLen < 16) || (kLen > 255)) {
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo Security Key must be between 16 and 255 caracters long ...")
		return false
	} //end if
	//--
	ini_SMART_FRAMEWORK_SECURITY_KEY = key
	//--
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo Security Key was Set (size is `" + ConvertIntToStr(len(ini_SMART_FRAMEWORK_SECURITY_KEY)) + "` bytes): Success")
	//--
	return true
	//--
} //END FUNCTION


func CryptoGetSecurityKey() (string, error) {
	//--
	var key string = StrTrimWhitespaces(ini_SMART_FRAMEWORK_SECURITY_KEY)
	//--
	var kLen int = len(key)
	if((kLen < 16) || (kLen > 255)) {
		return "", NewError("SmartGo Security Key must be between 16 and 255 caracters long")
	} //end if
	//--
	return key, nil
	//--
} //END FUNCTION


//-----


func byteRot13(b byte) byte { // https://go.googlesource.com/tour/+/release-branch.go1.2/solutions/rot13.go
	//--
	var a, z byte
	//--
	switch {
		case 'a' <= b && b <= 'z':
			a, z = 'a', 'z'
		case 'A' <= b && b <= 'Z':
			a, z = 'A', 'Z'
		default:
			return b
	} //end switch
	//--
	return (b - a + 13) % (z - a + 1) + a
	//--
} //END FUNCTION


func DataRot13(s string) string {
	//--
	if(s == "") {
		return s
	} //end if
	//--
	var b []byte = []byte(s)
	var r []byte = nil
	for i := 0; i < len(b); i++ {
		r = append(r, byteRot13(b[i]))
	} //end for
	//--
	return string(r)
	//--
} //END FUNCTION


func DataRRot13(s string) string {
	//--
	if(s == "") {
		return s
	} //end if
	//--
	return StrRev(DataRot13(s))
	//--
} //END FUNCTION


//-----


func HashHmac(algo string, key string, str string, b64 bool) (string, error) {
	//--
	algo = StrToLower(StrTrimWhitespaces(algo))
	//--
	var ok bool = false
	var sum string = ""
	//--
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


func Sh3a512B64(str string) string {
	//--
	hash := sha3.New512()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


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


func Sh3a384B64(str string) string {
	//--
	hash := sha3.New384()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


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


func Sh3a256B64(str string) string {
	//--
	hash := sha3.New256()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


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


func Sh3a224B64(str string) string {
	//--
	hash := sha3.New224()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


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


func Sha512B64(str string) string {
	//--
	hash := sha512.New()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


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

//-#
// SHA384 is roughly 50% faster than SHA-256 on 64-bit machines
// SHA384 has resistances to length extension attack but SHA512 doesn't have
// SHA384 128-bit resistance against the length extension attacks is because the attacker needs to guess the 128-bit to perform the attack, due to the truncation
//-#

func Sha384B64(str string) string {
	//--
	hash := sha512.New384()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


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


func Sha256B64(str string) string {
	//--
	hash := sha256.New()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


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


func Sha224B64(str string) string {
	//--
	hash := sha256.New224()
	//--
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func Sha1(str string) string {
	//--
	hash := sha1.New()
	hash.Write([]byte(str))
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha1B64(str string) string {
	//--
	hash := sha1.New()
	hash.Write([]byte(str))
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func Md5(str string) string {
	//--
	hash := md5.New()
	io.WriteString(hash, str)
	//--
//	return StrToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return StrToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Md5B64(str string) string {
	//--
	hash := md5.New()
	io.WriteString(hash, str)
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


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


// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) { // https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
	//--
	b := make([]byte, n)
	//--
	_, err := cryptorand.Read(b) // Note that err == nil only if we read len(b) bytes.
	if(err != nil) {
		return nil, err
	} //end if
	//--
	return b, nil
	//--
} //END FUNCTION


// GenerateRandomString returns a securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(n int) (string, error) { // https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
	//--
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	//--
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(letters))))
		if(err != nil) {
			return "", err
		} //end if
		ret[i] = letters[num.Int64()]
	} //end for
	//--
	return string(ret), nil
	//--
} //END FUNCTION


//-----


func SafeChecksumHashSmart(plainTextData string, customSalt string) string { // {{{SYNC-HASH-SAFE-CHECKSUM}}} [PHP]
	//-- r.20231204
	// Create a safe checksum of data
	// It will append the salt to the end of data to avoid the length extension attack # https://en.wikipedia.org/wiki/Length_extension_attack
	// Protected by SHA3-384 that has 128-bit resistance against the length extension attacks since the attacker needs to guess the 128-bit to perform the attack, due to the truncation
	// Now includes also a Poly1305 custom derivation ... adds 10x more resistence against length extension attacks ; increases exponential chances for rainbow attacks
	//--
	// this have to be extremely fast, it is a checksum not a 2-way encryption or a password, thus not using PBKDF2 derivation
	// more, it is secured against length attacks with a combination of SHA3-384 / SHA384 and a core of SHA3-512 as derivations ; double prefixed with high complexity strings: B64 prefix 88 chars ; B92 suffix, variable
	// time execution ~ 0.07s .. 0.08s
	//--
	defer PanicHandler() // for: b64Dec ; Hex2Bin
	//--
	customSalt = StrTrimWhitespaces(customSalt)
	if(customSalt == "") {
		customSalt = SALT_PREFIX + " " + SALT_SEPARATOR + " " + SALT_SUFFIX // dissalow empty salt, fallback to have at least something
		appNs, errAppNs := AppGetNamespace()
		if(errAppNs != nil) {
			log.Println("[WARNING]", CurrentFunctionName(), "App Namespace value Error:", errAppNs)
			return ""
		} //end if
		customSalt += " " + appNs
		secKey, errSecKey := CryptoGetSecurityKey()
		if(errSecKey != nil) {
			log.Println("[WARNING]", CurrentFunctionName(), "Security Key value Error:", errSecKey)
			return ""
		} //end if
		customSalt += " " + secKey
	} //end if
	//--
	var antiAtkLen string = Sha384(plainTextData + NULL_BYTE + customSalt) // Hex
	var antiAtkB64Len string = Sha384B64(plainTextData + NULL_BYTE + customSalt) // B64
	//--
	var cSalt string = Crc32bB36(antiAtkLen) // B36
	//--
	oSalt, errOSalt := HashHmac("SHA3-384", customSalt, NULL_BYTE + plainTextData + NULL_BYTE + antiAtkLen, false) // Hex
	if(errOSalt != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Hmac Checksum Failed:", errOSalt)
		return ""
	} //end if
	var pSalt string = DataRRot13(Base64sEncode(Hex2Bin(oSalt))) // B64s
	var rSalt string = Sh3a256(cSalt + NULL_BYTE + Sh3a224B64(pSalt + NULL_BYTE + antiAtkB64Len) + NULL_BYTE + Sha512B64(plainTextData) + NULL_BYTE + Md5B64(plainTextData) + NULL_BYTE + Sha1B64(plainTextData) + NULL_BYTE + Sha224B64(plainTextData) + NULL_BYTE + Sha256B64(plainTextData) + NULL_BYTE + Sha384B64(plainTextData) + NULL_BYTE + StrRev(antiAtkLen)) // Hex
	//--
	var tSalt string = BaseEncode([]byte(Hex2Bin(antiAtkLen)), "b32") // B32
	var vSalt string = BaseEncode([]byte(Hex2Bin(rSalt)), "b58") // B58
	var wSalt string = BaseEncode([]byte(Hex2Bin(oSalt + antiAtkLen)), "b85") // B85
	var xSalt string = BaseEncode([]byte(Hex2Bin(StrRev(oSalt) + antiAtkLen)), "b92") // B92
	var ySalt string = Sh3a512B64(customSalt + NULL_BYTE + plainTextData + NULL_BYTE + tSalt + NULL_BYTE + xSalt) // B64 of B92
	var polyKey string = StrRev(StrSubstr(xSalt, 17, 17+32)) // B64 (part)
	var polyData string = customSalt + NULL_BYTE + plainTextData + NULL_BYTE + wSalt // ascii
	zSalt, errZSalt := Poly1305(polyKey, polyData, true) // B64
	if(errZSalt != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Poly Checksum Failed:", errOSalt)
		return ""
	} //end if
	//--
	var b64CkSum string = Sh3a384B64(ySalt + VERTICAL_TAB + plainTextData + HORIZONTAL_TAB + vSalt + LINE_FEED + customSalt + CARRIAGE_RETURN + xSalt + NULL_BYTE + zSalt) // SHA3-384 B64 of B64 derived salt (88 characters) + data + B92 derived salt (variable length ~ 72 characters)
	//--
	return DataRRot13(BaseEncode([]byte(Base64Decode(b64CkSum)), "b62")) // B62
	//--
} //END FUNCTION


//-----


func SafePassHashSmart(plainPass string, theSalt string, useArgon2id bool) string { // {{{SYNC-HASH-PASSWORD}}} [PHP]
	//-- r.20231204 + Argon2Id
	defer PanicHandler() // for: Hex2Bin ; Argon2Id
	//--
	// V2 was a bit unsecure..., was deprecated a long time, now is no more supported !
	// V3 is the current version: 20231028, using PBKDF2 + derivations, SHA3-512 and SHA3-384
	//--
	// the password salt must not be too complex related to the password itself # http://stackoverflow.com/questions/5482437/md5-hashing-using-password-as-salt
	// an extraordinary good salt + a weak password may increase the risk of colissions
	// just sensible salt + strong password = safer
	// to achieve this, the salt is derived, to make it safe and even more unpredictable
	// for passwords the best is to pre-pend the salt: http://stackoverflow.com/questions/4171859/password-salts-prepending-vs-appending
	// for checksuming is better to append the salt to avoid the length extension attack # https://en.wikipedia.org/wiki/Length_extension_attack
	// ex: azA-Z09 pass, prepend needs 26^6 permutations while append 26^10, so append adds more complexity
	//--
	if(StrTrimWhitespaces(plainPass) == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Password is Empty !")
		return ""
	} //end if
	if(StrTrimWhitespaces(theSalt) == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Salt is Empty !")
		return ""
	} //end if
	//--
	if(
		(StrUnicodeLen(plainPass) < int(PASSWORD_PLAIN_MIN_LENGTH)) ||
		(StrUnicodeLen(plainPass) > int(PASSWORD_PLAIN_MAX_LENGTH))) { // {{{SYNC-PASS-HASH-SHA512-PLUS-SALT-SAFE}}} ; sync with auth validate password: max pass allowed length is 55 !
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Password is too long or too short !")
		return ""
	} //end if
	//--
	if(
		(StrLen(theSalt) < int(DERIVE_MIN_KLEN)) ||
		(StrLen(theSalt) > int(DERIVE_MAX_KLEN))) { // {{{SYNC-CRYPTO-KEY-MAX}}} divided by 2 as it is composed of both
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Salt is too long or too short !")
		return ""
	} //end if
	//--
	key, errKey := Pbkdf2PreDerivedKey(plainPass + NULL_BYTE + theSalt)
	key = StrTrimWhitespaces(key)
	if(errKey != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Pre-Derived Key Error: " + errKey.Error())
		return ""
	} else if(len(key) != int(DERIVE_PREKEY_LEN)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Pre-Derived Key Length is Invalid: " + ConvertIntToStr(len(key)))
		return ""
	} //end if else
	//--
	pbkdf2Salt, errSalt := Pbkdf2PreDerivedKey(theSalt + NULL_BYTE + theSalt)
	pbkdf2Salt = StrTrimWhitespaces(pbkdf2Salt)
	if(errSalt != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Pre-Derived Salt Error: " + errSalt.Error())
		return ""
	} else if(len(pbkdf2Salt) != int(DERIVE_PREKEY_LEN)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Pre-Derived Salt Length is Invalid: " + ConvertIntToStr(len(pbkdf2Salt)))
		return ""
	} //end if else
	//--
	const reqLen uint16 = 34 // be sure it is an even number ; must fit max len for B92 + Padding
	var sSalt string = ""
	var errSSalt error = nil
	if(useArgon2id == true) {
		sSalt = string(argon2.IDKey([]byte(key), []byte(pbkdf2Salt + VERTICAL_TAB + DataRot13(BaseEncode([]byte(pbkdf2Salt), "b32"))), uint32(math.Floor((float64(DERIVE_CENTITER_PW) * 2.8) - 2)), 128*1024, 1, uint32(reqLen))) // Argon2id resources: 215 cycles, 128MB memory, 1 thread, 34 bytes = 272 bits
		sSalt = StrSubstr(StrPad2LenRight(BaseEncode([]byte(sSalt), "b92"), "'", int(reqLen)), 0, int(reqLen))
	} else {
		sSalt, errSSalt = Pbkdf2DerivedKey("sha3-384", key, pbkdf2Salt, reqLen, DERIVE_CENTITER_PW, true) // B92
	} //end if else
	if(errSSalt != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Error: " + errSSalt.Error())
		return ""
	} else if(len(sSalt) != int(reqLen)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Length is Invalid: " + ConvertIntToStr(len(sSalt)))
		return ""
	} //end if else
	//--
	fSalt := StrSubstr(StrPad2LenLeft(sSalt, "'", 22), 0, 22) // fixed length sale: 22 chars (from ~ 21..22), with a more wider character set: B92
	//--
	chksPass := Crc32bB36(plainPass) // 7 chars
	pddPass := StrPad2LenRight(plainPass, VERTICAL_TAB, int(PASSWORD_PLAIN_MAX_LENGTH)) // fixed length: 55
	chksPPass := Crc32bB36(pddPass) // 7 chars
	hashData := fSalt + LINE_FEED + pddPass + CARRIAGE_RETURN + HORIZONTAL_TAB + chksPass // MUST BE FIXED LEN ! It is 87 a PRIME Number ! To avoid colissions ; SHA3-512 collisions safe max string is 256 bit (32 bytes only) !!!
	//--
	hashHexPass := Sh3a512(hashData) // hex, 128
	hashBinPass := Hex2Bin(hashHexPass)
	if(hashBinPass == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Hash Hex is Invalid")
		return ""
	} //end if
	hashB92Pass := BaseEncode([]byte(hashBinPass), "b92")
	hashPass := StrPad2LenRight(hashB92Pass, "'", 80) // 79..80 chars ; fixed length: 80
	//--
	antiAtkLen := Sh3a224(fSalt + NULL_BYTE + plainPass + NULL_BYTE + chksPPass)
	antiAtkLen = Hex2Bin(antiAtkLen)
	if(antiAtkLen == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived antiAtkLen Hash Hex is Invalid")
		return ""
	} //end if
	antiAtkLen = StrPad2LenRight(BaseEncode([]byte(antiAtkLen), "b92"), "'", 36) // 35..36 chars ; fixed length: 36
	//--
	var hash string = ""
	if(useArgon2id == true) {
		hash += PASSWORD_PREFIX_A2ID_VERSION
	} else {
		hash += PASSWORD_PREFIX_VERSION
	} //end if else
	hash += "'" + hashPass + "'" + antiAtkLen
	hash = StrPad2LenRight(hash, "'", 127)
	hash = StrSubstr(hash + "!", 0, 128)
	//--
	if(
		(StrTrimWhitespaces(hash) == "") ||
		(StrTrimWhitespaces(hash) != hash) ||
		(len(hash) != int(PASSWORD_HASH_LENGTH))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Internal Error: Password Hash :: Length must be " + ConvertUInt8ToStr(PASSWORD_HASH_LENGTH) + " bytes !")
		return ""
	} //end if
	//--
	return hash
	//--
} //END FUNCTION


//-----


func Pbkdf2PreDerivedKey(key string) (string, error) {
	//-- r.20231128
	defer PanicHandler() // for: Hex2Bin
	//--
	key = StrTrimWhitespaces(key)
	klen := len(key)
	//--
	if(klen < int(DERIVE_MIN_KLEN)) {
		return "", NewError(CurrentFunctionName() + " # The Key is too short: " + ConvertIntToStr(klen))
	} else if(klen > int(DERIVE_MAX_KLEN)) {
		return "", NewError(CurrentFunctionName() + " # The Key is too long: " + ConvertIntToStr(klen))
	} //end if else
	//--
	b64 := Sh3a384B64(key) // 64 chars fixed length, B64
	hex := Sh3a512(key + VERTICAL_TAB + Crc32bB36(key) + VERTICAL_TAB + DataRRot13(b64)) // 128 chars fixed length, HEX
	bin := Hex2Bin(hex)
	if(bin == "") {
		return "", NewError(CurrentFunctionName() + " # Hash Hex2Bin Error")
	} //end if
	b92 := BaseEncode([]byte(bin), "b92")
	//--
	preKey := StrTrimWhitespaces(DataRRot13(StrSubstr(StrPad2LenRight(b92, "'", int(DERIVE_PREKEY_LEN)), 0, int(DERIVE_PREKEY_LEN))))
	//--
	if(
		(StrTrimWhitespaces(preKey) == "") || // avoid being empty
		(StrTrim(preKey, "'") == "") || // avoid being all '
		(len(preKey) != int(DERIVE_PREKEY_LEN))) {
			return "", NewError(CurrentFunctionName() + " # The B92 PBKDF2 Pre-Derived Key is empty or does not match the expected size ; required size is: " + ConvertUInt16ToStr(DERIVE_PREKEY_LEN) + " bytes ; but the actual size is: " + ConvertIntToStr(len(preKey)) + " bytes")
	} //end if
	//--
	return preKey, nil
	//--
} //END FUNCTION


func Pbkdf2DerivedKey(algo string, key string, salt string, klen uint16, iterations uint16, b92 bool) (string, error) {
	//-- r.20231128
	defer PanicHandler() // for: pbkdf2.Key
	//--
	algo = StrToLower(algo)
	//--
	var err error
	//--
	var lk = len(key)
	var ls = len(salt)
	//--
	if(lk < int(DERIVE_MIN_KLEN)) {
		return "", NewError(CurrentFunctionName() + " # The Key is too short: " + ConvertIntToStr(lk))
	} else if(lk > int(DERIVE_MAX_KLEN)) {
		return "", NewError(CurrentFunctionName() + " # The Key is too long: " + ConvertIntToStr(lk))
	} //end if else
	if(ls < int(DERIVE_MIN_KLEN)) {
		return "", NewError(CurrentFunctionName() + " # The Salt is too short: " + ConvertIntToStr(ls))
	} else if(ls > int(DERIVE_MAX_KLEN)) {
		return "", NewError(CurrentFunctionName() + " # The Salt is too long: " + ConvertIntToStr(ls))
	} //end if else
	//--
	var keyLen int = int(klen) // below values may be adjusted, avoid out of range of uint16
	if(klen <= 0) {
		return "", NewError(CurrentFunctionName() + " # The length parameter is zero or negative")
	} //end if
	if(b92 == true) {
		keyLen = 2 * keyLen // ensure double size ; {{{SYNC-PBKDF2-HEX-TO-B92-LENGTH-ADJUST}}} ; should have enough length to ensure the same size because Base92 length shrinks after conversion from HEX (Base16)
	} //end if
	//--
	var iterCycles int = int(iterations) // below values may be adjusted, avoid out of range of uint16
	if(iterCycles < 1) {
		iterCycles = 1
		err = NewError(CurrentFunctionName() + " # The Number of iterations is too low: " + ConvertUInt16ToStr(iterations))
	} else if(iterCycles > 50000) { // in go let 5000 * 10 as in PHP
		iterCycles = 50000
		err = NewError(CurrentFunctionName() + " # The Number of iterations is too high: " + ConvertUInt16ToStr(iterations))
	} //end if
	//--
	var ok bool = false
	var dk string = ""
	//--
	switch(algo) { // {{{SYNC-HASHING-ALGOS-LIST}}}
		//--
		case "sha3-512":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha3.New512))
			break
		case "sha3-384":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha3.New384))
			break
		case "sha3-256":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha3.New256))
			break
		case "sha3-224":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha3.New224))
			break
		//--
		case "sha512":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha512.New))
			break
		case "sha384":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha512.New384))
			break
		case "sha256":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha256.New))
			break
		case "sha224":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha256.New224))
			break
		case "sha1":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, sha1.New))
			break
		case "md5":
			ok = true
			dk = string(pbkdf2.Key([]byte(key), []byte(salt), iterCycles, keyLen, md5.New))
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
	if(StrTrimWhitespaces(dk) == "") {
		return "", NewError(CurrentFunctionName() + " # Failed to create a PBKDF2 Derived Key for Algo: `" + algo + "`")
	} //end if
	//--
	if(len(dk) != keyLen) {
		return "", NewError(CurrentFunctionName() + " # The PBKDF2 Derived Key have an invalid length for Algo: `" + algo + "`")
	} //end if
	//--
	if(len(dk) < int(klen)) { // before converting to hex, is RAW, just ensure is enough size
		return "", NewError(CurrentFunctionName() + " # The PBKDF2 Derived Raw Key length is invalid for Algo: `" + algo + "` as: " + ConvertIntToStr(len(dk)))
	} //end if
	//--
	if(b92 == true) { // B92
		//--
		dk = StrSubstr(dk, 0, int(klen)) // extract required size
		dk = BaseEncode([]byte(dk), "b92")
		dk = StrSubstr(StrPad2LenRight(dk, "'", int(klen)), 0, int(klen)) // both: HEX or B92 must do this in Go
		if(len(dk) != int(klen)) {
			return "", NewError(CurrentFunctionName() + " # The PBKDF2 Derived Key length is invalid for Algo: `" + algo + "` as: " + ConvertIntToStr(len(dk)))
		} //end if
		//--
	} else { // Hex
		//--
		dk = StrToLower(Bin2Hex(dk))
		if(len(dk) < (int(klen) * 2)) { // after converting to hex, doubles the size
			return "", NewError(CurrentFunctionName() + " # The PBKDF2 Derived Hex Key length is invalid for Algo: `" + algo + "` as: " + ConvertIntToStr(len(dk)))
		} //end if
		//--
		dk = StrSubstr(dk, 0, int(klen)) // extract required size
		if(len(dk) != int(klen)) {
			return "", NewError(CurrentFunctionName() + " # The PBKDF2 Derived Hex Key length after fix is invalid for Algo: `" + algo + "` as: " + ConvertIntToStr(len(dk)))
		} //end if
		//--
	} //end if
	//--
	return dk, err
	//--
} //END FUNCTION


//-----


// IMPORTANT: the input will be padded ; expects B64 data !
func CipherEncryptCBC(algo string, str string, key string, iv string, tweak string) (string, error) {
	//-- safety
	defer PanicHandler() // for: hex2bin ; cipher encrypt may panic handler with wrong padded data
	//-- init
	var encrypted string = ""
	var bcipher cipher.Block = nil
	var errCipher error = nil
	//-- checks
	algo = StrToLower(StrTrimWhitespaces(algo))
	switch(algo) {
		case "threefish.1024":
			if(len(key) != 128) {
				return "", NewError("Key Size must be 128 bytes for ThreeFish (1024) / algo: " + algo)
			} //end if
			if(len(iv) != 128) {
				return "", NewError("iV Size must be 128 bytes for ThreeFish (1024) algo: " + algo)
			} //end if
			if(len(tweak) != 16) {
				return "", NewError("Tweak Size must be 16 bytes for ThreeFish (1024) algo: " + algo)
			} //end if
			bcipher, errCipher = threefish.New1024([]byte(key), []byte(tweak))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		case "threefish.512":
			if(len(key) != 64) {
				return "", NewError("Key Size must be 64 bytes for ThreeFish (512) / algo: " + algo)
			} //end if
			if(len(iv) != 64) {
				return "", NewError("iV Size must be 64 bytes for ThreeFish (512) algo: " + algo)
			} //end if
			if(len(tweak) != 16) {
				return "", NewError("Tweak Size must be 16 bytes for ThreeFish (512) algo: " + algo)
			} //end if
			bcipher, errCipher = threefish.New512([]byte(key), []byte(tweak))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		case "threefish.256":
			if(len(key) != 32) {
				return "", NewError("Key Size must be 32 bytes for ThreeFish (256) / algo: " + algo)
			} //end if
			if(len(iv) != 32) {
				return "", NewError("iV Size must be 32 bytes for ThreeFish (256) algo: " + algo)
			} //end if
			if(len(tweak) != 16) {
				return "", NewError("Tweak Size must be 16 bytes for ThreeFish (256) algo: " + algo)
			} //end if
			bcipher, errCipher = threefish.New512([]byte(key), []byte(tweak))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		case "twofish.256":
			if(len(key) != 32) {
				return "", NewError("Key Size must be 32 bytes for TwoFish (256) / algo: " + algo)
			} //end if
			if(len(iv) != 16) {
				return "", NewError("iV Size must be 16 bytes for TwoFish (256) / algo: " + algo)
			} //end if
			if(len(tweak) != 0) {
				return "", NewError("Tweak is not supported by TwoFish (256) / algo: " + algo)
			} //end if
			bcipher, errCipher = twofish.NewCipher([]byte(key))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		case "blowfish.448":
			if(len(key) != 56) {
				return "", NewError("Key Size must be 56 bytes for BlowFish (448) / algo: " + algo)
			} //end if
			if(len(iv) != 8) {
				return "", NewError("iV Size must be 8 bytes for BlowFish (448) / algo: " + algo)
			} //end if
			if(len(tweak) != 0) {
				return "", NewError("Tweak is not supported by BlowFish (448) / algo: " + algo)
			} //end if
			bcipher, errCipher = blowfish.NewCipher([]byte(key))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
		case "blowfish.384":
			if(len(key) != 48) {
				return "", NewError("Key Size must be 48 bytes for BlowFish (384) / algo: " + algo)
			} //end if
			if(len(iv) != 8) {
				return "", NewError("iV Size must be 8 bytes for BlowFish (384) / algo: " + algo)
			} //end if
			if(len(tweak) != 0) {
				return "", NewError("Tweak is not supported by BlowFish (384) / algo: " + algo)
			} //end if
			bcipher, errCipher = blowfish.NewCipher([]byte(key))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		default:
			return "", NewError("Invalid Cipher Algo: `" + algo + "`")
	} //end switch
	if(bcipher == nil) {
		return "", NewError("No Cipher Selected for Algo: `" + algo + "`")
	} //end if
	if(len(iv) != bcipher.BlockSize()) {
		return "", NewError("Invalid iV: Does not Match the Block Size")
	} //end if
	//-- check for empty data
	if(str == "") {
		return "", nil
	} //end if
	//-- fix: padding
	var slen int = len(str)
	var modulus int = slen % bcipher.BlockSize()
	if(modulus > 0) {
		var padlen int = bcipher.BlockSize() - modulus
		str = StrPad2LenRight(str, " ", slen + padlen) // pad with spaces
		slen = slen + padlen
	} //end if
	//-- encrypt
	ciphertext := make([]byte, bcipher.BlockSize()+slen) // make ciphertext big enough to store data
	ecbc := cipher.NewCBCEncrypter(bcipher, []byte(iv)) // create the encrypter: CBC
	ecbc.CryptBlocks(ciphertext[bcipher.BlockSize():], []byte(str)) // encrypt the blocks
	str = "" // no more needed
	encrypted = StrTrimWhitespaces(Bin2Hex(string(ciphertext))) // prepare output
	ciphertext = nil
	//-- clear first header block ; will use BlockSize*2 because is operating over HEX data ; there are BlockSize*2 trailing zeroes that represent the HEX of BlockSize null bytes ; remove them
	if(StrSubstr(encrypted, 0, bcipher.BlockSize()*2) != strings.Repeat("0", bcipher.BlockSize()*2)) { // {{{FIX-GOLANG-CIPHER-1ST-NULL-BLOCK-HEADER}}}
		return "", NewError("Invalid Hex Header")
	} //end if
	encrypted = StrTrimWhitespaces(StrSubstr(encrypted, bcipher.BlockSize()*2, 0)) // {{{FIX-GOLANG-CIPHER-1ST-NULL-BLOCK-HEADER}}}
	if(encrypted == "") { // must be some data after the first null header bytes
		return "", NewError("Empty Hex Body")
	} //end if
	//--
	return Hex2Bin(encrypted), nil // raw crypto data
	//--
} //END FUNCTION


// IMPORTANT: the output must be trimmed for the padding added when encrypted ; expects B64 data, so trim is OK !
func CipherDecryptCBC(algo string, str string, key string, iv string, tweak string) (string, error) {
	//-- safety
	defer PanicHandler() // for: hex2bin ; cipher decrypt may panic handler with malformed data
	//-- init
	var decrypted []byte = nil
	var bcipher cipher.Block = nil
	var errCipher error = nil
	//-- checks
	algo = StrToLower(StrTrimWhitespaces(algo))
	switch(algo) {
		case "threefish.1024":
			if(len(key) != 128) {
				return "", NewError("Key Size must be 128 bytes for ThreeFish (1024) / algo: " + algo)
			} //end if
			if(len(iv) != 128) {
				return "", NewError("iV Size must be 128 bytes for ThreeFish (1024) algo: " + algo)
			} //end if
			if(len(tweak) != 16) {
				return "", NewError("Tweak Size must be 16 bytes for ThreeFish (1024) algo: " + algo)
			} //end if
			bcipher, errCipher = threefish.New1024([]byte(key), []byte(tweak))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		case "threefish.512":
			if(len(key) != 64) {
				return "", NewError("Key Size must be 64 bytes for ThreeFish (512) / algo: " + algo)
			} //end if
			if(len(iv) != 64) {
				return "", NewError("iV Size must be 64 bytes for ThreeFish (512) algo: " + algo)
			} //end if
			if(len(tweak) != 16) {
				return "", NewError("Tweak Size must be 16 bytes for ThreeFish (512) algo: " + algo)
			} //end if
			bcipher, errCipher = threefish.New512([]byte(key), []byte(tweak))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		case "threefish.256":
			if(len(key) != 32) {
				return "", NewError("Key Size must be 32 bytes for ThreeFish (256) / algo: " + algo)
			} //end if
			if(len(iv) != 32) {
				return "", NewError("iV Size must be 32 bytes for ThreeFish (256) algo: " + algo)
			} //end if
			if(len(tweak) != 16) {
				return "", NewError("Tweak Size must be 16 bytes for ThreeFish (256) algo: " + algo)
			} //end if
			bcipher, errCipher = threefish.New512([]byte(key), []byte(tweak))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		case "twofish.256":
			if(len(key) != 32) {
				return "", NewError("Key Size must be 32 bytes for TwoFish (256) / algo: " + algo)
			} //end if
			if(len(iv) != 16) {
				return "", NewError("iV Size must be 16 bytes for TwoFish (256) / algo: " + algo)
			} //end if
			if(len(tweak) != 0) {
				return "", NewError("Tweak is not supported by TwoFish (256) / algo: " + algo)
			} //end if
			bcipher, errCipher = twofish.NewCipher([]byte(key))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		case "blowfish.448":
			if(len(key) != 56) {
				return "", NewError("Key Size must be 56 bytes for BlowFish (448) / algo: " + algo)
			} //end if
			if(len(iv) != 8) {
				return "", NewError("iV Size must be 8 bytes for BlowFish (448) / algo: " + algo)
			} //end if
			if(len(tweak) != 0) {
				return "", NewError("Tweak is not supported by BlowFish (448) / algo: " + algo)
			} //end if
			bcipher, errCipher = blowfish.NewCipher([]byte(key))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
		case "blowfish.384":
			if(len(key) != 48) {
				return "", NewError("Key Size must be 48 bytes for BlowFish (384) / algo: " + algo)
			} //end if
			if(len(iv) != 8) {
				return "", NewError("iV Size must be 8 bytes for BlowFish (384) / algo: " + algo)
			} //end if
			if(len(tweak) != 0) {
				return "", NewError("Tweak is not supported by BlowFish (384) / algo: " + algo)
			} //end if
			bcipher, errCipher = blowfish.NewCipher([]byte(key))
			if(errCipher != nil) {
				return "", errCipher
			} //end if
			break
		default:
			return "", NewError("Invalid Cipher Algo: `" + algo + "`")
	} //end switch
	if(bcipher == nil) {
		return "", NewError("No Cipher Selected for Algo: `" + algo + "`")
	} //end if
	if(len(iv) != bcipher.BlockSize()) {
		return "", NewError("Invalid iV: Does not Match the Block Size")
	} //end if
	//-- check for empty data
	if(str == "") {
		return "", nil
	} //end if
	//-- fix: restore header block ; use blocksize * 2 (is hex ...)
	str = Hex2Bin(strings.Repeat("0", bcipher.BlockSize()*2) + Bin2Hex(str)) // {{{FIX-GOLANG-CIPHER-1ST-NULL-BLOCK-HEADER}}}
	if(str == "") {
		return "", NewError("Hex Header Restore Failed")
	} //end if
	//-- decrypt
	et := []byte(str)
	str = ""
	decrypted = et[bcipher.BlockSize():]
	et = nil
	if(len(decrypted) % bcipher.BlockSize() != 0) { // check last slice of encrypted text, if it's not a modulus of cipher block size, it's a problem
		return "", NewError("Decrypted Data is not a multiple of cipher BlockSize: [" + ConvertIntToStr(bcipher.BlockSize()) + "]")
	} //end if
	dcbc := cipher.NewCBCDecrypter(bcipher, []byte(iv))
	dcbc.CryptBlocks(decrypted, decrypted)
	//--
	return string(decrypted), nil
	//--
} //END FUNCTION


//-----


func cryptoContainerUnpack(algo string, ver uint8, str string) (string, error) {
	//--
	defer PanicHandler() // for: b64Dec
	//--
	algo = StrToLower(StrTrimWhitespaces(algo))
	//--
	if((ver != 3) && (ver != 2) && (ver != 1)) {
		return "", NewError("Invalid Version: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	if(str == "") {
		return "", NewError("Empty Data Packet, v: " + ConvertUInt8ToStr(ver))
	} //end if
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return "", NewError("Invalid Data Packet, v: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	var separator string = ""
	if(algo == "threefish") {
		if(ver != 3) {
			return "", NewError("Invalid Threefish Version, v: " + ConvertUInt8ToStr(ver))
		} //end if
		separator = SEPARATOR_CRYPTO_CHECKSUM_V3
	} else if(algo == "twofish") {
		if(ver != 3) {
			return "", NewError("Invalid Twofish Version, v: " + ConvertUInt8ToStr(ver))
		} //end if
		separator = SEPARATOR_CRYPTO_CHECKSUM_V3
	} else if(algo == "blowfish") {
		if(ver == 3) {
			separator = SEPARATOR_CRYPTO_CHECKSUM_V3
		} else if(ver == 2) {
			separator = SEPARATOR_CRYPTO_CHECKSUM_V2
		} else if(ver == 1) {
			separator = SEPARATOR_CRYPTO_CHECKSUM_V1
		} else {
			return "", NewError("Invalid BlowFish Version, v: " + ConvertUInt8ToStr(ver))
		} //end if else
	} else {
		return "", NewError("Invalid Algo: `" + algo + "` ; Version, v: " + ConvertUInt8ToStr(ver))
	} //end if else
	if(separator == "") {
		return "", NewError("Empty Data Packet Checksum Separator, v: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	if(!StrContains(str, separator)) {
		return "", NewError("Invalid Data Packet, NO Checksum, v: " + ConvertUInt8ToStr(ver))
	} //end if
	darr := ExplodeWithLimit(separator, str, 3)
	if(len(darr) != 2) {
		return "", NewError("Invalid Data Packet Segments, v: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	str = "" // clear
	var dlen int = len(darr)
	if(dlen < 2) {
		return "", NewError("Invalid Data Packet, Checksum NOT Found, v: " + ConvertUInt8ToStr(ver))
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		return "", NewError("Invalid Data Packet, Checksum is Empty, v: " + ConvertUInt8ToStr(ver))
	} //end if
	if(darr[0] == "") {
		return "", NewError("Invalid Data Packet, Packed Data NOT Found, v: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	switch(algo) {
		case "blowfish": // v3, v2, v1
			if(ver == 1) { // v1
				if(Sha1(darr[0]) != darr[1]) {
					return "", NewError("Invalid Blowfish Data Packet (v1), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
				} //end if
			} else if(ver == 2) { // v2
				if(Sha256B64(darr[0]) != darr[1]) {
					return "", NewError("Invalid Blowfish Data Packet (v2), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
				} //end if
			} else if(ver == 3) { // v3
				if(BaseEncode([]byte(Base64Decode(Sh3a512B64(darr[0]))), "b62") != darr[1]) {
					return "", NewError("Invalid Blowfish Data Packet (v3), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
				} //end if
			} else {
				return "", NewError("Invalid Blowfish Data Packet (v" + ConvertUInt8ToStr(ver) + "), Checksum Check SKIP :: A checksum was found but don't know how to handle: `" + darr[1] + "`")
			} //end if else
			break
		case "twofish": // v3 only
			if(BaseEncode([]byte(Base64Decode(Sh3a512B64(darr[0]))), "b62") != darr[1]) {
				return "", NewError("Invalid Twofish Data Packet (v3), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
			} //end if
			break
		case "threefish": // v3 only
			if(BaseEncode([]byte(Base64Decode(Sh3a512B64(darr[0]))), "b62") != darr[1]) {
				return "", NewError("Invalid Threefish Data Packet (v3), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
			} //end if
			break
		default:
			return "", NewError("Invalid Data Packet, Algo: `" + algo + "` ; Version, v: " + ConvertUInt8ToStr(ver))
	} //end switch
	//--
	return Base64Decode(darr[0]), nil
	//--
} //END FUNCTION


//-----


func threefishSafeKey(plainTextKey string, useArgon2id bool) string { // {{{SYNC-CRYPTO-KEY-DERIVE}}}
	//-- r.20231203 + Argon2Id
	// B92 ; (128 bytes)
	//--
	defer PanicHandler() // for: Argon2Id
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if((key == "") || (len(key) < int(DERIVE_MIN_KLEN)) || (len(key) > int(DERIVE_MAX_KLEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty or Invalid !")
		return ""
	} //end if
	//--
	salt, errSalt := Pbkdf2PreDerivedKey(key)
	if((errSalt != nil) || (len(salt) != int(DERIVE_PREKEY_LEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Pre-Derived Key Salt is Invalid !")
		return ""
	} //end if
	//--
	const klen uint16 = 128
	var safeKey string = ""
	var errSafeKey error = nil
	if(useArgon2id == true) {
		safeKey = string(argon2.IDKey([]byte(plainTextKey), []byte(salt), uint32(DERIVE_CENTITER_EK), 96*1024, 1, uint32(klen))) // Argon2id resources: 87 cycles, 80MB memory, 1 thread, 128 bytes = 1024 bits
		safeKey = BaseEncode([]byte(safeKey), "b92") // b92
	} else {
		safeKey, errSafeKey = Pbkdf2DerivedKey("sha3-512", plainTextKey, salt, klen, DERIVE_CENTITER_EK, true) // b92
		if(errSafeKey != nil) {
			log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key is Empty !")
			return ""
		} //end if else
	} //end if else
	safeKey = StrTrimWhitespaces(StrSubstr(safeKey, 0, int(klen)))
	var kslen int = len(safeKey)
	if((errSafeKey != nil) || (kslen != int(klen)) || (kslen != 128)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Safe Key is invalid !")
		return ""
	} //end if
	//--
	return safeKey
	//--
} //END FUNCTION


func threefishSafeIv(plainTextKey string, useArgon2id bool) string { // {{{SYNC-CRYPTO-IV-DERIVE}}}
	//-- r.20231203 + Argon2Id
	// B85 ; (128 bytes)
	//--
	defer PanicHandler() // for: Argon2Id
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if((key == "") || (len(key) < int(DERIVE_MIN_KLEN)) || (len(key) > int(DERIVE_MAX_KLEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Iv is Empty or Invalid !")
		return ""
	} //end if
	//--
	salt, errSalt := Pbkdf2PreDerivedKey(DataRRot13(Base64sEncode(key)))
	if((errSalt != nil) || (len(salt) != int(DERIVE_PREKEY_LEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Pre-Derived Iv Salt is Invalid !")
		return ""
	} //end if
	//--
	const ivlen uint16 = 128
	var safeIv string = ""
	var errSafeIv error = nil
	if(useArgon2id == true) {
		safeIv = string(argon2.IDKey([]byte(plainTextKey), []byte(salt), uint32(DERIVE_CENTITER_EV), 64*1024, 1, uint32(ivlen))) // Argon2id resources: 78 cycles, 64MB memory, 1 thread, 128 bytes = 1024 bits
		safeIv = BaseEncode([]byte(safeIv), "b85") // b85
	} else {
		safeIv, errSafeIv = Pbkdf2DerivedKey("sha3-384", plainTextKey, salt, ivlen * 2, DERIVE_CENTITER_EV, false) // hex
		if(errSafeIv != nil) {
			log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Iv is Empty !")
			return ""
		} //end if else
		safeIv = Hex2Bin(safeIv)
		if(safeIv == "") {
			log.Println("[WARNING] " + CurrentFunctionName() + ":", "Post Derived Iv is Empty !")
			return ""
		} //end if
		safeIv = BaseEncode([]byte(safeIv), "b85") // b85
	} //end if else
	safeIv = StrTrimWhitespaces(StrSubstr(safeIv, 0, int(ivlen)))
	var ivslen int = len(safeIv)
	if((errSafeIv != nil) || (ivslen != int(ivlen)) || (ivslen != 128)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Safe Iv is invalid !")
		return ""
	} //end if
	//--
	return safeIv
	//--
} //END FUNCTION


func threefishSafeTweak(plainTextKey string) string {
	//-- r.20231203
	// B92 ; (16 bytes)
	//--
	defer PanicHandler() // for: Hex2Bin
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if((key == "") || (len(key) < int(DERIVE_MIN_KLEN)) || (len(key) > int(DERIVE_MAX_KLEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Tweak is Empty or Invalid !")
		return ""
	} //end if
	//--
	const twklen uint16 = 16
	//--
	var ckSumCrc32bKeyHex string = Crc32b(key)
	var ckSumCrc32bDKeyHex string = Crc32b(Base64Encode(key))
	var ckSumCrc32bKeyRaw string = Hex2Bin(ckSumCrc32bKeyHex)
	var ckSumCrc32bDKeyRaw string = Hex2Bin(ckSumCrc32bDKeyHex)
	var ckSumCrc32bKeyEnc string = BaseEncode([]byte(ckSumCrc32bKeyRaw + ckSumCrc32bDKeyRaw), "b62")
	var ckSumCrc32bDKeyEnc string = BaseEncode([]byte(ckSumCrc32bDKeyRaw + ckSumCrc32bKeyRaw), "b58")
	var ckSumHash string = Sh3a512B64(key + NULL_BYTE + SALT_PREFIX + " " + SALT_SEPARATOR + " " + SALT_SUFFIX + NULL_BYTE + ckSumCrc32bKeyEnc + NULL_BYTE + ckSumCrc32bDKeyEnc)
	//--
	poly1305Sum, polyErr := Poly1305(Md5(ckSumHash), key, true)
	if((StrTrimWhitespaces(poly1305Sum) == "") || (len(poly1305Sum) < 20) || (polyErr != nil)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Post Derived Tweak (step1) is Empty !")
		return ""
	} //end if
	poly1305Sum = Base64Decode(poly1305Sum) // do not trim, is binary data
	if(poly1305Sum == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Post Derived Tweak (step2) is Empty !")
		return ""
	} //end if
	//--
	var b92Tweak = StrTrimWhitespaces(BaseEncode([]byte(poly1305Sum), "b92"))
	if((b92Tweak == "") || (len(b92Tweak) < 15)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Post Derived Tweak (step3) is Empty !")
		return ""
	} //end if
	//--
	var safeTweak string = StrPad2LenRight(StrSubstr(b92Tweak, 0, 16), "`", 16) // 128/8 ; pad with ` as it is only base 92
	var twkslen int = len(safeTweak)
	if((twkslen != int(twklen)) || (twkslen != 16)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Safe Tweak is invalid !")
		return ""
	} //end if

	//--
	return safeTweak
	//--
} //END FUNCTION


func ThreefishEncryptCBC(str string, key string, useArgon2id bool) string {
	//-- safety
	defer PanicHandler() // for: encrypt
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	var oStr string = str
	str = Base64Encode(str)
	cksum := BaseEncode([]byte(Base64Decode(Sh3a512B64(str))), "b62")
	str = str + SEPARATOR_CRYPTO_CHECKSUM_V3 + cksum
	//log.Println("[DEBUG] " + CurrentFunctionName() + ":", str)
	//-- signature
	var theSignature string = ""
	if(useArgon2id == true) {
		theSignature = SIGNATURE_3FISH_1K_V1_ARGON2ID
	} else {
		theSignature = SIGNATURE_3FISH_1K_V1_DEFAULT
	} //end if else
	//-- derived key, iv, tweak
	var dKey string = threefishSafeKey(key, useArgon2id) // b92, (128 bytes)
	var iv string = threefishSafeIv(key, useArgon2id) // b92 (128 bytes)
	var tweak string = threefishSafeTweak(key) // b85 (16 bytes)
	//-- encrypt: CBC
	encStr, encErr := CipherEncryptCBC("ThreeFish.1024", str, dKey, iv, tweak)
	str = ""
	if(encErr != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Encrypt Error:", encErr)
		return ""
	} //end if
	encStr = Base64sEncode(encStr) // b64s
	//--
	var ckSum string = BaseEncode([]byte(Hex2Bin(Sh3a224(encStr + NULL_BYTE + oStr))), "b62")
	oStr = ""
	//--
	return theSignature + DataRRot13(encStr + ";" + ckSum) // signature
	//--
} //END FUNCTION


func ThreefishDecryptCBC(str string, key string, useArgon2id bool) string {
	//-- safety
	defer PanicHandler() // for: b64Dec
	//-- check
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//-- signature
	var theSignature string = ""
	if(useArgon2id == true) {
		theSignature = SIGNATURE_3FISH_1K_V1_ARGON2ID
	} else {
		theSignature = SIGNATURE_3FISH_1K_V1_DEFAULT
	} //end if else
	if(StrTrimWhitespaces(theSignature) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Empty Signature provided")
		return ""
	} //end if
	if(!StrContains(str, theSignature)) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Signature was not found")
		return ""
	} //end if
	//-- extract data after signature
	sgnArr := ExplodeWithLimit("!", str, 3)
	if(len(sgnArr) != 2) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Signature Separator")
		return ""
	} //end if
	str = StrTrimWhitespaces(DataRRot13(sgnArr[1]))
	sgnArr = nil
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": B64s Part not found")
		return ""
	} //end if
	//-- separe data from checksum + decode
	cksArr := ExplodeWithLimit(";", str, 3)
	if(len(cksArr) != 2) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Checksum Separator")
		return ""
	} //end if
	str = StrTrimWhitespaces(cksArr[0])
	cksum := StrTrimWhitespaces(cksArr[1])
	cksArr = nil
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Data Part not found")
		return ""
	} //end if
	if(cksum == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Checksum Part not found")
		return ""
	} //end if
	var pak string = str
	str = Base64sDecode(str)
	if(str == "") { // do not trim, it is raw crypto data
		log.Println("[NOTICE] " + CurrentFunctionName() + ": B64s Decode Failed")
		return ""
	} //end if
	//-- derived key, iv, tweak
	var dKey string = threefishSafeKey(key, useArgon2id) // b92, (128 bytes)
	var iv string = threefishSafeIv(key, useArgon2id) // b92 (128 bytes)
	var tweak string = threefishSafeTweak(key) // b85 (16 bytes)
	//-- decrypt: CBC
	var decrypted string = ""
	var errDecrypted error = nil
	decrypted, errDecrypted = CipherDecryptCBC("ThreeFish.1024", str, dKey, iv, tweak)
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Decrypt Failed:", errDecrypted)
		return ""
	} //end if
	//-- unpack
	decrypted, errDecrypted = cryptoContainerUnpack("ThreeFish", 3, decrypted)
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Unpack Failed:", errDecrypted)
		return ""
	} //end if
	//-- check package checksum
	if(StrTrimWhitespaces(cksum) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Data/Package Checksum is N/A, Cannot Verify")
		return ""
	} //end if
	if(StrTrimWhitespaces(pak) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Data/Package is N/A, Cannot Verify")
		return ""
	} //end if
	if(cksum != BaseEncode([]byte(Hex2Bin(Sh3a224(pak + NULL_BYTE + decrypted))), "b62")) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Data Checksum Failed")
		return ""
	} //end if
	//--
	return decrypted
	//--
} //END FUNCTION


//-----


func ThreefishEncryptTwofishBlowfishCBC(str string, key string, useArgon2id bool) string {
	//-- safety
	defer PanicHandler()
	//-- check
	if(str == "") {
		return ""
	} //end if
	//--
	sign3F := SIGNATURE_3FISH_1K_V1_DEFAULT
	sign3xF := SIGNATURE_3FISH_1K_V1_2FBF_D
	if(useArgon2id) {
		sign3F = SIGNATURE_3FISH_1K_V1_ARGON2ID
		sign3xF = SIGNATURE_3FISH_1K_V1_2FBF_A
	} //end if
	//--
	str = StrTrimWhitespaces(TwofishEncryptBlowfishCBC(str, key))
	if((str == "") || (!StrStartsWith(str, SIGNATURE_2FISH_V1_BF_DEFAULT)) || (len(str) <= len(SIGNATURE_2FISH_V1_BF_DEFAULT))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to BF Pre-Encrypt Data")
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(StrSubstr(str, len(SIGNATURE_2FISH_V1_BF_DEFAULT), -1))
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to Separe BF Encrypted Data")
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(ThreefishEncryptCBC(DataRRot13(str), key, useArgon2id))
	if((str == "") || (!StrStartsWith(str, sign3F)) || (len(str) <= len(sign3F))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to TF Encrypt Data")
		return ""
	} //end if
	str = StrTrimWhitespaces(StrSubstr(str, len(sign3F), -1))
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to Separe TF Encrypted Data")
		return ""
	} //end if
	//--
	return sign3xF + str
	//--
} //END FUNCTION


func ThreefishDecryptTwofishBlowfishCBC(str string, key string, useArgon2id bool) string {
	//-- safety
	defer PanicHandler()
	//-- check
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	sign3F := SIGNATURE_3FISH_1K_V1_DEFAULT
	sign3xF := SIGNATURE_3FISH_1K_V1_2FBF_D
	if(useArgon2id) {
		sign3F = SIGNATURE_3FISH_1K_V1_ARGON2ID
		sign3xF = SIGNATURE_3FISH_1K_V1_2FBF_A
	} //end if
	//--
	if((!StrStartsWith(str, sign3xF)) || (len(str) <= len(sign3xF))) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Wrong Signature provided")
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(StrSubstr(str, len(sign3xF), -1))
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Empty Data After Signature")
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(ThreefishDecryptCBC(sign3F + str, key, useArgon2id))
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Empty Data After TF Decrypt")
		return ""
	} //end if
	//--
	return TwofishDecryptBlowfishCBC(SIGNATURE_2FISH_V1_BF_DEFAULT + DataRRot13(str), key)
	//--
} //END FUNCTION


//-----


func twofishSafeKeyIv(plainTextKey string) (string, string) { // {{{SYNC-CRYPTO-KEY-DERIVE}}} [PHP] ; v3
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if((key == "") || (len(key) < int(DERIVE_MIN_KLEN)) || (len(key) > int(DERIVE_MAX_KLEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty or Invalid !")
		return "", ""
	} //end if
	//--
	var kSz uint16 = 32
	var iSz uint16 = 16
	//--
	var nkSz uint16 = kSz * 2 // ensure double size
	var niSz uint16 = iSz * 2 // ensure double size
	//--
	pbkdf2PK, errPK := Pbkdf2PreDerivedKey(key)
	if(errPK != nil) {
		log.Println("[WARNING] Pre-Derived Key Error:", errPK)
		return "", ""
	} //end if
	pbkdf2PK = StrTrimWhitespaces(pbkdf2PK)
	if((pbkdf2PK == "") || (len(pbkdf2PK) != int(DERIVE_PREKEY_LEN))) {
		log.Println("[WARNING] Invalid Pre-Derived Key Length:", len(pbkdf2PK))
		return "", ""
	} //end if
	//--
	pbkdf2PV, errPV := Pbkdf2PreDerivedKey(DataRRot13(Base64sEncode(key)) + NULL_BYTE + pbkdf2PK)
	if(errPV != nil) {
		log.Println("[WARNING] Pre-Derived Iv Error:", errPV)
		return "", ""
	} //end if
	pbkdf2PV = StrTrimWhitespaces(pbkdf2PV)
	if((pbkdf2PV == "") || (len(pbkdf2PV) != int(DERIVE_PREKEY_LEN))) {
		log.Println("[WARNING] Invalid Pre-Derived Iv Length:", len(pbkdf2PV))
		return "", ""
	} //end if
	//--
	var sK string = "[" + NULL_BYTE + pbkdf2PV + VERTICAL_TAB + Crc32bB36(VERTICAL_TAB + key + NULL_BYTE) + NULL_BYTE + "]" // s + B36
	pbkdf2K, errK := Pbkdf2DerivedKey("sha3-512", pbkdf2PK, sK, nkSz, DERIVE_CENTITER_EK, false) // hex
	if(errK != nil) {
		log.Println("[WARNING] Derived Key Error:", errK)
		return "", ""
	} //end if
	pbkdf2K = StrTrimWhitespaces(pbkdf2K) // hex
	if((pbkdf2K == "") || (len(pbkdf2K) != int(nkSz))) {
		log.Println("[WARNING] Invalid Derived Key Hex Length:", len(pbkdf2K))
		return "", ""
	} //end if
	pbkdf2K = Hex2Bin(pbkdf2K) // bin
	if((pbkdf2K == "") || (len(pbkdf2K) != int(kSz))) {
		log.Println("[WARNING] Invalid Derived Key Length:", len(pbkdf2K))
		return "", ""
	} //end if
	pbkdf2K = StrTrimWhitespaces(DataRRot13(StrSubstr(BaseEncode([]byte(pbkdf2K), "b92"), 0, int(kSz)))) // b92
	//--
	var sV string = "(" + NULL_BYTE + pbkdf2PK + VERTICAL_TAB + Crc32b(VERTICAL_TAB + key + NULL_BYTE) + NULL_BYTE + ")" // s + Hex
	pbkdf2V, errV := Pbkdf2DerivedKey("sha3-256", pbkdf2PV, sV, niSz, DERIVE_CENTITER_EV, false) // hex
	if(errV != nil) {
		log.Println("[WARNING] Derived Key Error:", errV)
		return "", ""
	} //end if
	pbkdf2V = StrTrimWhitespaces(pbkdf2V) // hex
	if((pbkdf2V == "") || (len(pbkdf2V) != int(niSz))) {
		log.Println("[WARNING] Invalid Derived Key Hex Length:", len(pbkdf2V))
		return "", ""
	} //end if
	pbkdf2V = Hex2Bin(pbkdf2V) // bin
	if((pbkdf2V == "") || (len(pbkdf2V) != int(iSz))) {
		log.Println("[WARNING] Invalid Derived Key Length:", len(pbkdf2V))
		return "", ""
	} //end if
	pbkdf2V = StrTrimWhitespaces(DataRRot13(StrSubstr(BaseEncode([]byte(pbkdf2V), "b85"), 0, int(iSz)))) // b85
	//--
	//log.Println("[DATA] " + CurrentFunctionName() + ":", "\n", pbkdf2PK, "\n", pbkdf2PV, "\n", pbkdf2K, "\n", pbkdf2V)
	return pbkdf2K, pbkdf2V
	//--
} //END FUNCTION


func TwofishEncryptCBC(str string, key string) string {
	//-- safety
	defer PanicHandler() // for: hex2bin ; encrypt
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	var oStr string = str
	str = Base64Encode(str)
	cksum := BaseEncode([]byte(Base64Decode(Sh3a512B64(str))), "b62")
	str = str + SEPARATOR_CRYPTO_CHECKSUM_V3 + cksum
	//log.Println("[DEBUG] " + CurrentFunctionName() + ":", str)
	//-- signature
	var theSignature string = SIGNATURE_2FISH_V1_DEFAULT
	//-- derived key, iv
	dKey, iv := twofishSafeKeyIv(key) // key b92, (32 bytes) ; iv b85 + b92 (16 bytes)
	//-- encrypt: CBC
	encStr, encErr := CipherEncryptCBC("TwoFish.256", str, dKey, iv, "")
	str = ""
	if(encErr != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Encrypt Error:", encErr)
		return ""
	} //end if
	encStr = Base64sEncode(encStr) // b64s
	//--
	var ckSum string = BaseEncode([]byte(Hex2Bin(Sh3a224(encStr + NULL_BYTE + oStr))), "b62")
	oStr = ""
	//--
	return theSignature + DataRRot13(encStr + ";" + ckSum) // signature
	//--
} //END FUNCTION


func TwofishDecryptCBC(str string, key string) string {
	//-- safety
	defer PanicHandler() // for: b64Dec
	//-- check
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//-- signature
	var theSignature string = SIGNATURE_2FISH_V1_DEFAULT
	if(StrTrimWhitespaces(theSignature) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Empty Signature provided")
		return ""
	} //end if
	if(!StrContains(str, theSignature)) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Signature was not found")
		return ""
	} //end if
	//-- extract data after signature
	sgnArr := ExplodeWithLimit("!", str, 3)
	if(len(sgnArr) != 2) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Signature Separator")
		return ""
	} //end if
	str = StrTrimWhitespaces(DataRRot13(sgnArr[1]))
	sgnArr = nil
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": B64s Part not found")
		return ""
	} //end if
	//-- separe data from checksum + decode
	cksArr := ExplodeWithLimit(";", str, 3)
	if(len(cksArr) != 2) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Checksum Separator")
		return ""
	} //end if
	str = StrTrimWhitespaces(cksArr[0])
	cksum := StrTrimWhitespaces(cksArr[1])
	cksArr = nil
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Data Part not found")
		return ""
	} //end if
	if(cksum == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Checksum Part not found")
		return ""
	} //end if
	var pak string = str
	str = Base64sDecode(str)
	if(str == "") { // do not trim, it is raw crypto data
		log.Println("[NOTICE] " + CurrentFunctionName() + ": B64s Decode Failed")
		return ""
	} //end if
	//-- derived key, iv
	dKey, iv := twofishSafeKeyIv(key) // key b92, (32 bytes) ; iv b85 + b92 (16 bytes)
	//-- decrypt: CBC
	var decrypted string = ""
	var errDecrypted error = nil
	decrypted, errDecrypted = CipherDecryptCBC("TwoFish.256", str, dKey, iv, "")
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Decrypt Failed:", errDecrypted)
		return ""
	} //end if
	//-- unpack
	decrypted, errDecrypted = cryptoContainerUnpack("TwoFish", 3, decrypted)
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Unpack Failed:", errDecrypted)
		return ""
	} //end if
	//-- check package checksum
	if(StrTrimWhitespaces(cksum) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Data/Package Checksum is N/A, Cannot Verify")
		return ""
	} //end if
	if(StrTrimWhitespaces(pak) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Data/Package is N/A, Cannot Verify")
		return ""
	} //end if
	if(cksum != BaseEncode([]byte(Hex2Bin(Sh3a224(pak + NULL_BYTE + decrypted))), "b62")) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Data Checksum Failed")
		return ""
	} //end if
	//--
	return decrypted
	//--
} //END FUNCTION


//-----


func TwofishEncryptBlowfishCBC(str string, key string) string {
	//-- safety
	defer PanicHandler()
	//-- check
	if(str == "") {
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(BlowfishEncryptCBC(str, key))
	if((str == "") || (!StrStartsWith(str, SIGNATURE_BFISH_V3)) || (len(str) <= len(SIGNATURE_BFISH_V3))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to BF Pre-Encrypt Data")
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(StrSubstr(str, len(SIGNATURE_BFISH_V3), -1))
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to Separe BF Encrypted Data")
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(TwofishEncryptCBC(DataRRot13(str), key))
	if((str == "") || (!StrStartsWith(str, SIGNATURE_2FISH_V1_DEFAULT)) || (len(str) <= len(SIGNATURE_2FISH_V1_DEFAULT))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to TF Encrypt Data")
		return ""
	} //end if
	str = StrTrimWhitespaces(StrSubstr(str, len(SIGNATURE_2FISH_V1_DEFAULT), -1))
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Failed to Separe TF Encrypted Data")
		return ""
	} //end if
	//--
	return SIGNATURE_2FISH_V1_BF_DEFAULT + str
	//--
} //END FUNCTION


func TwofishDecryptBlowfishCBC(str string, key string) string {
	//-- safety
	defer PanicHandler()
	//-- check
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	if((!StrStartsWith(str, SIGNATURE_2FISH_V1_BF_DEFAULT)) || (len(str) <= len(SIGNATURE_2FISH_V1_BF_DEFAULT))) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Wrong Signature provided")
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(StrSubstr(str, len(SIGNATURE_2FISH_V1_BF_DEFAULT), -1))
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Empty Data After Signature")
		return ""
	} //end if
	//--
	str = StrTrimWhitespaces(TwofishDecryptCBC(SIGNATURE_2FISH_V1_DEFAULT + str, key))
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Empty Data After TF Decrypt")
		return ""
	} //end if
	//--
	return BlowfishDecryptCBC(SIGNATURE_BFISH_V3 + DataRRot13(str), key)
	//--
} //END FUNCTION


//-----


func blowfishV1SafeKey(plainTextKey string) string { // v1
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if((key == "") || (len(key) < int(DERIVE_MIN_KLEN)) || (len(key) > int(DERIVE_MAX_KLEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty or Invalid !")
		return ""
	} //end if
	//--
	var safeKey string = StrSubstr(Sha512(key), 13, 29+13) + StrToUpper(StrSubstr(Sha1(key), 13, 10+13)) + StrSubstr(Md5(key), 13, 9+13)
	//--
	//log.Println("[DEBUG] " + CurrentFunctionName() + " (v1):", safeKey)
	return safeKey
	//--
} //END FUNCTION


func blowfishV1SafeIv(plainTextKey string) string { // v1
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if((key == "") || (len(key) < int(DERIVE_MIN_KLEN)) || (len(key) > int(DERIVE_MAX_KLEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty or Invalid !")
		return ""
	} //end if
	//--
	var safeIv string = Base64Encode(Sha1("@Smart.Framework-Crypto/BlowFish:" + key + "#" + Sha1("BlowFish-iv-SHA1" + key) + "-" + StrToUpper(Md5("BlowFish-iv-MD5" + key)) + "#"))
	safeIv = StrSubstr(safeIv, 1, 8+1)
	//log.Println("[DEBUG] " + CurrentFunctionName() + " (v1):", safeIv)
	//--
	return safeIv
	//--
} //END FUNCTION


func blowfishComposeKey(plainTextKey string) string { // v2, v3 ; {{{SYNC-CRYPTO-KEY-DERIVE}}} [PHP]
	//--
	// This should be used as the basis for a derived key, will be 100% in theory and practice agains hash colissions (see the comments below)
	// It implements a safe mechanism that in order that a key to produce a colission must collide at the same time in all hashing mechanisms: md5, sha1, ha256 and sha512 + crc32b control
	// By enforcing the max key length to 4096 bytes actually will not have any chance to collide even in the lowest hashing such as md5 ...
	// It will return a string of 553 bytes length as: (base:key)[8(crc32b) + 1(null) + 32(md5) + 1(null) + 40(sha1) + 1(null) + 64(sha256) + 1(null) + 128(sha512) = 276] + 1(null) + (base:saltedKeyWithNullBytePrefix)[8(crc32b) + 1(null) + 32(md5) + 1(null) + 40(sha1) + 1(null) + 64(sha256) + 1(null) + 128(sha512) = 276]
	// More, it will return a fixed length (553 bytes) string with an ascii subset just of [ 01234567890abcdef + NullByte ] which already is colission free by using a max source string length of 4096 bytes and by combining many hashes as: md5, sha1, sha256, sha512 and the crc32b
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(key == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty !")
		return ""
	} //end if
	//--
	var klen int = len(key)
	if(klen < int(DERIVE_MIN_KLEN)) { // {{{SYNC-CRYPTO-KEY-MIN}}} ; minimum acceptable secure key is 7 characters long
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key Size is too short")
		return ""
	} else if(klen > int(DERIVE_MAX_KLEN)) { // {{{SYNC-CRYPTO-KEY-MAX}}} ; max key size is enforced to allow ZERO theoretical colissions on any of: md5, sha1, sha256 or sha512
		//-- as a precaution, use the lowest supported value which is 4096 (as the md5 supports) ; under this value all the hashes are safe against colissions (in theory)
		// MD5     produces 128 bits which is 16 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 16*256 =  4096 bytes
		// SHA-1   produces 160 bits which is 20 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 20*256 =  5120 bytes
		// SHA-256 produces 256 bits which is 32 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 32*256 =  8192 bytes
		// SHA-512 produces 512 bits which is 64 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 64*256 = 16384 bytes
		//-- anyway, as a more precaution, combine all hashes thus a key should produce a colission at the same time in all: md5, sha1, sha256 and sha512 ... which in theory, event with bad implementations of the hashing functions this is excluded !
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key Size is too long")
		return ""
	} //end if else
	//--
	// Security concept: be safe against collisions, the idea is to concatenate more algorithms on the exactly same input !!
	// https://security.stackexchange.com/questions/169711/when-hashing-do-longer-messages-have-a-higher-chance-of-collisions
	// just sensible salt + strong password = unbreakable ; using a minimal salt, prepended, the NULL byte ; a complex salt may be used later in combination with derived keys
	// the best is to pre-pend the salt: http://stackoverflow.com/questions/4171859/password-salts-prepending-vs-appending
	//--
	var saltedKey string = NULL_BYTE + key
	//--
	// https://stackoverflow.com/questions/1323013/what-are-the-chances-that-two-messages-have-the-same-md5-digest-and-the-same-sha
	// use just hex here and the null byte, with fixed lengths to reduce the chance of collisions for the next step (with not so complex fixed length strings, chances of colissions are infinite lower) ; this will generate a predictible concatenated hash using multiple algorithms ; actually the chances to find a colission for a string between 1..1024 characters that will produce a colission of all 4 hashing algorithms at the same time is ZERO in theory and in practice ... and in the well known universe using well known mathematics !
	//--
	var hkey1 string = Crc32b(key)       + NULL_BYTE + Md5(key)       + NULL_BYTE + Sha1(key)       + NULL_BYTE + Sha256(key)       + NULL_BYTE + Sha512(key)
	var hkey2 string = Crc32b(saltedKey) + NULL_BYTE + Md5(saltedKey) + NULL_BYTE + Sha1(saltedKey) + NULL_BYTE + Sha256(saltedKey) + NULL_BYTE + Sha512(saltedKey)
	//--
	return hkey1 + NULL_BYTE + hkey2 // composedKey
	//--
} //END FUNCTION


func blowfishSafeKey(plainTextKey string) string { // v2, v3
	//--
	defer PanicHandler() // for: hex2bin
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if((key == "") || (len(key) < int(DERIVE_MIN_KLEN)) || (len(key) > int(DERIVE_MAX_KLEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty or Invalid !")
		return ""
	} //end if
	//--
	var composedKey string = blowfishComposeKey(key)
	var len_composedKey int = len(composedKey)
	var len_trimmed_composedKey int = len(StrTrimWhitespaces(composedKey))
	if((len_composedKey != 553) || (len_trimmed_composedKey != 553)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Safe Composed Key is invalid (", len_composedKey, "/", len_trimmed_composedKey, ") !")
		return ""
	} //end if
	//--
	var derivedKey string = BaseEncode([]byte(Hex2Bin(Sha256(composedKey))), "b92") + "'" + BaseEncode([]byte(Hex2Bin(Md5(composedKey))), "b92")
	var safeKey string = StrSubstr(derivedKey, 0, 448/8) // 448/8
	//log.Println("[DEBUG] " + CurrentFunctionName() + ":", safeKey)
	return safeKey
	//--
} //END FUNCTION


func blowfishSafeIv(plainTextKey string) string { // v2, v3
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if((key == "") || (len(key) < int(DERIVE_MIN_KLEN)) || (len(key) > int(DERIVE_MAX_KLEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty or Invalid !")
		return ""
	} //end if
	//--
	var data string = StrPad2LenLeft(Crc32bB36(key), "0", 8)
	var safeIv string = StrSubstr(data + ":" + Sha1B64(key), 0, 64/8) // 64/8
	//--
	//log.Println("[DEBUG] " + CurrentFunctionName() + ":", safeIv)
	return safeIv
	//--
} //END FUNCTION


func BlowfishEncryptCBC(str string, key string) string { // v3 only
	//-- safety
	defer PanicHandler() // for: hex2bin ; encrypt
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	var oStr string = str
	str = Base64Encode(str)
	cksum := BaseEncode([]byte(Base64Decode(Sh3a512B64(str))), "b62")
	str = str + SEPARATOR_CRYPTO_CHECKSUM_V3 + cksum
	//log.Println("[DEBUG] " + CurrentFunctionName() + ":", str)
	//-- signature
	var theSignature string = SIGNATURE_BFISH_V3
	//-- derived key, iv
	var dKey string = blowfishSafeKey(key) // key b92 (56 bytes)
	var iv string = blowfishSafeIv(key) // iv b36 (8 bytes)
	//-- encrypt: CBC
	encStr, encErr := CipherEncryptCBC("BlowFish.448", str, dKey, iv, "")
	str = ""
	if(encErr != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Encrypt Error:", encErr)
		return ""
	} //end if
	encStr = Base64sEncode(encStr) // b64s
	//--
	var ckSum string = BaseEncode([]byte(Hex2Bin(Sh3a224(encStr + NULL_BYTE + oStr))), "b62")
	oStr = ""
	//--
	return theSignature + DataRRot13(encStr + ";" + ckSum) // signature
	//--
} //END FUNCTION


func BlowfishDecryptCBC(str string, key string) string { // v1, v2, v3
	//-- safety
	defer PanicHandler() // for: hex2bin ; b64Dec ; decrypt
	//-- check
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//-- signature
	var theSignature string = ""
	var versionDetected uint8 = 0
	if(StrPos(str, SIGNATURE_BFISH_V3) == 0) {
		versionDetected = 3
		theSignature = SIGNATURE_BFISH_V3
	} else if(StrPos(str, SIGNATURE_BFISH_V2) == 0) {
		versionDetected = 2
		theSignature = SIGNATURE_BFISH_V2
	} else if(StrPos(str, SIGNATURE_BFISH_V1) == 0) {
		versionDetected = 1
		theSignature = SIGNATURE_BFISH_V1
//	} else { // DISABLED, no more handle packages without a valid signature !
//		versionDetected = 1
//		theSignature = SIGNATURE_BFISH_V1
//		str = SIGNATURE_BFISH_V1 + str // if no signature found consider it is v1 and try to dercypt
	} //end if
	if((versionDetected < 1) || (versionDetected > 3)) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Version Detected:", versionDetected)
		return ""
	} //end if
	if(StrTrimWhitespaces(theSignature) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Empty or Invalid Signature ; Version:", versionDetected)
		return ""
	} //end if
	//-- extract data after signature
	sgnArr := ExplodeWithLimit("!", str, 3)
	if(len(sgnArr) != 2) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Signature Separator ; Version:", versionDetected)
		return ""
	} //end if
	str = StrTrimWhitespaces(sgnArr[1])
	sgnArr = nil
	if(str == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": B64s Part not found ; Version:", versionDetected)
		return ""
	} //end if
	//-- separe data from checksum + decode
	var pak string = ""
	var cksum string = ""
	if(versionDetected == 1) { // v1
		str = Hex2Bin(StrToLower(str))
		if(str == "") { // do not trim, it is raw crypto data
			log.Println("[NOTICE] " + CurrentFunctionName() + ": Hex Decode Failed ; Version:", versionDetected)
			return ""
		} //end if
	} else if(versionDetected == 2) { // v2
		str = Base64sDecode(str)
		if(str == "") { // do not trim, it is raw crypto data
			log.Println("[NOTICE] " + CurrentFunctionName() + ": B64s Decode Failed ; Version:", versionDetected)
			return ""
		} //end if
	} else { // v3
		cksArr := ExplodeWithLimit(";", DataRRot13(str), 3)
		if(len(cksArr) != 2) {
			log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Checksum Separator ; Version:", versionDetected)
			return ""
		} //end if
		str = StrTrimWhitespaces(cksArr[0])
		cksum = StrTrimWhitespaces(cksArr[1])
		cksArr = nil
		if(str == "") {
			log.Println("[NOTICE] " + CurrentFunctionName() + ": Data Part not found ; Version:", versionDetected)
			return ""
		} //end if
		if(cksum == "") {
			log.Println("[NOTICE] " + CurrentFunctionName() + ": Checksum Part not found ; Version:", versionDetected)
			return ""
		} //end if
		pak = str
		str = Base64sDecode(str)
		if(str == "") { // do not trim, it is raw crypto data
			log.Println("[NOTICE] " + CurrentFunctionName() + ": B64s Decode Failed ; Version:", versionDetected)
			return ""
		} //end if
	} //end if else
	//-- derived key, iv (by version)
	var dKey string = ""
	var iv string = ""
	if(versionDetected == 1) { // v1
		dKey = blowfishV1SafeKey(key) // 48 bytes
	} else { // v2, v3
		dKey = blowfishSafeKey(key) // 56 bytes
	} //end if else
	if(StrTrimWhitespaces(dKey) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Derived Key is NOT Set ; Version:", versionDetected)
		return ""
	} //end if
	if(versionDetected == 1) { // v1
		iv = blowfishV1SafeIv(key) // 8 bytes
	} else { // v2, v3
		iv = blowfishSafeIv(key) // 8 bytes
	} //end if else
	if(StrTrimWhitespaces(iv) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Derived Iv is NOT Set ; Version:", versionDetected)
		return ""
	} //end if
	//-- set algo (by version)
	var algoMode string = ""
	if(versionDetected == 1) {
		algoMode = "384"
	} else { // v2, v3
		algoMode = "448"
	} //end if else
	if(StrTrimWhitespaces(algoMode) == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Algo Mode is NOT Set ; Version:", versionDetected)
		return ""
	} //end if
	//-- decrypt: CBC
	var decrypted string = ""
	var errDecrypted error = nil
	decrypted, errDecrypted = CipherDecryptCBC("BlowFish." + algoMode, str, dKey, iv, "")
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Decrypt Failed ; Version:", versionDetected, "; ErrMsg:", errDecrypted)
		return ""
	} //end if
	//-- unpack
	decrypted, errDecrypted = cryptoContainerUnpack("BlowFish", versionDetected, decrypted)
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Unpack Failed ; Version:", versionDetected, "; ErrMsg:", errDecrypted)
		return ""
	} //end if
	//-- check package checksum ; v3 only
	if(versionDetected > 2) {
		//--
		if(StrTrimWhitespaces(cksum) == "") {
			log.Println("[NOTICE] " + CurrentFunctionName() + ": Data/Package Checksum is N/A, Cannot Verify ; Version:", versionDetected)
			return ""
		} //end if
		if(StrTrimWhitespaces(pak) == "") {
			log.Println("[NOTICE] " + CurrentFunctionName() + ": Data/Package is N/A, Cannot Verify ; Version:", versionDetected)
			return ""
		} //end if
		if(cksum != BaseEncode([]byte(Hex2Bin(Sh3a224(pak + NULL_BYTE + decrypted))), "b62")) {
			log.Println("[NOTICE] " + CurrentFunctionName() + ": Data Checksum Failed ; Version:", versionDetected)
			return ""
		} //end if
		//--
	} //end if
	//--
	return decrypted
	//--
} //END FUNCTION


//-----


// return: err, pubKeyPEM, privKeyPEM
func GenerateSSHKeyPairEd25519(comment string, password string) (error, string, string) {
	//-- info
	// the comment is expected to be an email address or a slug
	//-- trim, normalize spaces, replace spaces with -, and allow max 255 chars
	comment = StrSubstr(StrReplaceAll(StrTrimWhitespaces(StrNormalizeSpaces(comment)), " ", "-"), 0, 255)
	//-- do not trim, just ensure max allowed size
	password = StrSubstr(password, 0, 72) // the PASSWORD_BCRYPT as the algorithm supports max length as 72 !
	//--
	pub, priv, errK := ed25519.GenerateKey(cryptorand.Reader)
	if(errK != nil) {
		return errK, "", ""
	} //end if
	//--
	var p *pem.Block
	var errM error
	if(password != "") {
		p, errM = ssh.MarshalPrivateKeyWithPassphrase(crypto.PrivateKey(priv), comment, []byte(password))
	} else {
		p, errM = ssh.MarshalPrivateKey(crypto.PrivateKey(priv), comment)
	} //end if else
	if(errM != nil) {
		return errM, "", ""
	} //end if
	//--
	publicKey, err := ssh.NewPublicKey(pub)
	if(err != nil) {
		return errM, "", ""
	} //end if
	privateKeyPem := pem.EncodeToMemory(p)
	//--
	pubPemK := "ssh-ed25519" + " " + base64.StdEncoding.EncodeToString(publicKey.Marshal()) + " " + comment
	privPemK := string(privateKeyPem)
	//--
	return nil, StrTrimWhitespaces(pubPemK), StrTrimWhitespaces(privPemK)
	//--
} //END FUNCTION


//-----


// #END
