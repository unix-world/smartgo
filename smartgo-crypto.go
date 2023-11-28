
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231128.2358 :: STABLE
// [ CRYPTO ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"errors"
	"log"

	"strings"

	"math"
	"math/big"

	"io"

	"encoding/hex"
	"encoding/base64"

	"crypto/subtle"
	"crypto/cipher"
	cryptorand "crypto/rand"

	"hash/crc32"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/hmac"

	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/argon2"

	"github.com/unix-world/smartgo/poly1305"
	"github.com/unix-world/smartgo/pbkdf2"
	"github.com/unix-world/smartgo/blowfish"
	"github.com/unix-world/smartgo/twofish"
	"github.com/unix-world/smartgo/threefish"
)

const (
	SEPARATOR_CRYPTO_CHECKSUM_V1 string 	= "#CHECKSUM-SHA1#" 							// only to support v1 unarchive or decrypt ; (for v1 no archive or encrypt is available anymore ; use v2 for Blowfish and v3 for Twofish / Threefish !)
	SEPARATOR_CRYPTO_CHECKSUM_V2 string 	= "#CKSUM256#" 									// current, v2 ; archive + unarchive or encrypt + decrypt ; Blowfish only
	SEPARATOR_CRYPTO_CHECKSUM_V3 string 	= "#CKSUM512V3#" 								// current, v3 ; archive + unarchive or encrypt + decrypt ; Twofish / Threefish only

	SIGNATURE_BFISH_V1 string 				= "bf384.v1!" 									// this was not implemented in the v1, if used must be prefixed before decrypt for compatibility ... (for v1 no encrypt is available anymore)
	SIGNATURE_BFISH_V2 string 				= "bf448.v2!" 									// current, v2 ; encrypt + decrypt

	SIGNATURE_2FISH_V1_DEFAULT string 		= "2f256.v1!" 									// current, v1 (default)   ; encrypt + decrypt
	SIGNATURE_2FISH_V1_BFISH   string 		= "2f88B.v1!" 									// current, v1 (+blowfish) ; encrypt + decrypt ; Blowfish 56 (448) + TwoFish 32 (256) = 88 (704)

	SIGNATURE_3FISH_V1_DEFAULT string  		= "3f1kD.v1!" 									// current, v1 (default)  ; encrypt + decrypt
	SIGNATURE_3FISH_V1_ARGON2ID string 		= "3f1kA.v1!" 									// current, v1 (argon2id) ; encrypt + decrypt

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

	REGEX_SAFE_HTTP_USER_NAME string 		= `^[a-z0-9\.]+$` 								// Safe UserName Regex
)


//-----


func UserPassDefaultCheck(user string, pass string, requiredUsername string, requiredPassword string) bool {
	//--
	if( // {{{SYNC-HTTP-AUTH-CHECKS-GO-SMART}}}
		(StrTrimWhitespaces(user) == "") ||
		((len(user) < 3) || (len(user) > 128)) || // {{{SYNC-GO-SMART-AUTH-USER-LEN}}} ; std max username length is 128 ; min 3, from Smart.Framework
		(!StrRegexMatchString(REGEX_SAFE_HTTP_USER_NAME, user)) || // {{{SYNC-SF:REGEX_VALID_USER_NAME}}}
		//--
		(StrTrimWhitespaces(pass) == "") ||
		((len(StrTrimWhitespaces(pass)) < 7) || (len(pass) > 2048)) || // {{{SYNC-GO-SMART-AUTH-PASS-LEN}}} ; allow tokens, length can be up to 2048 (ex: JWT) ; min 7, from Smart.Framework (security)
		//--
		(len(user) != len(requiredUsername)) ||
		(len(pass) != len(requiredPassword)) ||
		(subtle.ConstantTimeCompare([]byte(user), []byte(requiredUsername)) != 1) ||
		(subtle.ConstantTimeCompare([]byte(pass), []byte(requiredPassword)) != 1) ||
		(user != requiredUsername) || (pass != requiredPassword)) {
		//--
		return false
		//--
	} //end if
	//--
	return true
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
	algo = StrToLower(algo)
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
		return "", errors.New(CurrentFunctionName() + " # " + "Invalid Algo: `" + algo + "`")
	} //end if
	//--
	if(StrTrimWhitespaces(sum) == "") {
		return "", errors.New(CurrentFunctionName() + " # Failed to create a HMac Sum for Algo: `" + algo + "`")
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
	defer PanicHandler() // req. by poly1305 ...
	//--
	if(len(key) != 32) {
		return "", errors.New(CurrentFunctionName() + " # " + "Key length is invalid, must be 32 bytes !")
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
	//--
	// Create a safe checksum of data
	// It will append the salt to the end of data to avoid the length extension attack # https://en.wikipedia.org/wiki/Length_extension_attack
	// Protected by SHA384 that has 128-bit resistance against the length extension attacks since the attacker needs to guess the 128-bit to perform the attack, due to the truncation
	//--
	defer PanicHandler() // req. by b64 decode panic handler with malformed data
	//--
	customSalt = StrTrimWhitespaces(customSalt)
	if(customSalt == "") {
		customSalt = SALT_PREFIX + " " + SALT_SEPARATOR + " " + SALT_SUFFIX // dissalow empty salt, fallback to have at least something
	} //end if
	//--
	var b64CkSum string = Sha384B64(plainTextData + "#" + customSalt) // sha384 is a better choice than sha256/sha512 because is more resistant to length attacks
	var rawCkSum string = Base64Decode(b64CkSum)
	//--
	return BaseEncode([]byte(rawCkSum), "b62")
	//--
} //END FUNCTION


//-----


func safePassComposedKey(plainTextKey string) string { // {{{SYNC-CRYPTO-KEY-DERIVE}}} [PHP]
	//--
	// This should be used as the basis for a derived key, will be 100% in theory and practice agains hash colissions (see the comments below)
	// It implements a safe mechanism that in order that a key to produce a colission must collide at the same time in all hashing mechanisms: md5, sha1, ha256 and sha512 + crc32b control
	// By enforcing the max key length to 4096 bytes actually will not have any chance to collide even in the lowest hashing such as md5 ...
	// It will return a string of 553 bytes length as: (base:key)[8(crc32b) + 1(null) + 32(md5) + 1(null) + 40(sha1) + 1(null) + 64(sha256) + 1(null) + 128(sha512) = 276] + 1(null) + (base:saltedKeyWithNullBytePrefix)[8(crc32b) + 1(null) + 32(md5) + 1(null) + 40(sha1) + 1(null) + 64(sha256) + 1(null) + 128(sha512) = 276]
	// More, it will return a fixed length (553 bytes) string with an ascii subset just of [ 01234567890abcdef + NullByte ] which already is colission free by using a max source string length of 4096 bytes and by combining many hashes as: md5, sha1, sha256, sha512 and the crc32b
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(plainTextKey != key) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is invalid, must not contain trailing spaces !")
		return ""
	} //end if
	//--
	var klen int = len(key)
	if(klen < 7) { // {{{SYNC-CRYPTO-KEY-MIN}}} ; minimum acceptable secure key is 7 characters long
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key Size is lower than 7 bytes (", klen, ") which is not safe against brute force attacks !")
		return ""
	} else if(klen > 4096) { // {{{SYNC-CRYPTO-KEY-MAX}}} ; max key size is enforced to allow ZERO theoretical colissions on any of: md5, sha1, sha256 or sha512
		//-- as a precaution, use the lowest supported value which is 4096 (as the md5 supports) ; under this value all the hashes are safe against colissions (in theory)
		// MD5     produces 128 bits which is 16 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 16*256 =  4096 bytes
		// SHA-1   produces 160 bits which is 20 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 20*256 =  5120 bytes
		// SHA-256 produces 256 bits which is 32 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 32*256 =  8192 bytes
		// SHA-512 produces 512 bits which is 64 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 64*256 = 16384 bytes
		//-- anyway, as a more precaution, combine all hashes thus a key should produce a colission at the same time in all: md5, sha1, sha256 and sha512 ... which in theory, event with bad implementations of the hashing functions this is excluded !
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key Size is higher than 4096 bytes (", klen, ") which is not safe against collisions !")
		return ""
	} //end if else
	//--
	// Security concept: be safe against collisions, the idea is to concatenate more algorithms on the exactly same input !!
	// https://security.stackexchange.com/questions/169711/when-hashing-do-longer-messages-have-a-higher-chance-of-collisions
	// just sensible salt + strong password = unbreakable ; using a minimal salt, prepended, the NULL byte ; a complex salt may be used later in combination with derived keys
	// the best is to pre-pend the salt: http://stackoverflow.com/questions/4171859/password-salts-prepending-vs-appending
	//--
	var saltedKey string = NULL_BYTE + key
	//-- use hex here, with fixed lengths to reduce the chance of collisions for the next step (with not so complex fixed length strings, chances of colissions are infinite lower) ; this will generate a predictible concatenated hash using multiple algorithms ; actually the chances to find a colission for a string between 1..1024 characters that will produce a colission of all 4 hashing algorithms at the same time is ZERO in theory and in practice ... and in the well known universe using well known mathematics !
	var hkey1 string = Crc32b(key)       + NULL_BYTE + Md5(key)       + NULL_BYTE + Sha1(key)       + NULL_BYTE + Sha256(key)       + NULL_BYTE + Sha512(key)
	var hkey2 string = Crc32b(saltedKey) + NULL_BYTE + Md5(saltedKey) + NULL_BYTE + Sha1(saltedKey) + NULL_BYTE + Sha256(saltedKey) + NULL_BYTE + Sha512(saltedKey)
	//--
	return hkey1 + NULL_BYTE + hkey2 // composedKey
	//--
} //END FUNCTION


//-----


func SafePassHashSmart(plainPass string, theSalt string, useArgon2id bool) string { // {{{SYNC-HASH-PASSWORD}}} [PHP]
	//-- r.20231128 + Argon2Id
	defer PanicHandler() // req. by Hex2Bin and Argon2Id
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
		sSalt = string(argon2.IDKey([]byte(key), []byte(pbkdf2Salt + "\v" + DataRot13(BaseEncode([]byte(pbkdf2Salt), "b32"))), uint32(math.Ceil((float64(DERIVE_CENTITER_PW) * 1.7) - 2)), 128*1024, 1, uint32(reqLen))) // Argon2id resources: 129 cycles, 128MB memory, 1 thread, 34 bytes = 272 bits
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
	pddPass := StrPad2LenRight(plainPass, "\v", int(PASSWORD_PLAIN_MAX_LENGTH)) // fixed length: 55
	chksPPass := Crc32bB36(pddPass) // 7 chars
	hashData := fSalt + "\n" + pddPass + "\r" + "\t" + chksPass // MUST BE FIXED LEN ! It is 87 a PRIME Number ! To avoid colissions ; SHA3-512 collisions safe max string is 256 bit (32 bytes only) !!!
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
	defer PanicHandler() // req. by Hex2Bin
	//--
	key = StrTrimWhitespaces(key)
	klen := len(key)
	//--
	if(klen < int(DERIVE_MIN_KLEN)) {
		return "", errors.New(CurrentFunctionName() + " # The Key is too short: " + ConvertIntToStr(klen))
	} else if(klen > int(DERIVE_MAX_KLEN)) {
		return "", errors.New(CurrentFunctionName() + " # The Key is too long: " + ConvertIntToStr(klen))
	} //end if else
	//--
	b64 := Sh3a384B64(key) // 64 chars fixed length, B64
	hex := Sh3a512(key + "\v" + Crc32bB36(key) + "\v" + DataRRot13(b64)) // 128 chars fixed length, HEX
	bin := Hex2Bin(hex)
	if(bin == "") {
		return "", errors.New(CurrentFunctionName() + " # Hash Hex2Bin Error")
	} //end if
	b92 := BaseEncode([]byte(bin), "b92")
	//--
	preKey := StrTrimWhitespaces(DataRRot13(StrSubstr(StrPad2LenRight(b92, "'", int(DERIVE_PREKEY_LEN)), 0, int(DERIVE_PREKEY_LEN))))
	//--
	if(
		(StrTrimWhitespaces(preKey) == "") || // avoid being empty
		(StrTrim(preKey, "'") == "") || // avoid being all '
		(len(preKey) != int(DERIVE_PREKEY_LEN))) {
			return "", errors.New(CurrentFunctionName() + " # The B92 PBKDF2 Pre-Derived Key is empty or does not match the expected size ; required size is: " + ConvertUInt16ToStr(DERIVE_PREKEY_LEN) + " bytes ; but the actual size is: " + ConvertIntToStr(len(preKey)) + " bytes")
	} //end if
	//--
	return preKey, nil
	//--
} //END FUNCTION


func Pbkdf2DerivedKey(algo string, key string, salt string, klen uint16, iterations uint16, b92 bool) (string, error) {
	//-- r.20231128
	defer PanicHandler() // may be req. by pbkdf2.Key
	//--
	algo = StrToLower(algo)
	//--
	var err error
	//--
	var lk = len(key)
	var ls = len(salt)
	//--
	if(lk < int(DERIVE_MIN_KLEN)) {
		return "", errors.New(CurrentFunctionName() + " # The Key is too short: " + ConvertIntToStr(lk))
	} else if(lk > int(DERIVE_MAX_KLEN)) {
		return "", errors.New(CurrentFunctionName() + " # The Key is too long: " + ConvertIntToStr(lk))
	} //end if else
	if(ls < int(DERIVE_MIN_KLEN)) {
		return "", errors.New(CurrentFunctionName() + " # The Salt is too short: " + ConvertIntToStr(ls))
	} else if(ls > int(DERIVE_MAX_KLEN)) {
		return "", errors.New(CurrentFunctionName() + " # The Salt is too long: " + ConvertIntToStr(ls))
	} //end if else
	//--
	var keyLen int = int(klen) // below values may be adjusted, avoid out of range of uint16
	if(klen <= 0) {
		return "", errors.New(CurrentFunctionName() + " # The length parameter is zero or negative")
	} //end if
	if(b92 == true) {
		keyLen = 2 * keyLen // ensure double size ; {{{SYNC-PBKDF2-HEX-TO-B92-LENGTH-ADJUST}}} ; should have enough length to ensure the same size because Base92 length shrinks after conversion from HEX (Base16)
	} //end if
	//--
	var iterCycles int = int(iterations) // below values may be adjusted, avoid out of range of uint16
	if(iterCycles < 1) {
		iterCycles = 1
		err = errors.New(CurrentFunctionName() + " # The Number of iterations is too low: " + ConvertUInt16ToStr(iterations))
	} else if(iterCycles > 50000) { // in go let 5000 * 10 as in PHP
		iterCycles = 50000
		err = errors.New(CurrentFunctionName() + " # The Number of iterations is too high: " + ConvertUInt16ToStr(iterations))
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
		return "", errors.New(CurrentFunctionName() + " # " + "Invalid Algo: `" + algo + "`")
	} //end if
	//--
	if(StrTrimWhitespaces(dk) == "") {
		return "", errors.New(CurrentFunctionName() + " # Failed to create a PBKDF2 Derived Key for Algo: `" + algo + "`")
	} //end if
	//--
	if(len(dk) != keyLen) {
		return "", errors.New(CurrentFunctionName() + " # The PBKDF2 Derived Key have an invalid length for Algo: `" + algo + "`")
	} //end if
	//--
	if(len(dk) < int(klen)) { // before converting to hex, is RAW, just ensure is enough size
		return "", errors.New(CurrentFunctionName() + " # The PBKDF2 Derived Raw Key length is invalid for Algo: `" + algo + "` as: " + ConvertIntToStr(len(dk)))
	} //end if
	//--
	if(b92 == true) { // B92
		//--
		dk = StrSubstr(dk, 0, int(klen)) // extract required size
		dk = BaseEncode([]byte(dk), "b92")
		dk = StrSubstr(StrPad2LenRight(dk, "'", int(klen)), 0, int(klen)) // both: HEX or B92 must do this in Go
		if(len(dk) != int(klen)) {
			return "", errors.New(CurrentFunctionName() + " # The PBKDF2 Derived Key length is invalid for Algo: `" + algo + "` as: " + ConvertIntToStr(len(dk)))
		} //end if
		//--
	} else { // Hex
		//--
		dk = StrToLower(Bin2Hex(dk))
		if(len(dk) < (int(klen) * 2)) { // after converting to hex, doubles the size
			return "", errors.New(CurrentFunctionName() + " # The PBKDF2 Derived Hex Key length is invalid for Algo: `" + algo + "` as: " + ConvertIntToStr(len(dk)))
		} //end if
		//--
		dk = StrSubstr(dk, 0, int(klen)) // extract required size
		if(len(dk) != int(klen)) {
			return "", errors.New(CurrentFunctionName() + " # The PBKDF2 Derived Hex Key length after fix is invalid for Algo: `" + algo + "` as: " + ConvertIntToStr(len(dk)))
		} //end if
		//--
	} //end if
	//--
	return dk, err
	//--
} //END FUNCTION


//-----


func cipherEncryptDataCBC(ecipher cipher.Block, str string, iv string) (string, error) {
	//-- init
	var encrypted string = ""
	//-- fix padding
	var slen int = len(str)
	var modulus int = slen % ecipher.BlockSize()
	if(modulus > 0) {
		var padlen int = ecipher.BlockSize() - modulus
		str = StrPad2LenRight(str, " ", slen + padlen) // pad with spaces
		slen = slen + padlen
	} //end if
	//-- encrypt
	ciphertext := make([]byte, ecipher.BlockSize()+slen) // make ciphertext big enough to store data
	ecbc := cipher.NewCBCEncrypter(ecipher, []byte(iv)) // create the encrypter: CBC
	ecbc.CryptBlocks(ciphertext[ecipher.BlockSize():], []byte(str)) // encrypt the blocks
	str = "" // no more needed
	encrypted = StrTrimWhitespaces(Bin2Hex(string(ciphertext))) // prepare output
	ciphertext = nil
	//-- clear first header block ; will use BlockSize*2 because is operating over HEX data ; there are BlockSize*2 trailing zeroes that represent the HEX of BlockSize null bytes ; remove them
	if(StrSubstr(encrypted, 0, ecipher.BlockSize()*2) != strings.Repeat("0", ecipher.BlockSize()*2)) { // {{{FIX-GOLANG-CIPHER-1ST-NULL-BLOCK-HEADER}}}
		return "", errors.New("Invalid Hex Header")
	} //end if
	encrypted = StrTrimWhitespaces(StrSubstr(encrypted, ecipher.BlockSize()*2, 0)) // {{{FIX-GOLANG-CIPHER-1ST-NULL-BLOCK-HEADER}}}
	if(encrypted == "") { // must be some data after the first null header bytes
		return "", errors.New("Empty Hex Body")
	} //end if
	//--
	return encrypted, nil
	//--
} //END FUNCTION


func cipherDecryptDataCBC(dcipher cipher.Block, str string, iv string) (string, error) {
	//-- init
	var decrypted []byte = nil
	//-- decrypt
	et := []byte(str)
	str = ""
	decrypted = et[dcipher.BlockSize():]
	et = nil
	if(len(decrypted) % dcipher.BlockSize() != 0) { // check last slice of encrypted text, if it's not a modulus of cipher block size, it's a problem
		return "", errors.New("Decrypted Data is not a multiple of cipher BlockSize: [" + ConvertIntToStr(dcipher.BlockSize()) + "]")
	} //end if
	dcbc := cipher.NewCBCDecrypter(dcipher, []byte(iv))
	dcbc.CryptBlocks(decrypted, decrypted)
	//--
	return string(decrypted), nil
	//--
} //END FUNCTION


func cryptoContainerUnpack(algo string, ver uint8, str string) (string, error) {
	//--
	defer PanicHandler() // req. by b64 decode panic handler with malformed data
	//--
	algo = StrToLower(StrTrimWhitespaces(algo))
	//--
	if((ver != 3) && (ver != 2) && (ver != 1)) {
		return "", errors.New("Invalid Version: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	if(str == "") {
		return "", errors.New("Empty Data Packet, v: " + ConvertUInt8ToStr(ver))
	} //end if
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return "", errors.New("Invalid Data Packet, v: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	var separator string = ""
	if(algo == "threefish") {
		if(ver != 3) {
			return "", errors.New("Invalid Threefish Version, v: " + ConvertUInt8ToStr(ver))
		} //end if
		separator = SEPARATOR_CRYPTO_CHECKSUM_V3
	} else if(algo == "twofish") {
		if(ver != 3) {
			return "", errors.New("Invalid Twofish Version, v: " + ConvertUInt8ToStr(ver))
		} //end if
		separator = SEPARATOR_CRYPTO_CHECKSUM_V3
	} else if(algo == "blowfish") {
		if(ver == 1) {
			separator = SEPARATOR_CRYPTO_CHECKSUM_V1
		} else if(ver == 2) {
			separator = SEPARATOR_CRYPTO_CHECKSUM_V2
		} else {
			return "", errors.New("Invalid BlowFish Version, v: " + ConvertUInt8ToStr(ver))
		} //end if else
	} else {
		return "", errors.New("Invalid Algo: `" + algo + "` ; Version, v: " + ConvertUInt8ToStr(ver))
	} //end if else
	if(separator == "") {
		return "", errors.New("Empty Data Packet Checksum Separator, v: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	if(!StrContains(str, separator)) {
		return "", errors.New("Invalid Data Packet, NO Checksum, v: " + ConvertUInt8ToStr(ver))
	} //end if
	darr := ExplodeWithLimit(separator, str, 3)
	if(len(darr) != 2) {
		return "", errors.New("Invalid Data Packet Segments, v: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	str = "" // clear
	var dlen int = len(darr)
	if(dlen < 2) {
		return "", errors.New("Invalid Data Packet, Checksum NOT Found, v: " + ConvertUInt8ToStr(ver))
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		return "", errors.New("Invalid Data Packet, Checksum is Empty, v: " + ConvertUInt8ToStr(ver))
	} //end if
	if(darr[0] == "") {
		return "", errors.New("Invalid Data Packet, Packed Data NOT Found, v: " + ConvertUInt8ToStr(ver))
	} //end if
	//--
	switch(algo) {
		case "blowfish": // v1 or v2
			if(ver == 1) { // v1
				if(Sha1(darr[0]) != darr[1]) {
					return "", errors.New("Invalid Blowfish Data Packet (v1), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
				} //end if
			} else { // v2
				if(Sha256B64(darr[0]) != darr[1]) {
					return "", errors.New("Invalid Blowfish Data Packet (v2), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
				} //end if
			} //end if else
			break
		case "twofish": // v3 only
			if(Sh3a384B64(darr[0]) != darr[1]) {
				return "", errors.New("Invalid Twofish Data Packet (v3), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
			} //end if
			break
		case "threefish": // v3 only
			if(Sh3a384B64(darr[0]) != darr[1]) {
				return "", errors.New("Invalid Threefish Data Packet (v3), Checksum FAILED :: A checksum was found but is invalid: `" + darr[1] + "`")
			} //end if
			break
		default:
			return "", errors.New("Invalid Data Packet, Algo: `" + algo + "` ; Version, v: " + ConvertUInt8ToStr(ver))
	} //end switch
	//--
	return Base64Decode(darr[0]), nil
	//--
} //END FUNCTION


//-----


func threefishSafeKey(plainTextKey string, useArgon2id bool) string { // {{{SYNC-CRYPTO-KEY-DERIVE}}}
	//--
	// B92 ; (128 bytes)
	//--
	defer PanicHandler() // req. by Argon2Id
	//--
	salt, errSalt := Pbkdf2PreDerivedKey(plainTextKey)
	if((errSalt != nil) || (len(salt) != int(DERIVE_PREKEY_LEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Pre-Derived Salt is Invalid !")
		return ""
	} //end if
	//--
	const klen uint16 = 128
	var safeKey string = ""
	var errSafeKey error = nil
	if(useArgon2id == true) {
		safeKey = string(argon2.IDKey([]byte(plainTextKey), []byte(salt), uint32(DERIVE_CENTITER_EK), 256*1024, 1, uint32(klen))) // Argon2id resources: 87 cycles, 256MB memory, 1 thread, 128 bytes = 1024 bits
		safeKey = BaseEncode([]byte(safeKey), "b92") // b92
	} else {
		safeKey, errSafeKey = Pbkdf2DerivedKey("sha3-512", plainTextKey, salt, klen, DERIVE_CENTITER_EK, true) // b92
		if(errSafeKey != nil) {
			safeKey = ""
		} //end if else
	} //end if else
	safeKey = StrSubstr(safeKey, 0, int(klen))
	safeKey = StrTrimWhitespaces(safeKey)
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
	//--
	// B92 ; (128 bytes)
	//--
	defer PanicHandler() // req. by Argon2Id
	//--
	salt, errSalt := Pbkdf2PreDerivedKey(DataRRot13(Base64sEncode(plainTextKey)))
	if((errSalt != nil) || (len(salt) != int(DERIVE_PREKEY_LEN))) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Pre-Derived Salt is Invalid !")
		return ""
	} //end if
	//--
	const ivlen uint16 = 128
	var safeIv string = ""
	var errSafeIv error = nil
	if(useArgon2id == true) {
		safeIv = string(argon2.IDKey([]byte(plainTextKey), []byte(salt), uint32(DERIVE_CENTITER_EV), 192*1024, 1, uint32(ivlen))) // Argon2id resources: 78 cycles, 192MB memory, 1 thread, 128 bytes = 1024 bits
		safeIv = BaseEncode([]byte(safeIv), "b92") // b92
	} else {
		safeIv, errSafeIv = Pbkdf2DerivedKey("sha3-384", plainTextKey, salt, ivlen, DERIVE_CENTITER_EV, true) // b92
		if(errSafeIv != nil) {
			safeIv = ""
		} //end if else
	} //end if else
	safeIv = StrSubstr(safeIv, 0, int(ivlen))
	safeIv = StrTrimWhitespaces(safeIv)
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
	//--
	// B85 ; (16 bytes)
	//--
	defer PanicHandler() // req. by cipher encrypt panic handler with wrong padded data
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(key == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty !")
		return ""
	} //end if
	//--
	var ckSumCrc32bKeyHex string = Crc32b(key)
	var ckSumCrc32bDKeyHex string = Crc32b(key)
	var ckSumCrc32bKeyRaw string = Hex2Bin(ckSumCrc32bKeyHex)
	var ckSumCrc32bDKeyRaw string = Hex2Bin(ckSumCrc32bDKeyHex)
	var ckSumCrc32bKeyEnc string = BaseEncode([]byte(ckSumCrc32bKeyRaw + ckSumCrc32bDKeyRaw), "b62")
	var ckSumCrc32bDKeyEnc string = BaseEncode([]byte(ckSumCrc32bDKeyRaw + ckSumCrc32bKeyRaw), "b58")
	var ckSumHash string = Sh3a512B64(key + NULL_BYTE + SALT_PREFIX + " " + SALT_SEPARATOR + " " + SALT_SUFFIX + NULL_BYTE + ckSumCrc32bKeyEnc + NULL_BYTE + ckSumCrc32bDKeyEnc)
	poly1305Sum, polyErr := Poly1305(Md5(ckSumHash), key, true)
	if((StrTrimWhitespaces(poly1305Sum) == "") || (len(poly1305Sum) < 20) || (polyErr != nil)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Failed to get a valid Poly1305 Sum !")
		return ""
	} //end if
	poly1305Sum = Base64Decode(poly1305Sum) // do not trim, is binary data
	if(poly1305Sum == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Failed to process a valid Poly1305 Sum !")
		return ""
	} //end if
	var b85Tweak = StrTrimWhitespaces(BaseEncode([]byte(poly1305Sum), "b85"))
	if((b85Tweak == "") || (len(b85Tweak) < 12)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Failed to get a valid Tweak B85 !")
		return ""
	} //end if
	//--
	var safeTweak string = StrPad2LenRight(StrSubstr(b85Tweak, 0, 16), "`", 16) // 128/8 ; pas with ` as it is only base 85
	//--
	return safeTweak
	//--
} //END FUNCTION


func ThreefishEncryptCBC(str string, key string, useArgon2id bool) string {
	//--
	defer PanicHandler() // req. by hex2bin and cipher encrypt panic handler with wrong padded data
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	str = Base64Encode(str)
	cksum := Sh3a384B64(str)
	str = str + SEPARATOR_CRYPTO_CHECKSUM_V3 + cksum
	//log.Println("[DEBUG] " + CurrentFunctionName() + ": " + str)
	//-- signature
	var theSignature string = ""
	if(useArgon2id == true) {
		theSignature = SIGNATURE_3FISH_V1_ARGON2ID
	} else {
		theSignature = SIGNATURE_3FISH_V1_DEFAULT
	} //end if else
	//-- derived key
	var derivedKey string = threefishSafeKey(key, useArgon2id) // b92, (128 bytes)
	if(len(derivedKey) != 128) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Size must be 128 bytes, and it is:", len(derivedKey))
		return ""
	} //end if
	//-- derived iv
	var iv string = threefishSafeIv(key, useArgon2id) // b92 (128 bytes)
	if(len(iv) != 128) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "iV Size must be 128 bytes")
		return ""
	} //end if
	//-- tweak
	var tweak string = threefishSafeTweak(key) // b85 (16 bytes)
	if(len(tweak) != 16) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Tweak Size must be 16 bytes")
		return ""
	} //end if
	//-- create the cipher
	ecipher, err := threefish.New1024([]byte(derivedKey), []byte(tweak))
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//-- encrypt: CBC
	encStr, encErr := cipherEncryptDataCBC(ecipher, str, iv)
	if(encErr != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Encrypt Error:", encErr)
		return ""
	} //end if
	//--
	return theSignature + DataRRot13(Base64sEncode(Hex2Bin(encStr))) // signature
	//--
} //END FUNCTION


func ThreefishDecryptCBC(str string, key string, useArgon2id bool) string {
	//--
	defer PanicHandler() // req. by hex2bin and crypto decrypt panic handler with malformed data
	//-- check
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//-- signature
	var theSignature string = ""
	if(useArgon2id == true) {
		theSignature = SIGNATURE_3FISH_V1_ARGON2ID
	} else {
		theSignature = SIGNATURE_3FISH_V1_DEFAULT
	} //end if else
	if(StrTrimWhitespaces(theSignature) == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Empty Signature provided")
		return ""
	} //end if
	if(!StrContains(str, theSignature)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Signature was not found")
		return ""
	} //end if
	//-- derived key
	var derivedKey string = threefishSafeKey(key, useArgon2id) // b92, (128 bytes)
	if(len(derivedKey) != 128) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Size must be 128 bytes, and it is:", len(derivedKey))
		return ""
	} //end if
	//-- derived iv
	var iv string = threefishSafeIv(key, useArgon2id) // b92 (128 bytes)
	if(len(iv) != 128) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "iV Size must be 128 bytes")
		return ""
	} //end if
	//-- tweak
	var tweak string = threefishSafeTweak(key) // b85 (16 bytes)
	if(len(tweak) != 16) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Tweak Size must be 16 bytes")
		return ""
	} //end if
	//-- create the cipher
	dcipher, err := threefish.New1024([]byte(derivedKey), []byte(tweak))
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//-- extract data after signature
	sgnArr := ExplodeWithLimit("!", str, 3)
	if(len(sgnArr) != 2) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Invalid Signature Separator")
		return ""
	} //end if
	str = StrTrimWhitespaces(sgnArr[1])
	sgnArr = nil
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": B64s Part not found")
		return ""
	} //end if
	//-- decode and restore back first empty header block
	str = Base64sDecode(DataRRot13(str))
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": B64s Decode Failed")
		return ""
	} //end if
	str = Hex2Bin(strings.Repeat("0", dcipher.BlockSize()*2) + Bin2Hex(str)) // {{{FIX-GOLANG-CIPHER-1ST-NULL-BLOCK-HEADER}}}
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Hex Header Restore and Decode Failed")
		return ""
	} //end if
	//-- decrypt
	var decrypted string = ""
	var errDecrypted error = nil
	decrypted, errDecrypted = cipherDecryptDataCBC(dcipher, str, iv)
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Decrypt Failed:", errDecrypted)
		return ""
	} //end if
	//--
	decrypted, errDecrypted = cryptoContainerUnpack("ThreeFish", 3, decrypted)
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Unpack Failed:", errDecrypted)
		return ""
	} //end if
	//--
	return decrypted
	//--
} //END FUNCTION


//-----


func twofishSafeKey(plainTextKey string) string { // {{{SYNC-CRYPTO-KEY-DERIVE}}}
	//--
	// B92 (32 bytes)
	//-- TODO ...
	return Md5(plainTextKey)
	//--
} //END FUNCTION


func twofishSafeIv(plainTextKey string) string {
	//--
	// B92 (16 bytes)
	//-- TODO ...
	return StrSubstr(Md5(plainTextKey), 0, 16)
	//--
} //END FUNCTION


func TwofishEncryptCBC(str string, key string) string {
	//--
	defer PanicHandler() // req. by hex2bin and cipher encrypt panic handler with wrong padded data
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	str = Base64Encode(str)
//	cksum := Sh3a384B64(str)
//	str = str + SEPARATOR_CRYPTO_CHECKSUM_V3 + cksum
	//log.Println("[DEBUG] " + CurrentFunctionName() + ": " + str)
	//--
//	var theSignature string = SIGNATURE_2FISH_V1_DEFAULT
	var derivedKey string = twofishSafeKey(key) // b92, (32 bytes)
	if(len(derivedKey) != 32) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Size must be 32 bytes")
		return ""
	} //end if
	var iv string = twofishSafeIv(key) // b85 + b92 (16 bytes)
	if(len(iv) != 16) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "iV Size must be 16 bytes")
		return ""
	} //end if
	//-- create the cipher
	ecipher, err := twofish.NewCipher([]byte(derivedKey)) // 32 bytes (256 bit)
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//-- encrypt: CBC
	encStr, encErr := cipherEncryptDataCBC(ecipher, str, iv)
	if(encErr != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Encrypt Error:", encErr)
		return ""
	} //end if
	//--
//	return theSignature + Base64sEncode(Hex2Bin(encStr)) // signature
	return Base64Encode(Hex2Bin(encStr)) // signature
	//--
} //END FUNCTION


//-----


// PRIVATE : Blowfish key @ v1 # ONLY FOR COMPATIBILITY : DECRYPT SUPPORT ONLY
func blowfishV1SafeKey(plainTextKey string) string {
	//--
	var key string = StrTrimWhitespaces(plainTextKey)
	if(key == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty !")
		return ""
	} //end if
	//--
	var safeKey string = StrSubstr(Sha512(key), 13, 29+13) + StrToUpper(StrSubstr(Sha1(key), 13, 10+13)) + StrSubstr(Md5(key), 13, 9+13)
	//--
	//log.Println("[DEBUG] " + CurrentFunctionName() + " (v1):", safeKey)
	return safeKey
	//--
} //END FUNCTION


// PRIVATE : Blowfish iv @ v1 # ONLY FOR COMPATIBILITY : DECRYPT SUPPORT ONLY
func blowfishV1SafeIv(plainTextKey string) string {
	//--
	var key string = StrTrimWhitespaces(plainTextKey)
	if(key == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty !")
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


// PRIVATE : Blowfish key {{{SYNC-BLOWFISH-KEY}}}
func blowfishSafeKey(plainTextKey string) string {
	//--
	defer PanicHandler() // req. by hex2bin panic handler with malformed data
	//--
	var composedKey string = safePassComposedKey(plainTextKey)
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


// PRIVATE : Blowfish iv {{{SYNC-BLOWFISH-IV}}}
func blowfishSafeIv(plainTextKey string) string {
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(key == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty !")
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


func BlowfishEncryptCBC(str string, key string) string {
	//--
	defer PanicHandler() // req. by hex2bin and blowfish encrypt panic handler with wrong padded data
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	str = Base64Encode(str)
	cksum := Sha256B64(str)
	str = str + SEPARATOR_CRYPTO_CHECKSUM_V2 + cksum
	//log.Println("[DEBUG] " + CurrentFunctionName() + ": " + str)
	//--
	var derivedKey string = blowfishSafeKey(key) // 56 bytes
	if(len(derivedKey) != 56) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Size must be 56 bytes")
		return ""
	} //end if
	var iv string = blowfishSafeIv(key) // 8 bytes
	if(len(iv) != 8) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "iV Size must be 128 bytes")
		return ""
	} //end if
	//-- create the cipher
	ecipher, err := blowfish.NewCipher([]byte(derivedKey))
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//-- encrypt: CBC
	encStr, encErr := cipherEncryptDataCBC(ecipher, str, iv)
	if(encErr != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Encrypt Error:", encErr)
		return ""
	} //end if
	//--
	return SIGNATURE_BFISH_V2 + Base64sEncode(Hex2Bin(encStr))
	//--
} //END FUNCTION


func BlowfishDecryptCBC(str string, key string) string {
	//--
	defer PanicHandler() // req. by hex2bin and blowfish decrypt panic handler with malformed data
	//-- check
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//-- signature
	var theSignature string = ""
	var versionDetected uint8 = 0
	if(StrPos(str, SIGNATURE_BFISH_V2) == 0) {
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
	if(StrTrimWhitespaces(theSignature) == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Empty or Invalid Signature")
		return ""
	} //end if
	//-- derived key
	var derivedKey string = ""
	if(versionDetected == 1) { // v1
		derivedKey = blowfishV1SafeKey(key) // 48 bytes
		if(len(derivedKey) != 48) {
			log.Println("[WARNING] " + CurrentFunctionName() + " (v1):", "Derived Key Size must be 48 bytes")
			return ""
		} //end if
	} else { // v2
		derivedKey = blowfishSafeKey(key) // 56 bytes
		if(len(derivedKey) != 56) {
			log.Println("[WARNING] " + CurrentFunctionName() + " (v2):", "Derived Key Size must be 56 bytes")
			return ""
		} //end if
	} //end if else
	//-- derived iv
	var iv string = ""
	if(versionDetected == 1) { // v1
		iv = blowfishV1SafeIv(key) // 8 bytes
	} else { // v2
		iv = blowfishSafeIv(key) // 8 bytes
	} //end if else
	if(len(iv) != 8) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "iV Size must be 128 bytes")
		return ""
	} //end if
	//-- create the cipher
	dcipher, err := blowfish.NewCipher([]byte(derivedKey))
	if(err != nil) {
		//-- fix this. its okay for this tester program, but...
		log.Println("[WARNING] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//-- extract data after signature
	sgnArr := ExplodeWithLimit("!", str, 3)
	if(len(sgnArr) != 2) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Invalid Signature Separator")
		return ""
	} //end if
	str = StrTrimWhitespaces(sgnArr[1])
	sgnArr = nil
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": B64s Part not found")
		return ""
	} //end if
	//-- decode and restore back first empty header block
	if(versionDetected == 1) {
		str = Hex2Bin(strings.Repeat("0", dcipher.BlockSize()*2) + StrToLower(str)) // {{{FIX-GOLANG-CIPHER-1ST-NULL-BLOCK-HEADER}}}
	} else { // v2
		str = Base64sDecode(str)
		str = Hex2Bin(strings.Repeat("0", dcipher.BlockSize()*2) + Bin2Hex(str)) // {{{FIX-GOLANG-CIPHER-1ST-NULL-BLOCK-HEADER}}}
	} //end if else
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Hex Header Restore and Decode Failed")
		return ""
	} //end if
	//-- decrypt
	var decrypted string = ""
	var errDecrypted error = nil
	decrypted, errDecrypted = cipherDecryptDataCBC(dcipher, str, iv)
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Decrypt Failed:", errDecrypted)
		return ""
	} //end if
	//--
	decrypted, errDecrypted = cryptoContainerUnpack("BlowFish", versionDetected, decrypted)
	if(errDecrypted != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Unpack Failed:", errDecrypted)
		return ""
	} //end if
	//--
	return decrypted
	//--
} //END FUNCTION


//-----


// #END
