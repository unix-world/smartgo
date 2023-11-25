
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231124.2232 :: STABLE
// [ CRYPTO ]

// REQUIRE: go 1.17 or later
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

	"github.com/unix-world/smartgo/base32"
	"github.com/unix-world/smartgo/base36"
	"github.com/unix-world/smartgo/base58"
	"github.com/unix-world/smartgo/base62"
	"github.com/unix-world/smartgo/base85"
	"github.com/unix-world/smartgo/base92"
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

	SIGNATURE_PASSWORD_SMART string   		= "sfpass.v2!" 									// curent, v2, smart framework password
	SIGNATURE_PASSWORD_A2ID824 string 		= "a2idpass.v2!" 								// curent, v2, argon2id.824 password

	FIXED_CRYPTO_SALT string 				= "Smart Framework # スマート フレームワーク" 		// fixed salt data for various crypto contexts

	DERIVE_MIN_KLEN uint16 					=    3 											// Key Derive Min Length
	DERIVE_MAX_KLEN uint16 					= 4096 											// Key Derive Min Length

	REGEX_SAFE_HTTP_USER_NAME string 		= `^[a-z0-9\.]+$` 								// Safe UserName Regex
)


//-----


func UserPassDefaultCheck(user string, pass string, requiredUsername string, requiredPassword string) bool {
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
		return false
	} //end if
	return true
}


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
	return StrPad2LenLeft(StrToLower(base36.Encode(hash.Sum(nil))), "0", 7)
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
		customSalt = FIXED_CRYPTO_SALT // dissalow empty salt, fallback to have at least something
	} //end if
	//--
	var b64CkSum string = Sha384B64(plainTextData + "#" + customSalt) // sha384 is a better choice than sha256/sha512 because is more resistant to length attacks
	var rawCkSum string = Base64Decode(b64CkSum)
	//--
	return base62.Encode([]byte(rawCkSum))
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


func SafePassHashSmart(plainPass string, customSalt string) string { // {{{SYNC-HASH-PASSWORD}}} [PHP]
	//--
	// It uses a custom salt + an internally hard-coded salt to avoid rainbow attack
	//--
	// the password salt must not be too complex related to the password itself # http://stackoverflow.com/questions/5482437/md5-hashing-using-password-as-salt
	// nn extraordinary good salt + a weak password may increase the risk of colissions
	// just sensible salt + strong password = safer
	// for passwords the best is to pre-pend the salt: http://stackoverflow.com/questions/4171859/password-salts-prepending-vs-appending
	// for checksuming is better to append the salt to avoid the length extension attack # https://en.wikipedia.org/wiki/Length_extension_attack
	// ex: azA-Z09 pass, prepend needs 26^6 permutations while append 26^10, so append adds more complexity
	// SHA512 is high complexity: O(2^n/2) # http://stackoverflow.com/questions/6776050/how-long-to-brute-force-a-salted-sha-512-hash-salt-provided
	//--
	if((len(plainPass) > 2048) || (len(customSalt) > 2048)) { // {{{SYNC-CRYPTO-KEY-MAX}}}
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Password or Salt is too long !")
		return ""
	} //end if
	//-- // SIGNATURE_PASSWORD_SMART
	var composedKey string = safePassComposedKey(plainPass) // no need for right padding min 7, in smartgo
	var len_composedKey int = len(composedKey)
	var len_trimmed_composedKey int = len(StrTrimWhitespaces(composedKey)) // no need for right padding min 7, in smartgo
	if((len_composedKey != 553) || (len_trimmed_composedKey != 553)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Safe Composed Key is invalid (", len_composedKey, "/", len_trimmed_composedKey, ") !")
		return ""
	} //end if
	//--
	var salt string = Sha512(customSalt + " " + FIXED_CRYPTO_SALT)
	var pass string = Sha512B64(Sha256(salt) + " " + composedKey + " " + salt)
	var minpasslen float64 = math.Ceil(128 / 2 * 1.33)
	if(len(pass) < int(minpasslen)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Password hash must be at least:", minpasslen, "bytes !")
		return ""
	} //end if
	const hashlen int = 128
	var padlen int = hashlen - len(SIGNATURE_PASSWORD_SMART)
	pass = SIGNATURE_PASSWORD_SMART + StrPad2LenRight(pass, "*", padlen) // {{{SYNC-AUTHADM-PASS-PADD}}}
	if(len(pass) != hashlen) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Password hash must be:", hashlen, "bytes !")
		return ""
	} //end if
	//--
	return pass
	//--
} //END FUNCTION


//-----


func Pbkdf2DerivedKey(algo string, key string, salt string, klen uint16, iterations uint16, b92 bool) (string, error) {
	//--
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
		dk = base92.Encode([]byte(dk))
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


func SafePassHashArgon2id824(plainPass string, customSalt string, usePrefix bool) string { // Go lang only, no interchange with PHP
	//--
	// without prefix is 128 bytes
	// with prefix is 160 bytes, extra-padded to fixed length
	//--
	if((len(plainPass) > 2048) || (len(customSalt) > 2048)) { // {{{SYNC-CRYPTO-KEY-MAX}}}
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Password or Salt is too long !")
		return ""
	} //end if
	//--
	var composedKey string = safePassComposedKey(plainPass)
	var len_composedKey int = len(composedKey)
	var len_trimmed_composedKey int = len(StrTrimWhitespaces(composedKey)) // no need for right padding min 7, in smartgo
	if((len_composedKey != 553) || (len_trimmed_composedKey != 553)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Safe Composed Key is invalid (", len_composedKey, "/", len_trimmed_composedKey, ") !")
		return ""
	} //end if
	//--
	var salt string = FIXED_CRYPTO_SALT + NULL_BYTE // use a fixed salt with a safe composed derived key to be safe against colissions ; if the salt is random there is no more safety against colissions ...
	if(customSalt != "") {
		salt = customSalt + " " + salt // prepend
	} //end if
	salt = Bin2Hex(salt)
	salt = base32.Encode([]byte(salt))
	salt = base36.Encode([]byte(salt))
	salt = base58.Encode([]byte(salt))
	salt = base62.Encode([]byte(salt))
	salt = Base64sEncode(salt)
	salt = base85.Encode([]byte(salt))
	salt = Sha384B64(Md5B64(salt) + NULL_BYTE + salt)
	salt = StrSubstr(StrPad2LenRight(salt, "#", 28), 0, 28)
	//fmt.Println("Argon2id Salt:", salt)
	//--
	var key []byte = argon2.IDKey([]byte(composedKey), []byte(salt), 21, 512*1024, 1, 103) // Argon2id resources: 21 cycles, 512MB memory, 1 thread, 103 bytes = 824 bits ; return as base92 encoded with a fixed length of 128 bytes (1024 bits) by padding b92 encoded data on the right with ' character
	//--
	const hashlen int = 128
	var pass string = StrPad2LenRight(base92.Encode(key), "'", hashlen) // add right padding with '
	if(len(pass) != hashlen) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Password hash must be:", hashlen, "bytes !")
		return ""
	} //end if
	//--
	if(usePrefix == true) {
		pass = StrPad2LenRight(SIGNATURE_PASSWORD_A2ID824 + pass, " ", hashlen + 31) + "'" // add prefix and extra padding with spaces and ending '
	} //end if
	//--
	return pass
	//--
} //END FUNCTION


//-----


func cryptoPacketCheckAndDecode(str string, fx string, ver uint8, algo string) string {
	//--
	defer PanicHandler() // req. by b64 decode panic handler with malformed data
	//--
	if((ver != 3) && (ver != 2) && (ver != 1)) {
		log.Println("[NOTICE]", fx, "Invalid Version:", ver, CurrentFunctionName())
		return ""
	} //end if
	//--
	if(str == "") {
		log.Println("[NOTICE]", fx, "Empty Data Packet, v:", ver, CurrentFunctionName())
		return ""
	} //end if
	str = StrTrimWhitespaces(str)
	if(str == "") {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, v:", ver, CurrentFunctionName())
		return ""
	} //end if
	//--
	var separator string = ""
	if(algo == "threefish") {
		if(ver != 3) {
			log.Println("[NOTICE]", fx, "Invalid ThreeFish Version:", ver, CurrentFunctionName())
		} //end if
		separator = SEPARATOR_CRYPTO_CHECKSUM_V3
	} else {
		if(ver == 1) {
			separator = SEPARATOR_CRYPTO_CHECKSUM_V1
		} else if(ver == 2) {
			separator = SEPARATOR_CRYPTO_CHECKSUM_V2
		} else {
			log.Println("[NOTICE]", fx, "Invalid BlowFish Version:", ver, CurrentFunctionName())
		} //end if else
	} //end if else
	if(separator == "") {
		log.Println("[NOTICE]", fx, "Empty Data Packet Checksum Separator, v:", ver, CurrentFunctionName())
		return ""
	} //end if
	//--
	if(!StrContains(str, separator)) {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, no Checksum v:", ver, CurrentFunctionName())
		return ""
	} //end if
	//--
	darr := Explode(separator, str)
	str = ""
	var dlen int = len(darr)
	if(dlen < 2) {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, Checksum not found v:", ver, CurrentFunctionName())
		return ""
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, Checksum is Empty v:", ver, CurrentFunctionName())
		return ""
	} //end if
	if(darr[0] == "") {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, Packed Data not found v:", ver, CurrentFunctionName())
		return ""
	} //end if
	//--
	switch(algo) {
		case "blowfish":
			if(ver == 1) {
				if(Sha1(darr[0]) != darr[1]) {
					log.Println("[NOTICE]", fx, "Invalid Blowfish Data Packet (v.1), Checksum FAILED :: A checksum was found but is invalid:", darr[1], CurrentFunctionName())
					return ""
				} //end if
			} else {
				if(Sha256B64(darr[0]) != darr[1]) {
					log.Println("[NOTICE]", fx, "Invalid Blowfish Data Packet (v.2), Checksum FAILED :: A checksum was found but is invalid:", darr[1], CurrentFunctionName())
					return ""
				} //end if
			} //end if else
			break
		case "threefish":
			if(Sh3a384B64(darr[0]) != darr[1]) {
				log.Println("[NOTICE]", fx, "Invalid Threefish Data Packet (v.*), Checksum FAILED :: A checksum was found but is invalid:", darr[1], CurrentFunctionName())
				return ""
			} //end if
			break
		default:
			log.Println("[NOTICE]", fx, "Invalid Data Packet, Algo `" + algo + "` not found v:", ver, CurrentFunctionName())
			return ""
	} //end switch
	//--
	return Base64Decode(darr[0])
	//--
} //END FUNCTION


//-----


func threefishSafeKey(plainTextKey string) string { // {{{SYNC-CRYPTO-KEY-DERIVE}}}
	//--
	// B92 ; (128 bytes)
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
	var derivedKey string = StrPad2LenLeft(Crc32bB36(composedKey), "0", 8) + "'" + base92.Encode([]byte(Hex2Bin(Sh3a512(composedKey)))) + "'" + base92.Encode([]byte(Hex2Bin(Sh3a224(composedKey))))
	var safeKey string = StrSubstr(StrPad2LenRight(derivedKey, "'", 128), 0, 1024/8) // 1024/8
	//--
//	log.Println("[DEBUG] " + CurrentFunctionName() + ":", safeKey)
	return safeKey
	//--
} //END FUNCTION


func threefishSafeIv(plainTextKey string) string {
	//--
	// B85 + B92 ; (128 bytes)
	//--
	defer PanicHandler() // req. by cipher encrypt panic handler with wrong padded data
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(key == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty !")
		return ""
	} //end if
	//--
	var b64CkSum string = Sh3a384B64(NULL_BYTE + "#" + key) // sha384 is a better choice than sha256/sha512 because is more resistant to length attacks
	var rawCkSum string = Base64Decode(b64CkSum)
	var safeIv string = StrSubstr(base85.Encode([]byte(rawCkSum)) + base92.Encode([]byte(rawCkSum)) + b64CkSum + StrRev(b64CkSum) + Sha384(key), 0, 1024/8) // 1024/8 ; // sha384 is a better choice than sha512 because is more resistant to length attacks
	//--
	//log.Println("[DEBUG] " + CurrentFunctionName() + ":", safeIv)
	return safeIv
	//--
} //END FUNCTION


func threefishSafeTweak(plainTextKey string, derivedKey string) string {
	//--
	// B92 ; (16 bytes)
	//--
	defer PanicHandler() // req. by cipher encrypt panic handler with wrong padded data
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(key == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Key is Empty !")
		return ""
	} //end if
	//--
	if(StrTrimWhitespaces(derivedKey) == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key is Empty !")
		return ""
	} //end if
	//--
	var ckSumCrc32bKeyHex string = Crc32b(key)
	var ckSumCrc32bDKeyHex string = Crc32b(derivedKey)
	var ckSumCrc32bKeyRaw string = Hex2Bin(ckSumCrc32bKeyHex)
	var ckSumCrc32bDKeyRaw string = Hex2Bin(ckSumCrc32bDKeyHex)
	var ckSumCrc32bKeyEnc string = base62.Encode([]byte(ckSumCrc32bKeyRaw + ckSumCrc32bDKeyRaw))
	var ckSumCrc32bDKeyEnc string = base58.Encode([]byte(ckSumCrc32bDKeyRaw + ckSumCrc32bKeyRaw))
	var ckSumHash string = Sh3a512B64(key + NULL_BYTE + FIXED_CRYPTO_SALT + NULL_BYTE + ckSumCrc32bKeyEnc + NULL_BYTE + ckSumCrc32bDKeyEnc)
	poly1305Sum, polyErr := Poly1305(Md5(ckSumHash), key, true)
	if((StrTrimWhitespaces(poly1305Sum) == "") || (len(poly1305Sum) < 20) || (polyErr != nil)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Failed to get a valid Poly1305 Sum !")
		return ""
	} //end if
	poly1305Sum = Base64Decode(poly1305Sum)
	if(poly1305Sum == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Failed to process a valid Poly1305 Sum !")
		return ""
	} //end if
	var b92Tweak = base92.Encode([]byte(poly1305Sum))
	if((b92Tweak == "") || (len(b92Tweak) < 12)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Failed to get a valid Tweak B92 !")
		return ""
	} //end if
	//--
	//log.Println("[DEBUG] " + CurrentFunctionName() + ":", ckSumHash, ckSumCrc32bKeyEnc, ckSumCrc32bDKeyEnc)
	var safeTweak string = StrPad2LenRight(StrSubstr(b92Tweak, 0, 16), "'", 16) // 128/8
	//log.Println("[DEBUG] " + CurrentFunctionName() + ":", safeTweak)
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
	//--
	var theSignature string = ""
	var derivedKey string = "" // 128 bytes
	if(useArgon2id == true) {
		theSignature = SIGNATURE_3FISH_V1_ARGON2ID
		derivedKey = SafePassHashArgon2id824(key, "", false) // b92, don't use prefix (without prefix is 128 bytes)
	} else {
		theSignature = SIGNATURE_3FISH_V1_DEFAULT
		derivedKey = threefishSafeKey(key) // b92, (128 bytes)
	} //end if else
	if(len(derivedKey) != 128) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Size must be 128 bytes")
		return ""
	} //end if
	var iv string = threefishSafeIv(key) // b85 + b92 (128 bytes)
	if(len(iv) != 128) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "iV Size must be 128 bytes")
		return ""
	} //end if
	var tweak string = threefishSafeTweak(key, derivedKey) // b92 (16 bytes)
	if(len(tweak) != 16) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Tweak Size must be 16 bytes")
		return ""
	} //end if
	//--
	block, err := threefish.New1024([]byte(derivedKey), []byte(tweak))
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//fmt.Println("Threefish BlockSize is:", block.BlockSize())
	//-- fix padding
	var slen int = len(str)
	var modulus int = slen % block.BlockSize()
	if(modulus > 0) {
		var padlen int = block.BlockSize() - modulus
		str = StrPad2LenRight(str, " ", slen + padlen) // pad with spaces
		slen = slen + padlen
	} //end if
	//-- encrypt
	ciphertext := make([]byte, block.BlockSize()+slen)
	ecbc := cipher.NewCBCEncrypter(block, []byte(iv))
	ecbc.CryptBlocks(ciphertext[block.BlockSize():], []byte(str))
	str = "" // no more needed
	var encTxt string = StrTrimWhitespaces(Bin2Hex(string(ciphertext))) // prepare output
	ciphertext = nil
	if(StrSubstr(encTxt, 0, block.BlockSize()*2) != strings.Repeat("0", block.BlockSize()*2)) { // {{{FIX-GOLANG-THREEFISH-1ST-128-NULL-BYTES}}}
		log.Println("[WARNING] " + CurrentFunctionName() + ": Invalid Hex Header")
		return ""
	} //end if
	encTxt = StrTrimWhitespaces(StrSubstr(encTxt, block.BlockSize()*2, 0)) // fix: {{{FIX-GOLANG-THREEFISH-1ST-128-NULL-BYTES}}} ; there are 256 trailing zeroes that represent the HEX of 128 null bytes ; remove them
	if(encTxt == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Empty Hex Body") // must be some data after the 128 null bytes null header
		return ""
	} //end if
	//--
	return theSignature + Base64sEncode(Hex2Bin(encTxt)) // signature
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
	//--
	var theSignature string = ""
	var derivedKey string = "" // 128 bytes
	if(useArgon2id == true) {
		theSignature = SIGNATURE_3FISH_V1_ARGON2ID
		derivedKey = SafePassHashArgon2id824(key, "", false) // b92, don't use prefix (without prefix is 128 bytes)
	} else {
		theSignature = SIGNATURE_3FISH_V1_DEFAULT
		derivedKey = threefishSafeKey(key) // b92, (128 bytes)
	} //end if else
	if(len(derivedKey) != 128) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Derived Key Size must be 128 bytes")
		return ""
	} //end if
	var iv string = threefishSafeIv(key) // b85 + b92 (128 bytes)
	if(len(iv) != 128) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "iV Size must be 128 bytes")
		return ""
	} //end if
	var tweak string = threefishSafeTweak(key, derivedKey) // b92 (16 bytes)
	if(len(tweak) != 16) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", "Tweak Size must be 16 bytes")
		return ""
	} //end if
	//--
	block, err := threefish.New1024([]byte(derivedKey), []byte(tweak))
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//--
	if(StrTrimWhitespaces(theSignature) == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Empty Signature provided")
	} //end if
	if(!StrContains(str, theSignature)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Signature was not found")
		return ""
	} //end if
	sgnArr := Explode("!", str)
	str = StrTrimWhitespaces(sgnArr[1])
	sgnArr = nil
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": B64s Part not found")
		return ""
	} //end if
	str = Base64sDecode(str)
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": B64s Decode Failed")
		return ""
	} //end if
	str = Hex2Bin(strings.Repeat("0", block.BlockSize()*2) + Bin2Hex(str)) // fix: {{{FIX-GOLANG-THREEFISH-1ST-128-NULL-BYTES}}} ; add back the 256 trailing null bytes as HEX
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Hex Header Restore and Decode Failed")
		return ""
	} //end if
	//--
	et := []byte(str)
	str = ""
	decrypted := et[block.BlockSize():]
	et = nil
	if(len(decrypted) % block.BlockSize() != 0) { //-- check last slice of encrypted text, if it's not a modulus of cipher block size, it's a problem
		log.Println("[NOTICE] " + CurrentFunctionName() + ": decrypted is not a multiple of block.BlockSize() #", block.BlockSize())
		return ""
	} //end if
	dcbc := cipher.NewCBCDecrypter(block, []byte(iv))
	dcbc.CryptBlocks(decrypted, decrypted)
	//--
	return cryptoPacketCheckAndDecode(string(decrypted), CurrentFunctionName(), 3, "threefish")
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
	//--
	block, err := twofish.NewCipher([]byte(derivedKey)) // 32 bytes (256 bit)
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//fmt.Println("Twofish BlockSize is:", block.BlockSize())
	//-- fix padding
	var slen int = len(str)
	var modulus int = slen % block.BlockSize()
	if(modulus > 0) {
		var padlen int = block.BlockSize() - modulus
		str = StrPad2LenRight(str, " ", slen + padlen) // pad with spaces
		slen = slen + padlen
	} //end if
	//-- encrypt
	ciphertext := make([]byte, block.BlockSize()+slen)
	ecbc := cipher.NewCBCEncrypter(block, []byte(iv))
	ecbc.CryptBlocks(ciphertext[block.BlockSize():], []byte(str))
	str = "" // no more needed
	var encTxt string = StrTrimWhitespaces(Bin2Hex(string(ciphertext))) // prepare output
	ciphertext = nil
	if(StrSubstr(encTxt, 0, block.BlockSize()*2) != strings.Repeat("0", block.BlockSize()*2)) { // {{{FIX-GOLANG-TWOFISH-1ST-32-NULL-BYTES}}}
		log.Println("[WARNING] " + CurrentFunctionName() + ": Invalid Hex Header")
		return ""
	} //end if
	encTxt = StrTrimWhitespaces(StrSubstr(encTxt, block.BlockSize()*2, 0)) // fix: {{{FIX-GOLANG-TWOFISH-1ST-32-NULL-BYTES}}} ; there are 256 trailing zeroes that represent the HEX of 128 null bytes ; remove them
	if(encTxt == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Empty Hex Body") // must be some data after the 32 null bytes null header
		return ""
	} //end if
	//--
//	return theSignature + Base64sEncode(Hex2Bin(encTxt)) // signature
	return Base64Encode(Hex2Bin(encTxt)) // signature
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
	var derivedKey string = base92.Encode([]byte(Hex2Bin(Sha256(composedKey)))) + "'" + base92.Encode([]byte(Hex2Bin(Md5(composedKey))))
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
	//-- fix padding
	var slen int = len(str)
	var modulus int = slen % blowfish.BlockSize
	if(modulus > 0) {
		var padlen int = blowfish.BlockSize - modulus
		str = StrPad2LenRight(str, " ", slen + padlen) // pad with spaces
		slen = slen + padlen
	} //end if
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
	//-- make ciphertext big enough to store data
	ciphertext := make([]byte, blowfish.BlockSize+slen)
	//-- make initialisation vector {{{SYNC-BLOWFISH-IV}}}
	eiv := []byte(iv)
	//-- create the encrypter
	ecbc := cipher.NewCBCEncrypter(ecipher, eiv)
	//-- encrypt the blocks, because block cipher
	ecbc.CryptBlocks(ciphertext[blowfish.BlockSize:], []byte(str))
	str = "" // no more needed
	//-- return ciphertext to calling function
	var encTxt string = StrTrimWhitespaces(Bin2Hex(string(ciphertext)))
	ciphertext = nil
	prePaddingSize := blowfish.BlockSize * 2
	if(StrSubstr(encTxt, 0, prePaddingSize) != strings.Repeat("0", prePaddingSize)) { // {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}}
		log.Println("[WARNING] " + CurrentFunctionName() + ": Invalid Hex Header")
		return ""
	} //end if
	encTxt = StrTrimWhitespaces(StrSubstr(encTxt, prePaddingSize, 0)) // fix: {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}} ; there are 16 trailing zeroes that represent the HEX of 8 null bytes ; remove them
	if(encTxt == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Empty Hex Body") // must be some data after the 8 bytes null header
		return ""
	} //end if
	//--
	return SIGNATURE_BFISH_V2 + Base64sEncode(Hex2Bin(encTxt))
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
	//--
	var versionDetected uint8 = 0
	if(StrPos(str, SIGNATURE_BFISH_V2) == 0) {
		versionDetected = 2
	} else if(StrPos(str, SIGNATURE_BFISH_V1) == 0) {
		versionDetected = 1
	} else {
		str = SIGNATURE_BFISH_V1 + str // if no signature found consider it is v1 and try to dercypt
		versionDetected = 1
	} //end if
	//--
	sgnArr := Explode("!", str)
	str = StrTrimWhitespaces(sgnArr[1])
	sgnArr = nil
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": B64s Part not found")
		return ""
	} //end if
	//--
	prePaddingSize := blowfish.BlockSize * 2
	if(versionDetected == 1) {
		str = Hex2Bin(strings.Repeat("0", prePaddingSize) + StrToLower(str)) // fix: {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}} ; add back the 8 trailing null bytes as HEX
	} else { // v2
		str = Base64sDecode(str)
		str = Hex2Bin(strings.Repeat("0", prePaddingSize) + Bin2Hex(str)) // fix: {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}} ; add back the 8 trailing null bytes as HEX
	} //end if else
	if(str == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Hex Header Restore and Decode Failed")
		return ""
	} //end if
	//-- cast string to bytes
	et := []byte(str)
	str = ""
	//--
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
	//-- make initialisation vector {{{SYNC-BLOWFISH-IV}}}
	div := []byte(iv)
	//-- check last slice of encrypted text, if it's not a modulus of cipher block size, it's a problem
	decrypted := et[blowfish.BlockSize:]
	if(len(decrypted) % blowfish.BlockSize != 0) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": decrypted is not a multiple of blowfish.BlockSize")
		return ""
	} //end if
	//-- ok, all good... create the decrypter
	dcbc := cipher.NewCBCDecrypter(dcipher, div)
	//-- decrypt
	dcbc.CryptBlocks(decrypted, decrypted)
	//--
	return cryptoPacketCheckAndDecode(string(decrypted), CurrentFunctionName(), versionDetected, "blowfish")
	//--
} //END FUNCTION


//-----


// #END
