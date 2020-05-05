
// GO Lang :: SmartGo :: Smart.Framework
// (c) 2020 unix-world.org
// r.20200505.2315 :: STABLE

package smartgo


import (
	"os"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"time"
	"fmt"
	"bytes"
	"strings"
	"strconv"
	"regexp"
	"html"
	"unicode"
	"path/filepath"
	"net/url"
	"encoding/json"
	"encoding/hex"
	"encoding/base64"
	"compress/flate"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/cipher"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"

	"github.com/fatih/color"
)


const (
	DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH = "2006-01-02"
	DATE_TIME_FMT_ISO_STD_GO_EPOCH    = "2006-01-02 15:04:05"
	DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH  = "2006-01-02 15:04:05 -0700"

	DATA_ARCH_SIGNATURE = "PHP.SF.151129/B64.ZLibRaw.HEX"
)


type uxmDateTimeStruct struct {
	Status        string  `json:"status"` 			// OK | ERROR
	ErrMsg        string  `json:"errMsg"` 			// error message (if any if date/time conversion was used)
	Time          int64   `json:"time"` 			// 1607230987 as unix epoch (seconds since unix epoch 1970-01-01 00:00:00), 64-bit integer !!
	DayOfWeekName string  `json:"dayOfWeekName"` 	// "Sunday" .. "Wednesday" .. "Saturday"
	DayOfWeek     int     `json:"dayOfWeek"` 		// 1        .. 4           .. 7
	DayOfYear     int     `json:"dayOfYear"` 		// 1 .. 365(366)
	Year          int     `json:"year"` 			// 2020
	Years         string  `json:"years"` 			// "2020"
	Month         int     `json:"month"` 			// 5
	Months        string  `json:"months"` 			// "05"
	MonthName     string  `json:"monthName"` 		// "May"
	Day           int     `json:"day"` 				// 7
	Days          string  `json:"days"` 			// "07"
	Hour          int     `json:"hour"` 			// 9
	Hours         string  `json:"hours"` 			// "09"
	Minute        int     `json:"minute"` 			// 8
	Minutes       string  `json:"minutes"` 			// "08"
	Second        int     `json:"second"` 			// 1
	Seconds       string  `json:"seconds"` 			// "01"
	NanoSec       int     `json:"nanoSec"` 			// Ex: 709122707
	TzOffset      string  `json:"tzOffset"` 		// "+0000" / "+0300" / ... / "-0700" / ...
	TzName        string  `json:"tzName"` 			// "UTC" | "LOCAL"
}


//-----


// PRIVATE
func parseDateTimeAsStruct(mode string, dateIsoStr string) uxmDateTimeStruct { // mode = UTC | LOCAL
	//--
	dateIsoStr = StrTrimWhitespaces(dateIsoStr)
	if((dateIsoStr == "") || (strIContains(dateIsoStr, "NOW"))) {
		dateIsoStr = ""
	} //end if
	//--
	var currentTime time.Time = time.Now()
	var theError error = nil
	if(dateIsoStr != "") {
		dateIsoArr := Explode(" ", dateIsoStr)
		var dtFormat string = DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH // YYYY-MM-DD
		var isWellFormatedDate bool = true
		if(len(dateIsoArr) == 3) { // YYYY-MM-DD HH:II:SS +ZZZZ
			dtFormat = DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH
		} else if(len(dateIsoArr) == 2) { // YYYY-MM-DD HH:II:SS
			dtFormat = DATE_TIME_FMT_ISO_STD_GO_EPOCH
		} else if(len(dateIsoArr) == 1) { // YYYY-MM-DD
			// OK
		} else {
			isWellFormatedDate = false
		} //end if else
		if(isWellFormatedDate == true) {
			parseTime, err := time.Parse(dtFormat, dateIsoStr)
			if(err != nil) {
				theError = err
			} else {
				currentTime = parseTime
			} //end if
		} else { // error
			theError = errors.New(`Invalid Format for the Input Date/Time: "` + dateIsoStr + `" # Using Now()`)
		} //end if else
	} //end if else
	//--
	if(mode == "UTC") {
		currentTime = currentTime.UTC()
	} else if(mode == "LOCAL") {
		// leave as is
	} else {
		if(theError == nil) { // avoid overwrite if previous error registered
			theError = errors.New("Invalid Parsing Mode `" + mode + "` for Date/Time ... Using `LOCAL`")
		} //end if
	} //end if else
	//--
	var crrYear int = currentTime.Year() // type int
	var crrStrYear string = strconv.Itoa(crrYear)
	//--
	var crrDofY int = currentTime.YearDay()
	//--
	crrDofW := currentTime.Weekday() // type time.Weekday
	var crrDofWInt int = int(crrDofW) // using yota
	var crrDofWName string = crrDofW.String()
	//--
	crrMonth := currentTime.Month() // type time.Month
	crrIntMonth := int(crrMonth)
	var crrStrMonth string = ""
	if(crrIntMonth <= 9) {
		crrStrMonth = "0" + strconv.Itoa(crrIntMonth)
	} else {
		crrStrMonth = ""  + strconv.Itoa(crrIntMonth)
	} //end if else
	var crrNameOfMonth string = crrMonth.String()
	//--
	var crrDay int = currentTime.Day()
	var crrStrDay string = ""
	if(crrDay <= 9) {
		crrStrDay = "0" + strconv.Itoa(crrDay)
	} else {
		crrStrDay = ""  + strconv.Itoa(crrDay)
	} //end if else
	//--
	var crrHour int = int(currentTime.Hour())
	var crrStrHour string = ""
	if(crrHour <= 9) {
		crrStrHour = "0" + strconv.Itoa(crrHour)
	} else {
		crrStrHour = ""  + strconv.Itoa(crrHour)
	} //end if else
	//--
	var crrMinute int = int(currentTime.Minute())
	var crrStrMinute = ""
	if(crrMinute <= 9) {
		crrStrMinute = "0" + strconv.Itoa(crrMinute)
	} else {
		crrStrMinute = ""  + strconv.Itoa(crrMinute)
	} //end if else
	//--
	var crrSecond int = int(currentTime.Second())
	var crrStrSecond string = ""
	if(crrSecond <= 9) {
		crrStrSecond = "0" + strconv.Itoa(crrSecond)
	} else {
		crrStrSecond = ""  + strconv.Itoa(crrSecond)
	} //end if
	//--
	var crrDTimeFmt string = currentTime.Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
	arrDTimeFmt := Explode(" ", crrDTimeFmt)
	var crrStrTzOffs string = StrTrimWhitespaces(arrDTimeFmt[2])
	//--
	var unixTimeStamp64 int64 = int64(currentTime.Unix())
	var nanoSec int = int(currentTime.Nanosecond())
	//--
	var theStatus string = "OK"
	var theErrMsg string = ""
	if(theError != nil) {
		theErrMsg = string(theError.Error())
	} //end if
	if(theErrMsg != "") {
		theStatus = "ERROR"
		theErrMsg = StrReplaceAll(theErrMsg, `"`, "`")
	} //end if
	//--
	uxmDTStruct := uxmDateTimeStruct {
		Status        : theStatus,
		ErrMsg        : theErrMsg,
		Time          : unixTimeStamp64, // int64
		DayOfWeekName : crrDofWName,
		DayOfWeek     : (crrDofWInt + 1), // 1..7 (instead of 0..6)
		DayOfYear     : crrDofY,
		Year          : crrYear,
		Years         : crrStrYear,
		Month         : crrIntMonth,
		Months        : crrStrMonth,
		MonthName     : crrNameOfMonth,
		Day           : crrDay,
		Days          : crrStrDay,
		Hour          : crrHour,
		Hours         : crrStrHour,
		Minute        : crrMinute,
		Minutes       : crrStrMinute,
		Second        : crrSecond,
		Seconds       : crrStrSecond,
		NanoSec       : nanoSec,
		TzOffset      : crrStrTzOffs,
		TzName        : mode,
	}
	//--
	return uxmDTStruct
	//--
} //END FUNCTION


func DateTimeStructUtc(dateIsoStr string) uxmDateTimeStruct {
	//--
	return parseDateTimeAsStruct("UTC", dateIsoStr)
	//--
} //END FUNCTION


func DateNowUtc() string { // YYYY-MM-DD HH:II:SS +ZZZZ
	//--
	return time.Now().UTC().Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
	//--
} //END FUNCTION


func DateNowIsoUtc() string { // YYYY-MM-DD HH:II:SS
	//--
	return time.Now().UTC().Format(DATE_TIME_FMT_ISO_STD_GO_EPOCH)
	//--
} //END FUNCTION


func DateTimeStructLocal(dateIsoStr string) uxmDateTimeStruct {
	//--
	return parseDateTimeAsStruct("LOCAL", dateIsoStr)
	//--
} //END FUNCTION


func DateNowLocal() string { // YYYY-MM-DD HH:II:SS +ZZZZ
	//--
	return time.Now().Format(DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH)
	//--
} //END FUNCTION


func DateNowIsoLocal() string { // YYYY-MM-DD HH:II:SS
	//--
	return time.Now().Format(DATE_TIME_FMT_ISO_STD_GO_EPOCH)
	//--
} //END FUNCTION


//-----


//===== Custom Logger with Colors
type logWriterWithColors struct {}
func (writer logWriterWithColors) Write(bytes []byte) (int, error) {
	return fmt.Print(color.HiRedString("[LOG] | " + DateNowUtc() + " | " + string(bytes)))
} //END FUNCTION
func LogToConsoleWithColors() {
	log.SetFlags(0)
	log.SetOutput(new(logWriterWithColors))
} //END FUNCTION
//===== #


//-----


// PRIVATE
func blowfishChecksizeAndPad(str string, chr byte) string {
	//--
	// check the size of plaintext, does it need to be padded? because
	// blowfish is a block cipher, the plaintext needs to be padded to
	// a multiple of the blocksize.
	//--
	// INFO: chr = 32 is SPACE (for encrypt) ; chr = 0 is NULL (for decrypt)
	if(chr != 32) {
		chr = 0
	} //end if
	//--
	pt := []byte(str)
	//-- calculate modulus of plaintext to blowfish's cipher block size
	modulus := len(pt) % blowfish.BlockSize
	//-- if result is not 0, then need to pad
	if modulus != 0 {
		//-- how many bytes do we need to pad to make pt to be a multiple of blowfish's block size?
		padlen := blowfish.BlockSize - modulus
		//-- let's add the required padding
		for i := 0; i < padlen; i++ {
			//-- add the pad, one at a time
			pt = append(pt, chr) // if string is base64 encoded can pad with SPACE (32) otherwise must pad with NULL (0)
			//--
		} //end for
		//--
	} //end if
	//-- return the whole-multiple-of-blowfish.BlockSize-sized plaintext to the calling function
	return string(pt)
	//--
} //END FUNCTION


// PRIVATE : Blowfish key {{{SYNC-BLOWFISH-KEY}}}
func blowfishSafeKey(key string) string {
	//--
	var safeKey string = StrGetAsciiSubstring(Sha512(key), 13, 29+13) + strings.ToUpper(StrGetAsciiSubstring(Sha1(key), 13, 10+13)) + StrGetAsciiSubstring(Md5(key), 13, 9+13)
	//--
	//log.Println("BfKey: " + safeKey)
	return safeKey
	//--
} //END FUNCTION


// PRIVATE : Blowfish iv {{{SYNC-BLOWFISH-IV}}}
func blowfishSafeIv(key string) string {
	//--
	var safeIv string = Base64Encode(Sha1("@Smart.Framework-Crypto/BlowFish:" + key + "#" + Sha1("BlowFish-iv-SHA1" + key) + "-" + strings.ToUpper(Md5("BlowFish-iv-MD5" + key)) + "#"))
	safeIv = StrGetAsciiSubstring(safeIv, 1, 8+1)
	//log.Println("BfIv: " + safeIv)
	//--
	return safeIv
	//--
} //END FUNCTION


func BlowfishEncryptCBC(str string, key string) string {
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	str = Base64Encode(str)
	cksum := Sha1(str)
	str = str + "#CHECKSUM-SHA1#" + cksum
	//log.Println("BfTxt: " + str)
	//-- cast to bytes
	ppt := []byte(blowfishChecksizeAndPad(str, 32)) // pad with spaces
	str = "" // no more needed
	//-- create the cipher
	ecipher, err := blowfish.NewCipher([]byte(blowfishSafeKey(key)))
	if(err != nil) {
		log.Println("WARNING: BlowfishEncryptCBC: ", err)
		return ""
	} //end if
	//-- make ciphertext big enough to store len(ppt)+blowfish.BlockSize
	ciphertext := make([]byte, blowfish.BlockSize+len(ppt))
	//-- make initialisation vector {{{SYNC-BLOWFISH-IV}}}
	eiv := []byte(blowfishSafeIv(key))
	//-- create the encrypter
	ecbc := cipher.NewCBCEncrypter(ecipher, eiv)
	//-- encrypt the blocks, because block cipher
	ecbc.CryptBlocks(ciphertext[blowfish.BlockSize:], ppt)
	//-- return ciphertext to calling function
	var encTxt string = StrTrimWhitespaces(strings.ToUpper(Bin2Hex(string(ciphertext))))
	ciphertext = nil
	if(StrGetAsciiSubstring(encTxt, 0, 16) != "0000000000000000") { // {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}}
		log.Println("WARNING: BlowfishEncryptCBC: Invalid Hex Header")
		return ""
	} //end if
	encTxt = StrGetAsciiSubstring(encTxt, 16, 0) // fix: {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}} ; there are 16 trailing zeroes that represent the HEX of 8 null bytes ; remove them
	if(encTxt == "") {
		log.Println("WARNING: BlowfishEncryptCBC: Empty Hex Body") // must be some data after the 8 bytes null header
		return ""
	} //end if
	//--
	return encTxt
	//--
} //END FUNCTION


func BlowfishDecryptCBC(str string, key string) string {
	//-- check
	if(str == "") {
		return ""
	} //end if
	str = strings.ToLower(StrTrimWhitespaces(str))
	str = Hex2Bin("0000000000000000" + str) // fix: {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}} ; add back the 8 trailing null bytes as HEX
	if(str == "") {
		return ""
	} //end if
	//-- cast string to bytes
	et := []byte(str)
	//-- create the cipher
	dcipher, err := blowfish.NewCipher([]byte(blowfishSafeKey(key)))
	if(err != nil) {
		//-- fix this. its okay for this tester program, but...
		log.Println("WARNING: BlowfishDecryptCBC: ", err)
		return ""
	} //end if
	//-- make initialisation vector {{{SYNC-BLOWFISH-IV}}}
	div := []byte(blowfishSafeIv(key))
	//-- check last slice of encrypted text, if it's not a modulus of cipher block size, we're in trouble
	decrypted := et[blowfish.BlockSize:]
	if(len(decrypted)%blowfish.BlockSize != 0) {
		log.Println("NOTICE: BlowfishDecryptCBC: decrypted is not a multiple of blowfish.BlockSize")
		return ""
	} //end if
	//-- ok, all good... create the decrypter
	dcbc := cipher.NewCBCDecrypter(dcipher, div)
	//-- decrypt
	dcbc.CryptBlocks(decrypted, decrypted)
	//--
	str = string(decrypted)
	decrypted = nil
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		log.Println("NOTICE: Invalid BlowFishCBC Data, Empty Data after Decrypt")
		return ""
	} //end if
	if(!strContains(str, "#CHECKSUM-SHA1#")) {
		log.Println("NOTICE: Invalid BlowFishCBC Data, no Checksum")
		return ""
	} //end if
	//--
	darr := Explode("#CHECKSUM-SHA1#", str)
	var dlen int = len(darr)
	if(dlen < 2) {
		log.Println("NOTICE: Invalid BlowFishCBC Data, Checksum not found")
		return ""
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		log.Println("NOTICE: Invalid BlowFishCBC Data, Checksum is Empty")
		return ""
	} //end if
	if(darr[0] == "") {
		log.Println("NOTICE: Invalid BlowFishCBC Data, Encrypted Data not found")
		return ""
	} //end if
	if(Sha1(darr[0]) != darr[1]) {
		log.Println("NOTICE: BlowfishDecryptCBC // Invalid Packet, Checksum FAILED :: A checksum was found but is invalid")
		return ""
	} //end if
	str = Base64Decode(darr[0])
	darr = nil
	//--
	return str
	//--
} //END FUNCTION


//-----


func GzDeflate(str string, level int) string {
	//--
	if(level < 1 || level > 9) {
		level = -1 // zlib default compression
	} //end if
	//--
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, level) // RFC 1951
	//--
	if(err != nil) {
		log.Println("NOTICE: GzDeflate: ", err)
		return ""
	} //end if
	//--
	w.Write([]byte(str))
	w.Close()
	//--
	return b.String()
	//--
} //END FUNCTION


func GzInflate(str string) string {
	//--
	b := bytes.NewReader([]byte(str))
	r := flate.NewReader(b)
	bb2 := new(bytes.Buffer)
	_, _ = io.Copy(bb2, r)
	r.Close()
	byts := bb2.Bytes()
	//--
	return string(byts)
	//--
} //END FUNCTION


//-----


func DataUnArchive(str string) string {
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	arr := Explode("\n", str)
	var alen int = len(arr)
	//--
	arr[0] = StrTrimWhitespaces(arr[0])
	if(arr[0] == "") {
		log.Println("NOTICE: Data Unarchive // Invalid Package Format")
		return ""
	} //end if
	//--
	if(alen < 2) {
		log.Println("NOTICE: Data Unarchive // Empty Package Signature")
	} else {
		arr[1] = StrTrimWhitespaces(arr[1])
		if(arr[1] != DATA_ARCH_SIGNATURE) {
			log.Println("NOTICE: Data Unarchive // Invalid Package Signature: ", arr[1])
		} //end if
	} //end if
	//--
	arr[0] = Base64Decode(arr[0])
	if(arr[0] == "") {
		log.Println("NOTICE: Data Unarchive // Invalid B64 Data for packet with signature: ", arr[1])
		return ""
	} //end if
	//--
	arr[0] = GzInflate(arr[0])
	if(arr[0] == "") {
		log.Println("NOTICE: Data Unarchive // Invalid Zlib GzInflate Data for packet with signature: ", arr[1])
		return ""
	} //end if
	//--
	const txtErrExpl = "This can occur if decompression failed or an invalid packet has been assigned ..."
	//--
	if(!strContains(arr[0], "#CHECKSUM-SHA1#")) {
		log.Println("NOTICE: Invalid Packet, no Checksum :: ", txtErrExpl)
		return ""
	} //end if
	//--
	darr := Explode("#CHECKSUM-SHA1#", arr[0])
	var dlen int = len(darr)
	if(dlen < 2) {
		log.Println("NOTICE: Invalid Packet, Checksum not found :: ", txtErrExpl)
		return ""
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		log.Println("NOTICE: Invalid Packet, Checksum is Empty :: ", txtErrExpl)
		return ""
	} //end if
	if(darr[0] == "") {
		log.Println("NOTICE: Invalid Packet, Data not found :: ", txtErrExpl)
		return ""
	} //end if
	//--
	darr[0] = Hex2Bin(strings.ToLower(darr[0]))
	if(darr[0] == "") {
		log.Println("NOTICE: Data Unarchive // Invalid HEX Data for packet with signature: ", arr[1])
		return ""
	} //end if
	//--
	if(Sha1(darr[0]) != darr[1]) {
		log.Println("NOTICE: Data Unarchive // Invalid Packet, Checksum FAILED :: A checksum was found but is invalid: ", darr[1])
		return ""
	} //end if
	//--
	return darr[0]
	//--
} //END FUNCTION


func DataArchive(str string) string {
	//--
	var ulen int = len(str)
	//--
	if((str == "") || (ulen <= 0)) {
		return ""
	} //end if
	//--
	var chksum string = Sha1(str)
	//--
	var data string = StrTrimWhitespaces(strings.ToUpper(Bin2Hex(str))) + "#CHECKSUM-SHA1#" + chksum
	//--
	var arch string = GzDeflate(data, -1)
	var alen int = len(arch)
	//--
	if((arch == "") || (alen <= 0)) { // check also division by zero
		log.Println("ERROR: Data Archive // ZLib Deflated Data is Empty")
		return ""
	} //end if
	//--
	var ratio = float64(ulen) / float64(alen) // division by zero is checked above by (alen <= 0)
	if(ratio <= 0) {
		log.Println("ERROR: Data Archive // ZLib Data Ratio is zero: ", ratio)
		return ""
	} //end if
	if(ratio > 32768) { // check for this bug in ZLib {{{SYNC-GZ-ARCHIVE-ERR-CHECK}}}
		log.Println("ERROR: Data Archive // ZLib Data Ratio is higher than 32768: ", ratio)
		return ""
	} //end if
//	log.Println("INFO: Data Archive // ZLib Data Ratio is: ", ratio, " by division of: ", ulen, " with: (/) ", alen)
	//--
	arch = StrTrimWhitespaces(Base64Encode(arch)) + "\n" + DATA_ARCH_SIGNATURE
	//--
	var unarch_chksum string = Sha1(DataUnArchive(arch))
	if(unarch_chksum != chksum) {
		log.Println("ERROR: Data Archive // Data Encode Check Failed")
		return ""
	} //end if
	//--
	return arch
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
	decoded, err := base64.StdEncoding.DecodeString(data)
	if(err != nil) {
		log.Println("NOTICE: Base64Decode: ", err)
		//return "" // be flexible, don't return, try to decode as much as possible ...
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


func Md5(str string) string {
	//--
	hash := md5.New()
	io.WriteString(hash, str)
	//--
//	return strings.ToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return strings.ToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha1(str string) string {
	//--
	hash := sha1.New()
	hash.Write([]byte(str))
	//--
//	return strings.ToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return strings.ToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha256(str string) string {
	//--
	hash := sha256.New()
	//--
	hash.Write([]byte(str))
	//--
//	return strings.ToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return strings.ToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha384(str string) string {
	//--
	hash := sha512.New384()
	//--
	hash.Write([]byte(str))
	//--
//	return strings.ToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return strings.ToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


func Sha512(str string) string {
	//--
	hash := sha512.New()
	//--
	hash.Write([]byte(str))
	//--
//	return strings.ToLower(fmt.Sprintf("%x", hash.Sum(nil)))
	return strings.ToLower(hex.EncodeToString(hash.Sum(nil)))
	//--
} //END FUNCTION


//------


func Explode(delimiter string, text string) []string {
	//--
	return strings.Split(text, delimiter)
	//--
} //END FUNCTION


func Implode(glue string, pieces []string) string {
	//--
	return strings.Join(pieces, glue)
	//--
} //END FUNCTION


func strContains(str string, part string) bool {
	//--
	return strings.Contains(str, part)
	//--
} //END FUNCTION


func strIContains(str string, part string) bool {
	//--
	return strings.Contains(strings.ToLower(str), strings.ToLower(part))
	//--
} //END FUNCTION


func StrTrimWhitespaces(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
//	s = strings.TrimSpace(s) // TrimSpace returns a slice of the string s, with all leading and trailing white space removed, as defined by Unicode. Not sure if contain also \x00 and \x0B ...
	s = strings.Trim(s, " \t\n\r\x00\x0B") // this is compatible with PHP (not sure if above is quite compatible since there is no clear reference wich are the exact whitespaces it trims)
	//--
	return s
	//--
} //END FUNCTION


func StrReplaceAll(s string, part string, replacement string) string {
	//--
	return strings.ReplaceAll(s, part, replacement)
	//--
} //END FUNCTION


func StrReplaceWithLimit(s string, part string, replacement string, limit int) string {
	//--
	return strings.Replace(s, part, replacement, limit) // if (limit == -1) will replace all
	//--
} //END FUNCTION


func TextCutByLimit(s string, length int) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	if(length < 5) {
		length = 5
	} //end if
	//--
	max := len(s)
	if(length >= max) {
		return s
	} //end if
	//--
	s = StrGetUnicodeSubstring(s, 0, length - 3) // substract -3 because of the trailing dots ...
	s = RegexReplaceAllStr(`\s+?(\S+)?$`, s, "") // {{{SYNC-REGEX-TEXT-CUTOFF}}}
	s = s + "..." // add trailing dots
	//--
	return s
	//--
} //END FUNCTION


func StrGetUnicodeSubstring(s string, start int, stop int) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	runes := []rune(s)
	max := len(runes)
	//--
	if(start < 0) {
		start = 0
	} //end if
	if((stop <= 0) || (stop > max)) {
		stop = max
	} //end if
	//--
	return string(runes[start:stop])
	//--
} //END FUNCTION


func StrGetAsciiSubstring(s string, start int, stop int) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	max := len(s)
	//--
	if(start < 0) {
		start = 0
	} //end if
	if((stop <= 0) || (stop > max)) {
		stop = max
	} //end if
	//--
	return string(s[start:stop])
	//--
} //END FUNCTION


func ParseStringAsBoolStr(s string) string {
	//--
	if((s != "") && (s != "0")) { // fix PHP and Javascript as syntax if(tmp_marker_val){}
		s = "true"
	} else {
		s = "false"
	} //end if else
	//--
	return s
	//--
} //END FUNCTION


func ParseIntegerStrAsInt(s string) int {
	//--
	var Int int = 0 // set the integer as zero Int, in the case of parseInt Error
	if tmpInt, convErr := strconv.Atoi(s); convErr == nil {
		Int = tmpInt
	} //end if else
	//--
	return Int
	//--
} //END FUNCTION


func ParseInteger64AsStr(s string) string {
	//--
	if tmpInt, convErr := strconv.ParseInt(s, 10, 64); convErr == nil {
		s = strconv.FormatInt(tmpInt, 10)
	} else {
		s = "0" // set the integer as zero (string), in the case of parseInt Error
	} //end if else
	//--
	return s
	//--
} //END FUNCTION


func ParseFloatAsStrDecimal(s string, d int) string {
	//--
	if(d < 1) {
		d = 1
	} else if(d > 8) {
		d = 8
	} //end if else
	//--
	var f float64 = 0
	if tmpFlt, convErr := strconv.ParseFloat(s, 64); convErr == nil {
		f = tmpFlt
	} //end if
	s = fmt.Sprintf("%." + strconv.Itoa(d) + "f", f)
	//--
	return string(s)
	//--
} //END FUNCTION


func ParseFloatAsStrFloat(s string) string {
	//--
	var f float64 = 0
	if tmpFlt, convErr := strconv.ParseFloat(s, 64); convErr == nil {
		f = tmpFlt
	} //end if
	//--
	s = strconv.FormatFloat(f, 'g', 14, 64) // use precision 14 as in PHP
	//--
	return string(s)
	//--
} //END FUNCTION


//== PRIVATE
func isUnicodeNonspacingMarks(r rune) bool {
	//--
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
	//--
} //END FUNCTION
//==


func StrDeaccent(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	t := transform.Chain(norm.NFD, transform.RemoveFunc(isUnicodeNonspacingMarks), norm.NFC)
	//--
	result, _, _ := transform.String(t, s)
	//--
	return string(result)
	//--
} //END FUNCTION


func RegexReplaceAllStr(rexpr string, s string, repl string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	re := regexp.MustCompile(rexpr)
	return string(re.ReplaceAllString(s, repl))
	//--
} //END FUNCTION


func StrCreateSlug(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	s = StrDeaccent(s)
	//--
	s = RegexReplaceAllStr(`[^a-zA-Z0-9_\-]`, s, "-")
	s = RegexReplaceAllStr(`[\-]+`, s, "-") // suppress multiple -
	s = StrTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func StrCreateHtmId(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	//--
	s = RegexReplaceAllStr(`[^a-zA-Z0-9_\-]`, s, "")
	s = StrTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


func StrCreateJsVarName(s string) string {
	//--
	s = StrTrimWhitespaces(s)
	if(s == "") {
		return ""
	} //end if
	//--
	s = RegexReplaceAllStr(`[^a-zA-Z0-9_]`, s, "")
	s = StrTrimWhitespaces(s)
	//--
	return s
	//--
} //END FUNCTION


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
	decoded, err := hex.DecodeString(str)
	if(err != nil) {
		log.Println("NOTICE: Hex2Bin: ", err)
		//return "" // be flexible, don't return, try to decode as much as possible ...
	} //end if
	//--
	return string(decoded)
	//--
} //END FUNCTION


func JsonEncode(data interface{}) string { // inspired from: https://www.php2golang.com/method/function.json-encode.html
	//--
	jsons, err := json.Marshal(data)
	if(err != nil) {
		log.Println("NOTICE: JsonEncode: ", err)
		return ""
	} //end if
	//--
	var safeJson string = string(jsons)
	jsons = nil
	//-- this JSON string are replaced by Marshall, but just in case try to replace them if Marshall fail ; they will not be 100% like the one produced via PHP with HTML-Safe arguments but at least have the minimum escapes to avoid conflicting HTML tags
	safeJson = StrReplaceAll(safeJson, "&", "\\u0026") 		// & 	JSON_HEX_AMP                           ; already done by json.Marshal, but let in just in case if Marshall fails
	safeJson = StrReplaceAll(safeJson, "<", "\\u003C") 		// < 	JSON_HEX_TAG (use uppercase as in PHP) ; already done by json.Marshal, but let in just in case if Marshall fails
	safeJson = StrReplaceAll(safeJson, ">", "\\u003E") 		// > 	JSON_HEX_TAG (use uppercase as in PHP) ; already done by json.Marshal, but let in just in case if Marshall fails
	//-- these three are not done by json.Marshal
	safeJson = StrReplaceAll(safeJson, "/", "\\/") 			// / 	JSON_UNESCAPED_SLASHES
	safeJson = StrReplaceAll(safeJson, "\\\"", "\\u0022") 	// \" 	JSON_HEX_QUOT
	safeJson = StrTrimWhitespaces(safeJson)
	//-- Fixes: the JSON Marshall does not make the JSON to be HTML-Safe, thus we need several minimal replacements: https://www.drupal.org/node/479368 + escape / (slash)
	var out bytes.Buffer
	json.HTMLEscape(&out, []byte(safeJson)) // just in case, HTMLEscape appends to dst the JSON-encoded src with <, >, &, U+2028 and U+2029 characters inside string literals changed to \u003c, \u003e, \u0026, \u2028, \u2029 so that the JSON will be safe to embed inside HTML
	safeJson = ""
	return out.String()
	//--
} //END FUNCTION


func JsonDecode(data string) map[string]interface{} { // inspired from: https://www.php2golang.com/method/function.json-decode.html
	//--
	if(data == "") {
		return nil
	} //end if
	//--
	var dat map[string]interface{}
	err := json.Unmarshal([]byte(data), &dat)
	if(err != nil) {
		//log.Println("NOTICE: JsonDecode: ", err)
		return nil
	} //end if
	//--
	return dat
	//--
} //END FUNCTION


func RawUrlEncode(s string) string {
	//--
	return StrReplaceAll(url.QueryEscape(s), "+", "%20")
	//--
} //END FUNCTION


func EscapeHtml(s string) string { // provides a Smart.Framework ~ EscapeHtml
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return html.EscapeString(s) // escapes these five characters: < > & ' "
	//--
} //END FUNCTION


func EscapeCss(s string) string { // CSS provides a Twig-compatible CSS escaper
	//--
	var out = &bytes.Buffer{}
	//--
	for _, c := range s {
		if((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57)) {
			out.WriteRune(c) // a-zA-Z0-9
		} else {
			fmt.Fprintf(out, "\\%04X", c) // UTF-8
		} //end if else
	} //end for
	//--
	return out.String()
	//--
} //END FUNCTION


func EscapeJs(in string) string { // provides a Smart.Framework ~ EscapeJs
	//-- Test
	// RAW: "1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\"'~`!@#$%^&*()+=[]{}|\\<>,.?/\t\r\n"
	// GO :  1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\u0022\u0027~`!@#$%^\u0026*()+=[]{}|\\\u003C\u003E,.?\/\t\r\n
	// PHP:  1234567890_ abcdefghijklmnopqrstuvwxyz-ABCDEFGHIJKLMNOPQRSTUVWXYZ:;\u0022\u0027~`!@#$%^\u0026*()+=[]{}|\\\u003C\u003E,.?\/\t\r\n
	//--
	var out = &bytes.Buffer{}
	//--
	for _, c := range in {
		// chars: ASCII 32..126, but not 127 [DELETE] ; exclude: 34 ["] ; 38 [&] ; 39 ['] ; 47 [SLASH/] ; 60 [<] ; 62 [>] ; 92 [BACKSLASH]
		if((c >= 32) && (c <= 126) && (c != 34) && (c != 38) && (c != 39) && (c != 47) && (c != 60) && (c != 62) && (c != 92)) {
			out.WriteRune(c)
		} else if(c == 47) {   // SLASH/ = backslash + slash
			out.WriteRune(92)  // backslash
			out.WriteRune(c)   // slash
		} else if(c == 92) {   // BACKSLASH = backslash + backslash
			out.WriteRune(c)   // backslash
			out.WriteRune(c)   // backslash
		} else if(c == 9) {    // TAB as \t
			out.WriteRune(92)  // backslash
			out.WriteRune(116) // t
		} else if(c == 10) {   // LF as \n
			out.WriteRune(92)  // backslash
			out.WriteRune(110) // n
		} else if(c == 13) {   // CR as \r
			out.WriteRune(92)  // backslash
			out.WriteRune(114) // r
		} else {
			fmt.Fprintf(out, "\\u%04X", c) // UTF-8
		} //end if else
	} //end for
	//--
	return out.String()
	//--
} //END FUNCTION


func StrNl2Br(s string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = StrReplaceAll(s, "\r\n", "<br>")
	s = StrReplaceAll(s, "\r", "<br>")
	s = StrReplaceAll(s, "\n", "<br>")
	//--
	return s
	//--
} //END FUNCTION


//-----


func PathBaseName(filePath string) string {
	//--
	return filepath.Base(filePath)
	//--
} //END FUNCTION


func PathIsAbsolute(filePath string) bool {
	//--
	if(
		(StrGetAsciiSubstring(filePath, 0, 1) == "/") || // unix / linux
		(StrGetAsciiSubstring(filePath, 0, 1) == ":") || // windows
		(StrGetAsciiSubstring(filePath, 1, 2) == ":")) { // windows
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func PathIsBackwardUnsafe(filePath string) bool {
	//--
	if(
		strContains(filePath, "/../") ||
		strContains(filePath, "/./")  ||
		strContains(filePath, "/..")  ||
		strContains(filePath, "../")) {
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func ReadSafePathFile(filePath string, allowAbsolutePath bool) (fileContent string, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return "", errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return "", errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return "", errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	content, err := ioutil.ReadFile(filePath)
	if(err != nil) {
		return "", err.Error()
	} //end if
	//--
	return string(content), ""
	//--
} //END FUNCTION


func PathIsDir(thePath string) bool {
	//--
	fd, err := os.Stat(thePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return false
		} //end if
	} //end if
	//--
	fm := fd.Mode()
	//--
	return fm.IsDir()
	//--
} //END FUNCTION


func PathIsFile(thePath string) bool {
	//--
	fd, err := os.Stat(thePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return false
		} //end if
	} //end if
	//--
	fm := fd.Mode()
	//--
	return ! fm.IsDir()
	//--
} //END FUNCTION


func PathExists(thePath string) bool {
	//--
	_, err := os.Stat(thePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return false
		} //end if
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func PrepareNosyntaxHtmlMarkersTpl(tpl string) string {
	//--
	if(tpl == "") {
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "[###", "&lbrack;###")
	tpl = StrReplaceAll(tpl, "###]", "###&rbrack;")
	tpl = StrReplaceAll(tpl, "[%%%", "&lbrack;%%%")
	tpl = StrReplaceAll(tpl, "%%%]", "%%%&rbrack;")
	tpl = StrReplaceAll(tpl, "[@@@", "&lbrack;@@@")
	tpl = StrReplaceAll(tpl, "@@@]", "@@@&rbrack;")
	tpl = StrReplaceAll(tpl, "［###", "&lbrack;###")
	tpl = StrReplaceAll(tpl, "###］", "###&rbrack;")
	tpl = StrReplaceAll(tpl, "［%%%", "&lbrack;%%%")
	tpl = StrReplaceAll(tpl, "%%%］", "%%%&rbrack;")
	tpl = StrReplaceAll(tpl, "［@@@", "&lbrack;@@@")
	tpl = StrReplaceAll(tpl, "@@@］", "@@@&rbrack;")
	//--
	return tpl
	//--
} //END FUNCTION


func PrepareNosyntaxContentMarkersTpl(tpl string) string {
	//--
	if(tpl == "") {
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "[###", "［###")
	tpl = StrReplaceAll(tpl, "###]", "###］")
	tpl = StrReplaceAll(tpl, "[%%%", "［%%%")
	tpl = StrReplaceAll(tpl, "%%%]", "%%%］")
	tpl = StrReplaceAll(tpl, "[@@@", "［@@@")
	tpl = StrReplaceAll(tpl, "@@@]", "@@@］")
	//--
	return tpl
	//--
} //END FUNCTION


func RenderMarkersTpl(template string, arrobj map[string]string, isEncoded bool, revertSyntax bool) string { // r.20200121
	//-- replace out comments
	if((strContains(template, "[%%%COMMENT%%%]")) && (strContains(template, "[%%%/COMMENT%%%]"))) {
		template = RegexReplaceAllStr(`(?sU)\s?\[%%%COMMENT%%%\](.*)?\[%%%\/COMMENT%%%\]\s?`, template, "") // regex syntax as in PHP
	} //end if
	//-- process markers
	var re = regexp.MustCompile(`\[###([A-Z0-9_\-\.]+)((\|[a-z0-9]+)*)###\]`) // regex markers as in Javascript
	for i, match := range re.FindAllStringSubmatch(template, -1) {
		//--
		var tmp_marker_val string			= "" 									// just initialize
		var tmp_marker_id string			= string(match[0]) 						// [###THE-MARKER|escapings...###]
		var tmp_marker_key string			= string(match[1]) 						// THE-MARKER
		var tmp_marker_esc string			= string(match[2]) 						// |escaping1(|escaping2...|escaping99)
		//--
		mKeyValue, mKeyExists := arrobj[tmp_marker_key]
		//--
		if(mKeyExists) {
			//--
			tmp_marker_val = PrepareNosyntaxContentMarkersTpl(mKeyValue)
			//--
			if((tmp_marker_id != "") && (tmp_marker_key != "")) {
				//--
			//	fmt.Println("---------- : " + tmp_marker_val)
			//	fmt.Println(tmp_marker_id + " # found Marker at index: " + strconv.Itoa(i))
			//	fmt.Println(tmp_marker_key + " # found Marker Key at index:", strconv.Itoa(i))
			//	fmt.Println(tmp_marker_esc + " # found Marker Escaping at index:", strconv.Itoa(i))
				//--
				if(tmp_marker_esc != "") {
					//--
					var tmp_marker_arr_esc []string	= Explode("|", tmp_marker_esc) // just initialize
					//--
					for j, tmp_marker_each_esc := range tmp_marker_arr_esc {
						//--
						if(tmp_marker_each_esc != "") {
							//--
							var escaping string = "|" + tmp_marker_each_esc
							//--
			//				fmt.Println(escaping + " # found Marker Escaping [Arr] at index: " + strconv.Itoa(i) + "." + strconv.Itoa(j))
							//--
							if(escaping == "|bool") { // Boolean
								tmp_marker_val = ParseStringAsBoolStr(tmp_marker_val)
							} else if(escaping == "|int") { // Integer
								tmp_marker_val = ParseInteger64AsStr(tmp_marker_val)
							} else if(escaping == "|dec1") { // Decimals: 1
								tmp_marker_val = ParseFloatAsStrDecimal(tmp_marker_val, 1)
							} else if(escaping == "|dec2") { // Decimals: 2
								tmp_marker_val = ParseFloatAsStrDecimal(tmp_marker_val, 2)
							} else if(escaping == "|dec3") { // Decimals: 3
								tmp_marker_val = ParseFloatAsStrDecimal(tmp_marker_val, 3)
							} else if(escaping == "|dec4") { // Decimals: 4
								tmp_marker_val = ParseFloatAsStrDecimal(tmp_marker_val, 4)
							} else if(escaping == "|num") { // Number (Float / Decimal / Integer)
								tmp_marker_val = ParseFloatAsStrFloat(tmp_marker_val)
							} else if(escaping == "|slug") { // Slug: a-zA-Z0-9_- / - / -- : -
								tmp_marker_val = StrCreateSlug(tmp_marker_val)
							} else if(escaping == "|htmid") { // HTML-ID: a-zA-Z0-9_-
								tmp_marker_val = StrCreateHtmId(tmp_marker_val)
							} else if(escaping == "|jsvar") { // JS-Variable: a-zA-Z0-9_
								tmp_marker_val = StrCreateJsVarName(tmp_marker_val)
							} else if((StrGetAsciiSubstring(escaping, 0, 7) == "|substr") || (StrGetAsciiSubstring(escaping, 0, 7) == "|subtxt")) { // Sub(String|Text) (0,num)
								xstrnum := StrTrimWhitespaces(StrGetAsciiSubstring(escaping, 7, 0))
								xnum := ParseIntegerStrAsInt(xstrnum)
								if(xnum < 1) {
									xnum = 1
								} else if(xnum > 65535) {
									xnum = 65535
								} //end if else
								if(xnum >= 1 && xnum <= 65535) {
									if(len(tmp_marker_val) > xnum) {
										if(StrGetAsciiSubstring(escaping, 0, 7) == "|subtxt") {
											tmp_marker_val = TextCutByLimit(tmp_marker_val, xnum)
										} else { // '|substr'
											tmp_marker_val = StrGetUnicodeSubstring(tmp_marker_val, 0, xnum)
										} //end if
									} //end if else
								} //end if
								xstrnum = ""
								xnum = 0
							} else if(escaping == "|lower") { // apply lowercase
								tmp_marker_val = strings.ToLower(tmp_marker_val)
							} else if(escaping == "|upper") { // apply uppercase
								tmp_marker_val = strings.ToUpper(tmp_marker_val)
							} else if(escaping == "|ucfirst") { // apply uppercase first character
								x1st := strings.ToUpper(StrGetUnicodeSubstring(tmp_marker_val, 0, 1)) // get 1st char
								xrest := strings.ToLower(StrGetUnicodeSubstring(tmp_marker_val, 1, 0)) // get the rest of characters
								tmp_marker_val = x1st + xrest
								x1st = ""
								xrest = ""
							} else if(escaping == "|ucwords") { // apply uppercase on each word
								tmp_marker_val = strings.Title(strings.ToLower(tmp_marker_val))
							} else if(escaping == "|trim") { // apply trim
								tmp_marker_val = StrTrimWhitespaces(tmp_marker_val)
							} else if(escaping == "|url") { // escape URL
								tmp_marker_val = RawUrlEncode(tmp_marker_val)
							} else if(escaping == "|json") { // format as Json Data ; expects pure JSON !!!
								jsonObj := JsonDecode(tmp_marker_val)
								if(jsonObj == nil) {
									tmp_marker_val = "null"
								} else {
									tmp_marker_val = StrTrimWhitespaces(JsonEncode(jsonObj))
									if(tmp_marker_val == "") {
										tmp_marker_val = "null"
									} //end if
								} //end if else
								jsonObj = nil
							} else if(escaping == "|js") { // Escape JS
								tmp_marker_val = EscapeJs(tmp_marker_val)
							} else if(escaping == "|html") { // Escape HTML
								tmp_marker_val = EscapeHtml(tmp_marker_val)
							} else if(escaping == "|css") { // Escape CSS
								tmp_marker_val = EscapeCss(tmp_marker_val)
							} else if(escaping == "|nl2br") { // Format NL2BR
								tmp_marker_val = StrNl2Br(tmp_marker_val)
							} else if(escaping == "|syntaxhtml") { // fix back markers tpl escapings in html
								tmp_marker_val = PrepareNosyntaxHtmlMarkersTpl(tmp_marker_val)
							} else {
								log.Println("WARNING: RenderMarkersTpl: {### Invalid or Undefined Escaping " + escaping + " [" + strconv.Itoa(j) + "]" + " for Marker `" + tmp_marker_key + "` " + "[" + strconv.Itoa(i) + "]: " + " - detected in Replacement Key: " + tmp_marker_id + " ###}")
							} //end if
							//--
						} //end if
						//--
					} //end for
					//--
				} //end if
				//--
				template = StrReplaceWithLimit(template, tmp_marker_id, tmp_marker_val, -1) // replace all (testing also for replace with limit -1 !)
				//--
			} //end if
			//--
		} //end if
		//--
	} //end for
	//-- replace specials: Square-Brackets(L/R) R N TAB SPACE
	if(strContains(template, "[%%%|")) {
		template = StrReplaceAll(template, "[%%%|SB-L%%%]", "［")
		template = StrReplaceAll(template, "[%%%|SB-R%%%]", "］")
		template = StrReplaceAll(template, "[%%%|R%%%]",    "\r")
		template = StrReplaceAll(template, "[%%%|N%%%]",    "\n")
		template = StrReplaceAll(template, "[%%%|T%%%]",    "\t")
		template = StrReplaceAll(template, "[%%%|SPACE%%%]", " ")
	} //end if
	//--
	return template
	//--
} //END FUNCTION


// #END
