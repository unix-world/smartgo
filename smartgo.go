
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020 unix-world.org
// r.20200507.1905 :: STABLE

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
	"github.com/unix-world/smartgo/logutils"
)


const (
	DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH = "2006-01-02"
	DATE_TIME_FMT_ISO_STD_GO_EPOCH    = "2006-01-02 15:04:05"
	DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH  = "2006-01-02 15:04:05 -0700"

	TRIM_WHITESPACES = " \t\n\r\x00\x0B"

	DATA_ARCH_SIGNATURE = "PHP.SF.151129/B64.ZLibRaw.HEX"
)


//-----


// PRIVATES
type logWriterWithColors struct {}
func (writer logWriterWithColors) Write(bytes []byte) (int, error) {
	//--
	var theMsg string = StrTrimWhitespaces(StrNormalizeSpaces(string(bytes)))
	if(StrIPos(theMsg, "[ERROR]") == 0) {
		theMsg = color.HiRedString(theMsg)
	} else if(StrIPos(theMsg, "[WARNING]") == 0) {
		theMsg = color.HiYellowString(theMsg)
	} else if(StrIPos(theMsg, "[NOTICE]") == 0) {
		theMsg = color.HiBlueString(theMsg)
	} else if(StrIPos(theMsg, "[DEBUG]") == 0) {
		theMsg = color.HiMagentaString(theMsg)
	} else { // ALL OTHER CASES
		theMsg = color.HiCyanString(theMsg)
	} //end if else
	//--
	return fmt.Println("LOG | " + DateNowUtc() + " | " + theMsg)
	//--
} //END FUNCTION


// PRIVATES
var  logFilePath string = ""
var  logFileFormat string = "plain"
type logWriterFile struct {}
type logWriteJsonStruct struct {
	Type    string `json:"type"`
	DateUtc string `json:"dateUtc"`
	Message string `json:"message"`
}
func (writer logWriterFile) Write(bytes []byte) (int, error) {
	//--
	if(logFilePath == "") {
		return 0, errors.New("[ERROR] SmartGo LogFile :: Empty LogFile Path provided")
	} //end if
	//--
	var theMsg string = StrTrimWhitespaces(string(bytes))
	var theType string = ""
	if(StrIPos(theMsg, "[ERROR]") == 0) {
		theType = "error"
	} else if(StrIPos(theMsg, "[WARNING]") == 0) {
		theType = "warning"
	} else if(StrIPos(theMsg, "[NOTICE]") == 0) {
		theType = "notice"
	} else if(StrIPos(theMsg, "[DEBUG]") == 0) {
		theType = "debug"
	} else { // ALL OTHER CASES
		theType = "unknown"
	} //end if else
	var theFmtMsg string = ""
	if(logFileFormat == "json") {
		jsonLogStruct := logWriteJsonStruct {
			Type    : theType,
			DateUtc : DateNowUtc(),
			Message : theMsg, // not necessary to normalize spaces
		}
		theFmtMsg = JsonEncode(jsonLogStruct)
	} else {
		theFmtMsg = StrNormalizeSpaces(theMsg)
	} //end if else
	//--
	isSuccess, errMsg := SafePathFileWrite(theFmtMsg + "\n", "a", logFilePath, true)
	//--
	if(errMsg != "") {
		return 0, errors.New("[ERROR] SmartGo LogFile write Error `" + logFilePath + "` :: " + errMsg)
	} //end if
	//--
	if(isSuccess != true) {
		return 0, errors.New("[ERROR] SmartGo LogFile :: FAILED to write to the log File: `" + logFilePath + "`")
	} //end if
	//--
	return len(bytes), nil
	//--
} //END FUNCTION


// PRIVATE
func setLogLevelOutput(level string, output io.Writer) { // Example: setLogLevelOutput("WARNING", os.Stderr)
	//--
	level = strings.ToUpper(StrTrimWhitespaces(level))
	//--
	var mLevel string = "ERROR"
	if(level == "WARNING") {
		mLevel = "WARNING"
	} else if(level == "NOTICE") {
		mLevel = "NOTICE"
	} else if(level == "DEBUG") {
		mLevel = "DEBUG"
	} //end if else
	//--
	filter := &logutils.LevelFilter{
		Levels: []logutils.LogLevel{"DEBUG", "NOTICE", "WARNING", "ERROR"},
		MinLevel: logutils.LogLevel(mLevel),
		Writer: output,
	}
	log.SetOutput(filter)
	//--
} //END FUNCTION


func LogToConsole(level string, withColors bool) {
	//--
	if(withColors == true) {
		//--
		log.SetFlags(0) // custom log with colors, reset all flags
		//--
		setLogLevelOutput(level, new(logWriterWithColors))
		//--
	} else {
		//--
		setLogLevelOutput(level, os.Stderr)
		//--
	} //end if else
	//--
} //END FUNCTION


func LogToFile(level string, filePath string, asJson bool) {
	//--
	filePath = StrTrimLeftWhitespaces(filePath)
	if(filePath != "") {
		if(!PathIsBackwardUnsafe(filePath)) {
			if(!PathIsDir(filePath)) {
				//--
				log.SetFlags(0) // custom log, reset all flags
				//--
				logFilePath = filePath
				if(asJson == true) {
					logFileFormat = "json"
				} //end if
				setLogLevelOutput(level, new(logWriterFile))
				//--
			} //end if
		} //end if
	} //end if
	//--
} //END FUNCTION


//-----


// PRIVATE
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


// PRIVATE
func parseDateTimeAsStruct(mode string, dateIsoStr string) uxmDateTimeStruct { // mode = UTC | LOCAL
	//--
	dateIsoStr = StrTrimWhitespaces(dateIsoStr)
	if((dateIsoStr == "") || (StrIContains(dateIsoStr, "NOW"))) {
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
	var crrStrYear string = ConvertIntToStr(crrYear)
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
		crrStrMonth = "0" + ConvertIntToStr(crrIntMonth)
	} else {
		crrStrMonth = ""  + ConvertIntToStr(crrIntMonth)
	} //end if else
	var crrNameOfMonth string = crrMonth.String()
	//--
	var crrDay int = currentTime.Day()
	var crrStrDay string = ""
	if(crrDay <= 9) {
		crrStrDay = "0" + ConvertIntToStr(crrDay)
	} else {
		crrStrDay = ""  + ConvertIntToStr(crrDay)
	} //end if else
	//--
	var crrHour int = int(currentTime.Hour())
	var crrStrHour string = ""
	if(crrHour <= 9) {
		crrStrHour = "0" + ConvertIntToStr(crrHour)
	} else {
		crrStrHour = ""  + ConvertIntToStr(crrHour)
	} //end if else
	//--
	var crrMinute int = int(currentTime.Minute())
	var crrStrMinute = ""
	if(crrMinute <= 9) {
		crrStrMinute = "0" + ConvertIntToStr(crrMinute)
	} else {
		crrStrMinute = ""  + ConvertIntToStr(crrMinute)
	} //end if else
	//--
	var crrSecond int = int(currentTime.Second())
	var crrStrSecond string = ""
	if(crrSecond <= 9) {
		crrStrSecond = "0" + ConvertIntToStr(crrSecond)
	} else {
		crrStrSecond = ""  + ConvertIntToStr(crrSecond)
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
	var safeKey string = StrSubstr(Sha512(key), 13, 29+13) + strings.ToUpper(StrSubstr(Sha1(key), 13, 10+13)) + StrSubstr(Md5(key), 13, 9+13)
	//--
	//log.Println("[DEBUG] BfKey: " + safeKey)
	return safeKey
	//--
} //END FUNCTION


// PRIVATE : Blowfish iv {{{SYNC-BLOWFISH-IV}}}
func blowfishSafeIv(key string) string {
	//--
	var safeIv string = Base64Encode(Sha1("@Smart.Framework-Crypto/BlowFish:" + key + "#" + Sha1("BlowFish-iv-SHA1" + key) + "-" + strings.ToUpper(Md5("BlowFish-iv-MD5" + key)) + "#"))
	safeIv = StrSubstr(safeIv, 1, 8+1)
	//log.Println("[DEBUG] BfIv: " + safeIv)
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
	//log.Println("[DEBUG] BfTxt: " + str)
	//-- cast to bytes
	ppt := []byte(blowfishChecksizeAndPad(str, 32)) // pad with spaces
	str = "" // no more needed
	//-- create the cipher
	ecipher, err := blowfish.NewCipher([]byte(blowfishSafeKey(key)))
	if(err != nil) {
		log.Println("[WARNING] BlowfishEncryptCBC: ", err)
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
	if(StrSubstr(encTxt, 0, 16) != "0000000000000000") { // {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}}
		log.Println("[WARNING] BlowfishEncryptCBC: Invalid Hex Header")
		return ""
	} //end if
	encTxt = StrSubstr(encTxt, 16, 0) // fix: {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}} ; there are 16 trailing zeroes that represent the HEX of 8 null bytes ; remove them
	if(encTxt == "") {
		log.Println("[WARNING] BlowfishEncryptCBC: Empty Hex Body") // must be some data after the 8 bytes null header
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
		log.Println("[WARNING] BlowfishDecryptCBC: ", err)
		return ""
	} //end if
	//-- make initialisation vector {{{SYNC-BLOWFISH-IV}}}
	div := []byte(blowfishSafeIv(key))
	//-- check last slice of encrypted text, if it's not a modulus of cipher block size, we're in trouble
	decrypted := et[blowfish.BlockSize:]
	if(len(decrypted)%blowfish.BlockSize != 0) {
		log.Println("[NOTICE] BlowfishDecryptCBC: decrypted is not a multiple of blowfish.BlockSize")
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
		log.Println("[NOTICE] Invalid BlowFishCBC Data, Empty Data after Decrypt")
		return ""
	} //end if
	if(!StrContains(str, "#CHECKSUM-SHA1#")) {
		log.Println("[NOTICE] Invalid BlowFishCBC Data, no Checksum")
		return ""
	} //end if
	//--
	darr := Explode("#CHECKSUM-SHA1#", str)
	var dlen int = len(darr)
	if(dlen < 2) {
		log.Println("[NOTICE] Invalid BlowFishCBC Data, Checksum not found")
		return ""
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		log.Println("[NOTICE] Invalid BlowFishCBC Data, Checksum is Empty")
		return ""
	} //end if
	if(darr[0] == "") {
		log.Println("[NOTICE] Invalid BlowFishCBC Data, Encrypted Data not found")
		return ""
	} //end if
	if(Sha1(darr[0]) != darr[1]) {
		log.Println("[NOTICE] BlowfishDecryptCBC // Invalid Packet, Checksum FAILED :: A checksum was found but is invalid")
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
		log.Println("[NOTICE] GzDeflate: ", err)
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
		log.Println("[NOTICE] Data Unarchive // Invalid Package Format")
		return ""
	} //end if
	//--
	if(alen < 2) {
		log.Println("[NOTICE] Data Unarchive // Empty Package Signature")
	} else {
		arr[1] = StrTrimWhitespaces(arr[1])
		if(arr[1] != DATA_ARCH_SIGNATURE) {
			log.Println("[NOTICE] Data Unarchive // Invalid Package Signature: ", arr[1])
		} //end if
	} //end if
	//--
	arr[0] = Base64Decode(arr[0])
	if(arr[0] == "") {
		log.Println("[NOTICE] Data Unarchive // Invalid B64 Data for packet with signature: ", arr[1])
		return ""
	} //end if
	//--
	arr[0] = GzInflate(arr[0])
	if(arr[0] == "") {
		log.Println("[NOTICE] Data Unarchive // Invalid Zlib GzInflate Data for packet with signature: ", arr[1])
		return ""
	} //end if
	//--
	const txtErrExpl = "This can occur if decompression failed or an invalid packet has been assigned ..."
	//--
	if(!StrContains(arr[0], "#CHECKSUM-SHA1#")) {
		log.Println("[NOTICE] Invalid Packet, no Checksum :: ", txtErrExpl)
		return ""
	} //end if
	//--
	darr := Explode("#CHECKSUM-SHA1#", arr[0])
	var dlen int = len(darr)
	if(dlen < 2) {
		log.Println("[NOTICE] Invalid Packet, Checksum not found :: ", txtErrExpl)
		return ""
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		log.Println("[NOTICE] Invalid Packet, Checksum is Empty :: ", txtErrExpl)
		return ""
	} //end if
	if(darr[0] == "") {
		log.Println("[NOTICE] Invalid Packet, Data not found :: ", txtErrExpl)
		return ""
	} //end if
	//--
	darr[0] = Hex2Bin(strings.ToLower(darr[0]))
	if(darr[0] == "") {
		log.Println("[NOTICE] Data Unarchive // Invalid HEX Data for packet with signature: ", arr[1])
		return ""
	} //end if
	//--
	if(Sha1(darr[0]) != darr[1]) {
		log.Println("[NOTICE] Data Unarchive // Invalid Packet, Checksum FAILED :: A checksum was found but is invalid: ", darr[1])
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
		log.Println("[ERROR] Data Archive // ZLib Deflated Data is Empty")
		return ""
	} //end if
	//--
	var ratio = float64(ulen) / float64(alen) // division by zero is checked above by (alen <= 0)
	if(ratio <= 0) {
		log.Println("[ERROR] Data Archive // ZLib Data Ratio is zero: ", ratio)
		return ""
	} //end if
	if(ratio > 32768) { // check for this bug in ZLib {{{SYNC-GZ-ARCHIVE-ERR-CHECK}}}
		log.Println("[ERROR] Data Archive // ZLib Data Ratio is higher than 32768: ", ratio)
		return ""
	} //end if
//	log.Println("[DEBUG] Data Archive // ZLib Data Ratio is: ", ratio, " by division of: ", ulen, " with: (/) ", alen)
	//--
	arch = StrTrimWhitespaces(Base64Encode(arch)) + "\n" + DATA_ARCH_SIGNATURE
	//--
	var unarch_chksum string = Sha1(DataUnArchive(arch))
	if(unarch_chksum != chksum) {
		log.Println("[ERROR] Data Archive // Data Encode Check Failed")
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
		log.Println("[NOTICE] Base64Decode: ", err)
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


//-----


// case sensitive, find position of first occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrPos(haystack string, needle string) int {
	//--
	if((haystack == "") || (needle == "")) {
		return -1;
	} //end if
	//--
	pos := strings.Index(haystack, needle) // -1 if needle is not present in haystack
	//--
	if(pos < 0) {
		return -1 // make it standard return
	} //end if
	//--
	rs := []rune(haystack[0:pos])
	//--
	return len(rs)
	//--
} //END FUNCTION


// case insensitive, find position of first occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrIPos(haystack, needle string) int {
	//--
	return StrPos(strings.ToLower(haystack), strings.ToLower(needle))
	//--
} //END FUNCTION


// case sensitive, find position of last occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrRPos(haystack string, needle string) int {
	//--
	if((haystack == "") || (needle == "")) {
		return -1;
	} //end if
	//--
	pos := strings.LastIndex(haystack, needle) // -1 if needle is not present in haystack
	//--
	if(pos < 0) {
		return -1 // make it standard return
	} //end if
	//--
	rs := []rune(haystack[0:pos])
	//--
	return len(rs)
	//--
} //END FUNCTION


// case insensitive, find position of last occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrRIPos(haystack, needle string) int {
	//--
	return StrRPos(strings.ToLower(haystack), strings.ToLower(needle))
	//--
} //END FUNCTION


//-----


func StrContains(str string, part string) bool {
	//--
	return strings.Contains(str, part)
	//--
} //END FUNCTION


func StrIContains(str string, part string) bool {
	//--
	return strings.Contains(strings.ToLower(str), strings.ToLower(part))
	//--
} //END FUNCTION


func StrTrim(s string, cutset string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = strings.Trim(s, cutset)
	//--
	return s
	//--
} //END FUNCTION


func StrTrimLeft(s string, cutset string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = strings.TrimLeft(s, cutset)
	//--
	return s
	//--
} //END FUNCTION


func StrTrimRight(s string, cutset string) string {
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	s = strings.TrimRight(s, cutset)
	//--
	return s
	//--
} //END FUNCTION


func StrTrimWhitespaces(s string) string {
	//--
	return StrTrim(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


func StrTrimLeftWhitespaces(s string) string {
	//--
	return StrTrimLeft(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


func StrTrimRightWhitespaces(s string) string {
	//--
	return StrTrimRight(s, TRIM_WHITESPACES) // this is compatible with PHP
	//--
} //END FUNCTION


func StrMBSubstr(s string, start int, stop int) string {
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


func StrSubstr(s string, start int, stop int) string {
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


func StrNormalizeSpaces(s string) string {
	//--
	s = StrReplaceAll(s, "\r\n", " ")
	s = StrReplaceAll(s, "\r",   " ")
	s = StrReplaceAll(s, "\n",   " ")
	s = StrReplaceAll(s, "\t",   " ")
	s = StrReplaceAll(s, "\x0B", " ")
	s = StrReplaceAll(s, "\x00", " ")
	s = StrReplaceAll(s, "\f",   " ")
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
	s = StrMBSubstr(s, 0, length - 3) // substract -3 because of the trailing dots ...
	s = StrRegexReplaceAll(`\s+?(\S+)?$`, s, "") // {{{SYNC-REGEX-TEXT-CUTOFF}}}
	s = s + "..." // add trailing dots
	//--
	return s
	//--
} //END FUNCTION


func ConvertIntToStr(i int) string {
	//--
	return strconv.Itoa(i)
	//--
} //END FUNCTION


func ConvertInt64ToStr(i int64) string {
	//--
	return strconv.FormatInt(i, 10)
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


func ParseInteger64StrAsStr(s string) string {
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
	s = fmt.Sprintf("%." + ConvertIntToStr(d) + "f", f)
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


func StrRegexReplaceAll(rexpr string, s string, repl string) string {
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
	s = StrRegexReplaceAll(`[^a-zA-Z0-9_\-]`, s, "-")
	s = StrRegexReplaceAll(`[\-]+`, s, "-") // suppress multiple -
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
	s = StrRegexReplaceAll(`[^a-zA-Z0-9_\-]`, s, "")
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
	s = StrRegexReplaceAll(`[^a-zA-Z0-9_]`, s, "")
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
		log.Println("[NOTICE] Hex2Bin: ", err)
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
		log.Println("[NOTICE] JsonEncode: ", err)
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
		//log.Println("[NOTICE] JsonDecode: ", err)
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


func PathDirName(filePath string) string {
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	return filepath.Dir(filePath)
	//--
} //END FUNCTION


func PathBaseName(filePath string) string {
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	return filepath.Base(filePath)
	//--
} //END FUNCTION


func PathIsAbsolute(filePath string) bool {
	//--
	if(
		(StrSubstr(filePath, 0, 1) == "/") || // unix / linux
		(StrSubstr(filePath, 0, 1) == ":") || // windows
		(StrSubstr(filePath, 1, 2) == ":")) { // windows
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func PathIsBackwardUnsafe(filePath string) bool {
	//--
	if(
		StrContains(filePath, "/../") ||
		StrContains(filePath, "/./")  ||
		StrContains(filePath, "/..")  ||
		StrContains(filePath, "../")) {
		return true
	} //end if
	//--
	return false
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


func SafePathDirCreate(dirPath string, allowRecursive bool, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, errors.New("WARNING: Dir Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, errors.New("WARNING: Dir Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, errors.New("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathExists(dirPath)) {
		//--
		if(PathIsFile(dirPath)) {
			return false, errors.New("WARNING: Dir Path is a File not a Directory").Error()
		} //end if
		if(!PathIsDir(dirPath)) {
			return false, errors.New("WARNING: Dir Path is Not a Directory").Error()
		} //end if
		//--
	} else {
		//--
		var err error = nil
		if(allowRecursive == true) {
			err = os.MkdirAll(dirPath, 0755)
		} else {
			err = os.Mkdir(dirPath, 0755)
		} //end if else
		if(err != nil) {
			return false, err.Error()
		} //end if
		//--
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION



func SafePathDirDelete(dirPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, errors.New("WARNING: Dir Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, errors.New("WARNING: Dir Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, errors.New("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathExists(dirPath)) {
		//--
		if(PathIsFile(dirPath)) {
			return false, errors.New("WARNING: Dir Path is a File not a Directory").Error()
		} //end if
		if(!PathIsDir(dirPath)) {
			return false, errors.New("WARNING: Dir Path is Not a Directory").Error()
		} //end if
		//--
		err := os.RemoveAll(dirPath)
		if(err != nil) {
			return false, err.Error()
		} //end if
		//--
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathDirRename(dirPath string, dirNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, errors.New("WARNING: Dir Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, errors.New("WARNING: Dir Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, errors.New("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(StrTrimWhitespaces(dirNewPath) == "") {
		return false, errors.New("WARNING: New Dir Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(dirNewPath) == true) {
		return false, errors.New("WARNING: New Dir Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirNewPath) == true) {
			return false, errors.New("NOTICE: New Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(dirPath == dirNewPath) {
		return false, errors.New("WARNING: New Dir Path is the same as the Original Dir Path").Error()
	} //end if
	//--
	if(!PathExists(dirPath)) {
		return false, errors.New("WARNING: Dir Path does not exist").Error()
	} //end if
	if(!PathIsDir(dirPath)) {
		return false, errors.New("WARNING: Dir Path is Not a Dir").Error()
	} //end if
	//--
	if(PathIsFile(dirPath)) {
		return false, errors.New("WARNING: Dir Path is a File not a Directory").Error()
	} //end if
	if(PathIsFile(dirNewPath)) {
		return false, errors.New("WARNING: New Dir Path is a File not a Directory").Error()
	} //end if
	//--
	if(PathExists(dirNewPath)) {
		return false, errors.New("WARNING: New Dir Path already exist").Error()
	} //end if
	//--
	err := os.Rename(dirPath, dirNewPath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


//-----


func SafePathFileRead(filePath string, allowAbsolutePath bool) (fileContent string, errMsg string) {
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
	if(PathIsDir(filePath)) {
		return "", errors.New("WARNING: File Path is a Directory not a File").Error()
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


func SafePathFileWrite(fileContent string, wrMode string, filePath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	// wrMode : "a" for append | "w" for write
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	//--
	if(wrMode == "a") { // append mode
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if(err != nil) {
			return false, err.Error()
		} //end if
		defer f.Close()
		if _, err := f.WriteString(fileContent); err != nil {
			return false, err.Error()
		} //end if
	} else if(wrMode == "w") { // write mode
		err := ioutil.WriteFile(filePath, []byte(fileContent), 0644)
		if(err != nil) {
			return false, err.Error()
		} //end if
	} else {
		return false, errors.New("WARNING: Invalid File Write Mode: `" + wrMode + "`").Error()
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathFileDelete(filePath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(PathExists(filePath)) {
		//--
		if(PathIsDir(filePath)) {
			return false, errors.New("WARNING: File Path is a Directory not a File").Error()
		} //end if
		if(!PathIsFile(filePath)) {
			return false, errors.New("WARNING: File Path is Not a File").Error()
		} //end if
		//--
		err := os.Remove(filePath)
		if(err != nil) {
			return false, err.Error()
		} //end if
		//--
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathFileRename(filePath string, fileNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(StrTrimWhitespaces(fileNewPath) == "") {
		return false, errors.New("WARNING: New File Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(fileNewPath) == true) {
		return false, errors.New("WARNING: New File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(fileNewPath) == true) {
			return false, errors.New("NOTICE: New File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(filePath == fileNewPath) {
		return false, errors.New("WARNING: New File Path is the same as the Original File Path").Error()
	} //end if
	//--
	if(!PathExists(filePath)) {
		return false, errors.New("WARNING: File Path does not exist").Error()
	} //end if
	if(!PathIsFile(filePath)) {
		return false, errors.New("WARNING: File Path is Not a File").Error()
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	if(PathIsDir(fileNewPath)) {
		return false, errors.New("WARNING: New File Path is a Directory not a File").Error()
	} //end if
	//--
	if(PathExists(fileNewPath)) {
		return false, errors.New("WARNING: New File Path already exist").Error()
	} //end if
	//--
	err := os.Rename(filePath, fileNewPath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathFileCopy(filePath string, fileNewPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return false, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return false, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return false, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(StrTrimWhitespaces(fileNewPath) == "") {
		return false, errors.New("WARNING: New File Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(fileNewPath) == true) {
		return false, errors.New("WARNING: New File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(fileNewPath) == true) {
			return false, errors.New("NOTICE: New File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(filePath == fileNewPath) {
		return false, errors.New("WARNING: New File Path is the same as the Original File Path").Error()
	} //end if
	//--
	if(!PathExists(filePath)) {
		return false, errors.New("WARNING: File Path does not exist").Error()
	} //end if
	if(!PathIsFile(filePath)) {
		return false, errors.New("WARNING: File Path is Not a File").Error()
	} //end if
	//--
	if(PathIsDir(filePath)) {
		return false, errors.New("WARNING: File Path is a Directory not a File").Error()
	} //end if
	if(PathIsDir(fileNewPath)) {
		return false, errors.New("WARNING: New File Path is a Directory not a File").Error()
	} //end if
	if(PathIsFile(fileNewPath)) {
		testDelOldFile, errMsg := SafePathFileDelete(fileNewPath, allowAbsolutePath)
		if((testDelOldFile != true) || (errMsg != "")) {
			return false, errors.New("WARNING: Cannot Remove existing Destination File: " + errMsg).Error()
		} //end if
	} //end if
	//--
	/* this commented code would copy files using in-memory read of origin file and after that write to destination file which is not memory efficient when copying large files ; below is a revised version that copies through a pipe
	data, err := ioutil.ReadFile(filePath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	err = ioutil.WriteFile(fileNewPath, data, 0644)
	if(err != nil) {
		return false, err.Error()
	} //end if
	*/
	//-- revised copy file, using pipe
	sourceFileStat, err := os.Stat(filePath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	if(!sourceFileStat.Mode().IsRegular()) {
		return false, errors.New("WARNING: Source File is not a regular file").Error()
	} //end if
	source, err := os.Open(filePath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	defer source.Close()
	destination, err := os.Create(fileNewPath)
	if(err != nil) {
		return false, err.Error()
	} //end if
	defer destination.Close()
	nBytes, err := io.Copy(destination, source)
	if(err != nil) {
		return false, err.Error()
	} //end if
	//--
	if(!PathIsFile(fileNewPath)) {
		return false, errors.New("WARNING: New File Path cannot be found after copy").Error()
	} //end if
	errChmod := os.Chmod(fileNewPath, 0644)
	if(err != nil) {
		log.Println("[WARNING] Failed to CHMOD 0644 the Destination File after copy", fileNewPath, errChmod)
	} //end if
	//--
	fSizeOrigin, errMsg := SafePathFileGetSize(filePath, allowAbsolutePath);
	if(errMsg != "") {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Failed to Compare After Copy File Sizes (origin)").Error()
	} //end if
	fSizeDest, errMsg := SafePathFileGetSize(fileNewPath, allowAbsolutePath);
	if(errMsg != "") {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Failed to Compare After Copy File Sizes (destination)").Error()
	} //end if
	//--
	if(fSizeOrigin != fSizeDest) {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Compare After Copy File Sizes: File Sizes are Different: OriginSize=" + ConvertInt64ToStr(fSizeOrigin) + " / DestinationSize=" + ConvertInt64ToStr(fSizeDest)).Error()
	} //end if
	if(fSizeOrigin != nBytes) {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Compare After Copy File Sizes: Bytes Copied Size is Different than Original Size: OriginSize=" + ConvertInt64ToStr(fSizeOrigin) + " / BytesCopied=" + ConvertInt64ToStr(nBytes)).Error()
	} //end if
	//--
	return true, ""
	//--
} //END FUNCTION


func SafePathFileGetSize(filePath string, allowAbsolutePath bool) (fileSize int64, errMsg string) {
	//--
	if(StrTrimWhitespaces(filePath) == "") {
		return 0, errors.New("WARNING: File Path is Empty").Error()
	} //end if
	//--
	if(PathIsBackwardUnsafe(filePath) == true) {
		return 0, errors.New("WARNING: File Path is Backward Unsafe").Error()
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(filePath) == true) {
			return 0, errors.New("NOTICE: File Path is Absolute but not allowed to be absolute by the calling parameters").Error()
		} //end if
	} //end if
	//--
	if(!PathExists(filePath)) {
		return 0, errors.New("WARNING: File Path does not exist").Error()
	} //end if
	if(!PathIsFile(filePath)) {
		return 0, errors.New("WARNING: File Path is not a file").Error()
	} //end if
	//--
	fd, err := os.Stat(filePath)
	if(err != nil) {
		if(os.IsNotExist(err)) {
			return 0, err.Error()
		} //end if
	} //end if
	var size int64 = fd.Size()
	//--
	return size, ""
	//--
} //END FUNCTION


//-----


func MarkersTplPrepareNosyntaxHtml(tpl string) string {
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


func MarkersTplPrepareNosyntaxContent(tpl string) string {
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


func MarkersTplRender(template string, arrobj map[string]string, isEncoded bool, revertSyntax bool) string { // r.20200121
	//-- replace out comments
	if((StrContains(template, "[%%%COMMENT%%%]")) && (StrContains(template, "[%%%/COMMENT%%%]"))) {
		template = StrRegexReplaceAll(`(?sU)\s?\[%%%COMMENT%%%\](.*)?\[%%%\/COMMENT%%%\]\s?`, template, "") // regex syntax as in PHP
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
			tmp_marker_val = MarkersTplPrepareNosyntaxContent(mKeyValue)
			//--
			if((tmp_marker_id != "") && (tmp_marker_key != "")) {
				//--
			//	log.Println("[DEBUG] ---------- : " + tmp_marker_val)
			//	log.Println("[DEBUG] tmp_marker_id  + " # found Marker at index: " + ConvertIntToStr(i))
			//	log.Println("[DEBUG] tmp_marker_key + " # found Marker Key at index:", ConvertIntToStr(i))
			//	log.Println("[DEBUG] tmp_marker_esc + " # found Marker Escaping at index:", ConvertIntToStr(i))
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
						//	log.Println("[DEBUG] escaping + " # found Marker Escaping [Arr] at index: " + ConvertIntToStr(i) + "." + ConvertIntToStr(j))
							//--
							if(escaping == "|bool") { // Boolean
								tmp_marker_val = ParseStringAsBoolStr(tmp_marker_val)
							} else if(escaping == "|int") { // Integer
								tmp_marker_val = ParseInteger64StrAsStr(tmp_marker_val)
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
							} else if((StrSubstr(escaping, 0, 7) == "|substr") || (StrSubstr(escaping, 0, 7) == "|subtxt")) { // Sub(String|Text) (0,num)
								xstrnum := StrTrimWhitespaces(StrSubstr(escaping, 7, 0))
								xnum := ParseIntegerStrAsInt(xstrnum)
								if(xnum < 1) {
									xnum = 1
								} else if(xnum > 65535) {
									xnum = 65535
								} //end if else
								if(xnum >= 1 && xnum <= 65535) {
									if(len(tmp_marker_val) > xnum) {
										if(StrSubstr(escaping, 0, 7) == "|subtxt") {
											tmp_marker_val = TextCutByLimit(tmp_marker_val, xnum)
										} else { // '|substr'
											tmp_marker_val = StrMBSubstr(tmp_marker_val, 0, xnum)
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
								x1st := strings.ToUpper(StrMBSubstr(tmp_marker_val, 0, 1)) // get 1st char
								xrest := strings.ToLower(StrMBSubstr(tmp_marker_val, 1, 0)) // get the rest of characters
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
								tmp_marker_val = MarkersTplPrepareNosyntaxHtml(tmp_marker_val)
							} else {
								log.Println("[WARNING] MarkersTplRender: {### Invalid or Undefined Escaping " + escaping + " [" + ConvertIntToStr(j) + "]" + " for Marker `" + tmp_marker_key + "` " + "[" + ConvertIntToStr(i) + "]: " + " - detected in Replacement Key: " + tmp_marker_id + " ###}")
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
	if(StrContains(template, "[%%%|")) {
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
