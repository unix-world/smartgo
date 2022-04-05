
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2022 unix-world.org
// r.20220405.0608 :: STABLE

package smartgo

// REQUIRE: go 1.13 or later

import (
	"runtime/debug"
	"os"
	"os/exec"
	"context"
	"errors"

	"io"
	"io/ioutil"

	"time"

	"log"
	"fmt"

	"bytes"
	"strings"
	"strconv"
	"regexp"
	"unicode"
	"unicode/utf8"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"

	"compress/flate"
	"compress/gzip"

	"path/filepath"
	"net"
	"net/url"

	"mime"
	"html"
	"encoding/json"
	"encoding/hex"
	"encoding/base64"

	"hash"
	"hash/crc32"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/cipher"
	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/argon2"

	"github.com/unix-world/smartgo/threefish"
	"github.com/unix-world/smartgo/base32"
	"github.com/unix-world/smartgo/base36"
	"github.com/unix-world/smartgo/base58"
	"github.com/unix-world/smartgo/base62"
	"github.com/unix-world/smartgo/base85"
	"github.com/unix-world/smartgo/base92"
//	"github.com/fatih/color"
	color "github.com/unix-world/smartgo/colorstring"
	"github.com/unix-world/smartgo/logutils"
)


const (
	VERSION = "20220405.0608"

	// DO NOT MODIFY THE DATE CONSTANTS ... EVER ! THEY ARE REFERENCED WITH GO DATE !
	DATE_TIME_FMT_ISO_NOTIME_GO_EPOCH = "2006-01-02" 					// GO EPOCH:   NO TIME,   NO TZ OFFSET
	DATE_TIME_FMT_ISO_STD_GO_EPOCH    = "2006-01-02 15:04:05" 			// GO EPOCH: WITH TIME,   NO TZ OFFSET
	DATE_TIME_FMT_ISO_TZOFS_GO_EPOCH  = "2006-01-02 15:04:05 -0700" 	// GO EPOCH: WITH TIME, WITH TZ OFFSET

	TRIM_WHITESPACES = " \t\n\r\x00\x0B" 								// PHP COMPATIBILITY
	NULL_BYTE = "\000" 													// THE NULL BYTE

	REGEX_SMART_SAFE_PATH_NAME = `^[_a-zA-Z0-9\-\.@#\/]+$` 				// SAFETY: SUPPORT ONLY THESE CHARACTERS IN FILE SYSTEM PATHS ...
	REGEX_SMART_SAFE_FILE_NAME = `^[_a-zA-Z0-9\-\.@#]+$` 				// SAFETY: SUPPORT ONLY THESE CHARACTERS IN FILE SYSTEM FILE AND DIR NAMES ...
	REGEX_SMART_SAFE_NET_HOSTNAME  = `^[_a-z0-9\-\.]+$` 				// SAFETY: SUPPORT ONLY THESE CHARACTERS IN NET HOST NAMES AS RFC ; if a hostname have upper characters must be converted to all lower characters ; if a hostname have unicode characters must be converted using punnycode ...

	CMD_EXEC_ERR_SIGNATURE = "[SmartGo:cmdExec:Exit:ERROR]" 			// INTERNAL FLAG FOR CMD EXIT ERROR

	SEPARATOR_CHECKSUM_V1 = "#CHECKSUM-SHA1#" 							// only to support v1 unarchive or decrypt ; (for v1 no archive or encrypt is available anymore)
	SEPARATOR_CHECKSUM_V2 = "#CKSUM256#" 								// current, v2 ; archive + unarchive or encrypt + decrypt
	SIGNATURE_SFZ_DATA_ARCH_V1 = "PHP.SF.151129/B64.ZLibRaw.HEX" 		// only to support v1 unarchive ; (for v1 no archive is available anymore)
	SIGNATURE_SFZ_DATA_ARCH_V2 = "SFZ.20210818/B64.ZLibRaw.hex" 		// current, v2 ; archive + unarchive

	SIGNATURE_BFISH_V1 = "bf384.v1!" 									// this was not implemented in the v1, if used must be prefixed before decrypt for compatibility ... (for v1 no encrypt is available anymore)
	SIGNATURE_BFISH_V2 = "bf448.v2!" 									// current, v2 ; encrypt + decrypt

	SIGNATURE_3FISH_V1_DEFAULT  = "3f1kD.v1!" 							// current, v1 (default)  ; encrypt + decrypt
	SIGNATURE_3FISH_V1_ARGON2ID = "3f1kA.v1!" 							// current, v1 (argon2id) ; encrypt + decrypt

	FIXED_CRYPTO_SALT = "Smart Framework # スマート フレームワーク" 		// fixed salt data for various crypto contexts
)

//-----


// PRIVATES
type logWriterWithColors struct {}
func (writer logWriterWithColors) Write(bytes []byte) (int, error) {
	//--
	var theMsg string = StrTrimWhitespaces(StrNormalizeSpaces(string(bytes)))
	//--
	if(logColoredOnConsole) {
		if(StrIPos(theMsg, "[ERROR]") == 0) { // {{{SYNC-SMARTGO-ERR:LEVELS+COLORS}}}
			theMsg = color.HiRedString(theMsg)
		} else if(StrIPos(theMsg, "[WARNING]") == 0) {
			theMsg = color.YellowString(theMsg)
		} else if(StrIPos(theMsg, "[NOTICE]") == 0) {
			theMsg = color.HiBlueString(theMsg)
		} else if(StrIPos(theMsg, "[DATA]") == 0) {
			theMsg = color.HiYellowString(string(bytes)) // for data preserve the string how it is !
		} else if(StrIPos(theMsg, "[DEBUG]") == 0) {
			theMsg = color.HiMagentaString(theMsg)
		} else { // ALL OTHER CASES
			if(StrIPos(theMsg, "[OK]") == 0) {
				theMsg = color.HiGreenString(theMsg)
			} else {
				theMsg = color.HiCyanString(theMsg)
			} //end if else
		} //end if else
	} //end if
	//--
	return fmt.Println(color.GreyString("LOG | " + DateNowUtc() + " | ") + theMsg)
	//--
} //END FUNCTION


// PRIVATES
var logFilePath string = ""
var logFileFormat string = "plain" // can be: "plain" | "json"
var logToFileAlsoOnConsole bool = false
var logColoredOnConsole bool = false
type logWriterFile struct {}
type logWriteJsonStruct struct {
	Type    string `json:"type"`
	DateUtc string `json:"dateUtc"`
	Message string `json:"message"`
}
func (writer logWriterFile) Write(bytes []byte) (int, error) {
	//--
	var theErr string = ""
	var theMsg string = StrTrimWhitespaces(string(bytes))
	//--
	var theType string = ""
	var colorMsg string = theMsg
	if(StrIPos(theMsg, "[ERROR]") == 0) { // {{{SYNC-SMARTGO-ERR:LEVELS+COLORS}}}
		theType = "error"
		if(logColoredOnConsole) {
			colorMsg = color.HiRedString(colorMsg)
		} //end if
	} else if(StrIPos(theMsg, "[WARNING]") == 0) {
		theType = "warning"
		if(logColoredOnConsole) {
			colorMsg = color.YellowString(colorMsg)
		} //end if
	} else if(StrIPos(theMsg, "[NOTICE]") == 0) {
		theType = "notice"
		if(logColoredOnConsole) {
			colorMsg = color.HiBlueString(colorMsg)
		} //end if
	} else if(StrIPos(theMsg, "[DATA]") == 0) {
		theType = "data"
		if(logColoredOnConsole) {
			colorMsg = color.HiYellowString(colorMsg)
		}
	} else if(StrIPos(theMsg, "[DEBUG]") == 0) {
		theType = "debug"
		if(logColoredOnConsole) {
			colorMsg = color.HiMagentaString(colorMsg)
		} //end if
	} else { // ALL OTHER CASES
		theType = "info"
		if(logColoredOnConsole) {
			if(StrIPos(theMsg, "[OK]") == 0) {
				theType = "ok"
				colorMsg = color.HiGreenString(colorMsg)
			} else {
				colorMsg = color.HiCyanString(colorMsg)
			} //end if else
		} //end if
	} //end if else
	//--
	if(isLogPathSafeDir(logFilePath) != true) {
		theErr = "[ERROR] SmartGo LogFile (" + logFileFormat + ") :: LogFile Path provided is not an existing directory or is not safe: `" + logFilePath + "`"
		if(logColoredOnConsole) {
			fmt.Println(color.RedString(theErr) + " : " + colorMsg)
		} else {
			fmt.Println(theErr + " : " + theMsg)
		} //end if
		return 0, errors.New(theErr)
	} //end if
	//--
	var theFmtMsg string = ""
	var theLogPfx string = ""
	if(logFileFormat == "json") {
		theLogPfx = "json"
		jsonLogStruct := logWriteJsonStruct {
			Type    : theType,
			DateUtc : DateNowUtc(),
			Message : theMsg, // not necessary to normalize spaces
		}
		theFmtMsg = JsonEncode(jsonLogStruct)
	} else if(logFileFormat == "plain") {
		theFmtMsg = StrNormalizeSpaces(theMsg)
	} else {
		theErr = "[ERROR] SmartGo LogFile Invalid Format (" + logFileFormat + ") for LogPath `" + logFilePath + "`"
		if(logColoredOnConsole) {
			fmt.Println(color.RedString(theErr) + " : " + colorMsg)
		} else {
			fmt.Println(theErr + " : " + theMsg)
		} //end if else
		return 0, errors.New(theErr)
	} //end if else
	//--
	dtObjUtc := DateTimeStructUtc("")
	//--
	var theLogFile string = logFilePath + theLogPfx + "log" + "-" + dtObjUtc.Years + "-" + dtObjUtc.Months + "-" + dtObjUtc.Days + "-" + dtObjUtc.Hours + ".log"
	//--
	isSuccess, errMsg := SafePathFileWrite(theFmtMsg + "\n", "a", theLogFile, true)
	//--
	if(errMsg != "") {
		theErr = "[ERROR] SmartGo LogFile (" + logFileFormat + ") write Error `" + theLogFile + "` :: " + errMsg
		if(logColoredOnConsole) {
			fmt.Println(color.RedString(theErr) + " : " + colorMsg)
		} else {
			fmt.Println(theErr + " : " + theMsg)
		} //end if else
		return 0, errors.New(theErr)
	} //end if
	//--
	if(isSuccess != true) {
		theErr = "[ERROR] SmartGo LogFile (" + logFileFormat + ") :: FAILED to write to the log File: `" + theLogFile + "`"
		if(logColoredOnConsole) {
			fmt.Println(color.RedString(theErr) + " : " + colorMsg)
		} else {
			fmt.Println(theErr + " : " + theMsg)
		} //end if else
		return 0, errors.New(theErr)
	} //end if
	//--
	if(logToFileAlsoOnConsole) {
		return fmt.Println(color.GreyString("LOG | " + DateNowUtc() + " | ") + colorMsg)
	} //end if
	//--
	return len(bytes), nil
	//--
} //END FUNCTION


// PRIVATE
func setLogLevelOutput(level string, output io.Writer) { // Example: setLogLevelOutput("WARNING", os.Stderr)
	//--
	level = StrToUpper(StrTrimWhitespaces(level))
	//--
	var mLevel string = "ERROR"
	if(level == "WARNING") {
		mLevel = "WARNING"
	} else if(level == "NOTICE") {
		mLevel = "NOTICE"
	} else if(level == "DATA") {
		mLevel = "DATA"
	} else if(level == "DEBUG") {
		mLevel = "DEBUG"
	} //end if else
	//--
	filter := &logutils.LevelFilter{
		Levels: []logutils.LogLevel{"DEBUG", "DATA", "NOTICE", "WARNING", "ERROR"},
		MinLevel: logutils.LogLevel(mLevel),
		Writer: output,
	}
	log.SetOutput(filter)
	//--
} //END FUNCTION


// PRIVATE
func isLogPathSafeDir(pathForLogs string) bool {
	//--
	if((PathIsEmptyOrRoot(pathForLogs)) ||
		(PathIsBackwardUnsafe(pathForLogs)) ||
		(!PathExists(pathForLogs)) ||
		(!PathIsDir(pathForLogs)) ||
		(!StrEndsWith(pathForLogs, "/"))) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func LogToStdErr(level string) {
	//--
	setLogLevelOutput(level, os.Stderr)
	//--
} //END FUNCTION


func LogToConsole(level string, withColorsOnConsole bool) {
	//--
	logColoredOnConsole = withColorsOnConsole
	//--
	log.SetFlags(0) // custom log with colors, reset all flags
	setLogLevelOutput(level, new(logWriterWithColors))
	//--
} //END FUNCTION


func LogToFile(level string, pathForLogs string, theFormat string, alsoOnConsole bool, withColorsOnConsole bool) {
	//--
	pathForLogs = StrTrimWhitespaces(pathForLogs) // must be (with trailing slash, dir must be existing): a/relative/path/to/log/ | /an/absolute/path/to/log/
	//--
	if(isLogPathSafeDir(pathForLogs) == true) {
		//--
		logColoredOnConsole = withColorsOnConsole
		logToFileAlsoOnConsole = alsoOnConsole
		//--
		logFilePath = pathForLogs // assign
		if(theFormat == "json") {
			logFileFormat = "json"
		} else {
			logFileFormat = "plain"
		} //end if
		//--
		log.SetFlags(0) // custom log, reset all flags
		setLogLevelOutput(level, new(logWriterFile))
		//--
	} else {
		//--
		LogToConsole(level, true)
		//--
	} //end if
	//--
} //END FUNCTION


//-----


func ClearPrintTerminal() {
	//--
	print("\033[H\033[2J") // try to clear the terminal (should work on *nix and windows) ; for *nix only can be: fmt.Println("\033[2J")
	//--
} //END FUNCTION


//-----

// call as: defer PanicHandler()
func PanicHandler() {
	if panicInfo := recover(); panicInfo != nil {
		log.Println("[ERROR] PANIC Recovered:", panicInfo)
		log.Println("[DEBUG] PANIC Trace Stack:", string(debug.Stack()))
	} //end if
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


func safePassComposedKey(plainTextKey string) string { // {{{SYNC-CRYPTO-KEY-DERIVE}}}
	//--
	// This should be used as the basis for a derived key, will be 100% in theory and practice agains hash colissions (see the comments below)
	// It implements a safe mechanism that in order that a key to produce a colission must collide at the same time in all hashing mechanisms: md5, sha1, ha256 and sha512 + crc32b control
	// By enforcing the max key length to 4096 bytes actually will not have any chance to collide even in the lowest hashing such as md5 ...
	// It will return a string of 553 bytes length as: (base:key)[8(crc32b) + 1(null) + 32(md5) + 1(null) + 40(sha1) + 1(null) + 64(sha256) + 1(null) + 128(sha512) = 276] + 1(null) + (base:saltedKeyWithNullBytePrefix)[8(crc32b) + 1(null) + 32(md5) + 1(null) + 40(sha1) + 1(null) + 64(sha256) + 1(null) + 128(sha512) = 276]
	// More, it will return a fixed length (553 bytes) string with an ascii subset just of [ 01234567890abcdef + NullByte ] which already is colission free by using a max source string length of 4096 bytes and by combining many hashes as: md5, sha1, sha256, sha512 and the crc32b
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(plainTextKey != key) {
		log.Println("[WARNING] safePassComposedKey:", "Key is invalid, must not contain trailing spaces !")
		return ""
	} //end if
	//--
	var klen int = len(key)
	if(klen < 7) { // {{{SYNC-CRYPTO-KEY-MIN}}} ; minimum acceptable secure key is 7 characters long
		log.Println("[WARNING] safePassComposedKey:", "Key Size is lower than 7 bytes (", klen, ") which is not safe against brute force attacks !")
		return ""
	} else if(klen > 4096) { // {{{SYNC-CRYPTO-KEY-MAX}}} ; max key size is enforced to allow ZERO theoretical colissions on any of: md5, sha1, sha256 or sha512
		//-- as a precaution, use the lowest supported value which is 4096 (as the md5 supports) ; under this value all the hashes are safe against colissions (in theory)
		// MD5     produces 128 bits which is 16 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 16*256 =  4096 bytes
		// SHA-1   produces 160 bits which is 20 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 20*256 =  5120 bytes
		// SHA-256 produces 256 bits which is 32 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 32*256 =  8192 bytes
		// SHA-512 produces 512 bits which is 64 bytes, not characters, each byte has 256 possible values ; theoretical safe max colission free is: 64*256 = 16384 bytes
		//-- anyway, as a more precaution, combine all hashes thus a key should produce a colission at the same time in all: md5, sha1, sha256 and sha512 ... which in theory, event with bad implementations of the hashing functions this is excluded !
		log.Println("[WARNING] safePassComposedKey:", "Key Size is higher than 4096 bytes (", klen, ") which is not safe against collisions !")
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


func SafePassHashArgon2id824(plainTextKey string) string {
	//--
	var composedKey string = safePassComposedKey(plainTextKey)
	var len_composedKey int = len(composedKey)
	var len_trimmed_composedKey int = len(StrTrimWhitespaces(composedKey))
	if((len_composedKey != 553) || (len_trimmed_composedKey != 553)) {
		log.Println("[WARNING] SafePassHashArgon2id824:", "Safe Composed Key is invalid (", len_composedKey, "/", len_trimmed_composedKey, ") !")
		return ""
	} //end if
	//--
	var salt string = FIXED_CRYPTO_SALT + NULL_BYTE // use a fixed salt with a safe composed derived key to be safe against colissions ; if the salt is random there is no more safety against colissions ...
	salt = Bin2Hex(salt)
	salt = base32.Encode([]byte(salt))
	salt = base36.Encode([]byte(salt))
	salt = base58.Encode([]byte(salt))
	salt = base62.Encode([]byte(salt))
	salt = Base64sEncode(salt)
	salt = base85.Encode([]byte(salt))
	salt = StrSubstr(RightPad2Len(Md5B64(salt), "#", 28), 0, 28)
	//fmt.Println("Argon2id Salt:", salt)
	//--
	key := argon2.IDKey([]byte(composedKey), []byte(salt), 21, 512*1024, 1, 103) // Argon2id resources: 21 cycles, 512MB memory, 1 thread, 103 bytes = 824 bits ; return as base92 encoded with a fixed length of 128 bytes (1024 bits) by padding b92 encoded data on the right with ' character
	//--
	return StrSubstr(RightPad2Len(base92.Encode(key), "'", 128), 0, 128) // add right padding with '
	//--
} //END FUNCTION


//-----


func cryptoPacketCheckAndDecode(str string, fx string, ver uint8) string {
	//--
	defer PanicHandler() // req. by b64 decrypt panic handler with malformed data
	//--
	if((ver != 2) && (ver != 1)) {
		log.Println("[NOTICE]", fx, "Invalid Version:", ver)
		return ""
	} //end if
	//--
	if(str == "") {
		log.Println("[NOTICE]", fx, "Empty Data Packet, v:", ver)
		return ""
	} //end if
	str = StrTrimWhitespaces(str)
	if(str == "") {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, v:", ver)
		return ""
	} //end if
	//--
	var separator string = ""
	if(ver == 1) {
		separator = SEPARATOR_CHECKSUM_V1
	} else {
		separator = SEPARATOR_CHECKSUM_V2
	} //end if else
	if(separator == "") {
		log.Println("[NOTICE]", fx, "Empty Data Packet Checksum Separator, v:", ver)
		return ""
	} //end if
	//--
	if(!StrContains(str, separator)) {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, no Checksum v:", ver)
		return ""
	} //end if
	//--
	darr := Explode(separator, str)
	str = ""
	var dlen int = len(darr)
	if(dlen < 2) {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, Checksum not found v:", ver)
		return ""
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, Checksum is Empty v:", ver)
		return ""
	} //end if
	if(darr[0] == "") {
		log.Println("[NOTICE]", fx, "Invalid Data Packet, Packed Data not found v:", ver)
		return ""
	} //end if
	//--
	if(ver == 1) {
		if(Sha1(darr[0]) != darr[1]) {
			log.Println("[NOTICE]", fx, "Invalid Data Packet (v.1), Checksum FAILED :: A checksum was found but is invalid:", darr[1])
			return ""
		} //end if
	} else {
		if(Sha256B64(darr[0]) != darr[1]) {
			log.Println("[NOTICE]", fx, "Invalid Data Packet (v.2), Checksum FAILED :: A checksum was found but is invalid:", darr[1])
			return ""
		} //end if
	} //end if else
	//--
	return Base64Decode(darr[0])
	//--
} //END FUNCTION


//-----


func threefishSafeKey(plainTextKey string) string { // {{{SYNC-CRYPTO-KEY-DERIVE}}}
	//--
	defer PanicHandler() // req. by hex2bin panic handler with malformed data
	//--
	var composedKey string = safePassComposedKey(plainTextKey)
	var len_composedKey int = len(composedKey)
	var len_trimmed_composedKey int = len(StrTrimWhitespaces(composedKey))
	if((len_composedKey != 553) || (len_trimmed_composedKey != 553)) {
		log.Println("[WARNING] threefishSafeKey:", "Safe Composed Key is invalid (", len_composedKey, "/", len_trimmed_composedKey, ") !")
		return ""
	} //end if
	//--
	var derivedKey string = LeftPad2Len(Crc32bB36(composedKey), "0", 8) + "'" + base92.Encode([]byte(Hex2Bin(Sha512(composedKey)))) + "'" + base92.Encode([]byte(Hex2Bin(Sha256(composedKey))))
	var safeKey string = StrSubstr(RightPad2Len(derivedKey, "'", 128), 0, 1024/8) // 1024/8
	//log.Println("[DEBUG] 3fKey:", safeKey)
	return safeKey
	//--
} //END FUNCTION


func threefishSafeIv(plainTextKey string) string {
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(key == "") {
		log.Println("[WARNING] threefishSafeIv:", "Key is Empty !")
		return ""
	} //end if
	//--
	var safeIv string = StrSubstr(Sha512(key), 0, 1024/8) // 1024/8
	//--
	//log.Println("[DEBUG] 3fIv:", safeIv)
	return safeIv
	//--
} //END FUNCTION


func threefishSafeTweak(plainTextKey string, derivedKey string) string {
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(key == "") {
		log.Println("[WARNING] threefishSafeTweak:", "Key is Empty !")
		return ""
	} //end if
	//--
	if(StrTrimWhitespaces(derivedKey) == "") {
		log.Println("[WARNING] threefishSafeTweak:", "Derived Key is Empty !")
		return ""
	} //end if
	//--
	var safeTweak string = LeftPad2Len(StrSubstr(Crc32b(key) + Crc32b(derivedKey), 0, 128/8), "0", 128/8) // 128/8
	//--
	//log.Println("[DEBUG] 3fTweak:", safeTweak)
	return safeTweak
	//--
} //END FUNCTION


func ThreefishEncryptCBC(str string, key string, useArgon2id bool) string {
	//--
	defer PanicHandler() // req. by cipher encrypt panic handler with wrong padded data
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	str = Base64Encode(str)
	cksum := Sha256B64(str)
	str = str + SEPARATOR_CHECKSUM_V2 + cksum
	//log.Println("[DEBUG] BfTxt: " + str)
	//--
	var theSignature string = ""
	var derivedKey string = "" // 128 bytes
	if(useArgon2id == true) {
		theSignature = SIGNATURE_3FISH_V1_ARGON2ID
		derivedKey = SafePassHashArgon2id824(key) // b92
	} else {
		theSignature = SIGNATURE_3FISH_V1_DEFAULT
		derivedKey = threefishSafeKey(key) // ~ b92
	} //end if else
	if(len(derivedKey) != 128) {
		log.Println("[WARNING] ThreefishEncryptCBC:", "Derived Key Size must be 128 bytes")
		return ""
	} //end if
	var tweak string = threefishSafeTweak(key, derivedKey) // 16 bytes, hex
	if(len(tweak) != 16) {
		log.Println("[WARNING] ThreefishEncryptCBC:", "Tweak Size must be 16 bytes")
		return ""
	} //end if
	var iv string = threefishSafeIv(key) // 128 bytes, hex
	if(len(iv) != 128) {
		log.Println("[WARNING] ThreefishEncryptCBC:", "iV Size must be 128 bytes")
		return ""
	} //end if
	//--
	block, err := threefish.New1024([]byte(derivedKey), []byte(tweak))
	if(err != nil) {
		log.Println("[WARNING] ThreefishEncryptCBC:", err)
		return ""
	} //end if
	//fmt.Println("Threefish BlockSize is:", block.BlockSize());
	//-- fix padding
	var slen int = len(str)
	var modulus int = slen % block.BlockSize()
	if(modulus > 0) {
		var padlen int = block.BlockSize() - modulus
		str = RightPad2Len(str, " ", slen + padlen) // pad with spaces
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
		log.Println("[WARNING] ThreefishEncryptCBC: Invalid Hex Header")
		return ""
	} //end if
	encTxt = StrTrimWhitespaces(StrSubstr(encTxt, block.BlockSize()*2, 0)) // fix: {{{FIX-GOLANG-THREEFISH-1ST-128-NULL-BYTES}}} ; there are 256 trailing zeroes that represent the HEX of 128 null bytes ; remove them
	if(encTxt == "") {
		log.Println("[WARNING] ThreefishEncryptCBC: Empty Hex Body") // must be some data after the 128 null bytes null header
		return ""
	} //end if
	//--
	return theSignature + Base64sEncode(Hex2Bin(encTxt)) // signature
	//--
} //END FUNCTION


func ThreefishDecryptCBC(str string, key string, useArgon2id bool) string {
	//--
	defer PanicHandler() // req. by crypto decrypt panic handler with malformed data
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
		derivedKey = SafePassHashArgon2id824(key) // b92
	} else {
		theSignature = SIGNATURE_3FISH_V1_DEFAULT
		derivedKey = threefishSafeKey(key) // ~ b92
	} //end if else
	if(len(derivedKey) != 128) {
		log.Println("[WARNING] ThreefishDecryptCBC:", "Derived Key Size must be 128 bytes")
		return ""
	} //end if
	var tweak string = threefishSafeTweak(key, derivedKey) // 16 bytes, hex
	if(len(tweak) != 16) {
		log.Println("[WARNING] ThreefishDecryptCBC:", "Tweak Size must be 16 bytes")
		return ""
	} //end if
	var iv string = threefishSafeIv(key) // 128 bytes, hex
	if(len(iv) != 128) {
		log.Println("[WARNING] ThreefishDecryptCBC:", "iV Size must be 128 bytes")
		return ""
	} //end if
	//--
	block, err := threefish.New1024([]byte(derivedKey), []byte(tweak))
	if(err != nil) {
		log.Println("[WARNING] ThreefishDecryptCBC:", err)
		return ""
	} //end if
	//--
	if(StrTrimWhitespaces(theSignature) == "") {
		log.Println("[WARNING] ThreefishDecryptCBC Empty Signature provided")
	} //end if
	if(!StrContains(str, theSignature)) {
		log.Println("[WARNING] ThreefishDecryptCBC Signature was not found")
		return ""
	} //end if
	sgnArr := Explode("!", str)
	str = StrTrimWhitespaces(sgnArr[1])
	sgnArr = nil
	if(str == "") {
		log.Println("[WARNING] ThreefishDecryptCBC B64s Part not found")
		return ""
	} //end if
	str = Base64sDecode(str)
	if(str == "") {
		log.Println("[WARNING] ThreefishDecryptCBC B64s Decode Failed")
		return ""
	} //end if
	str = Hex2Bin(strings.Repeat("0", block.BlockSize()*2) + Bin2Hex(str)) // fix: {{{FIX-GOLANG-THREEFISH-1ST-128-NULL-BYTES}}} ; add back the 256 trailing null bytes as HEX
	if(str == "") {
		log.Println("[WARNING] ThreefishDecryptCBC Hex Header Restore and Decode Failed")
		return ""
	} //end if
	//--
	et := []byte(str)
	str = ""
	decrypted := et[block.BlockSize():]
	et = nil
	if(len(decrypted) % block.BlockSize() != 0) { //-- check last slice of encrypted text, if it's not a modulus of cipher block size, it's a problem
		log.Println("[NOTICE] ThreefishDecryptCBC: decrypted is not a multiple of block.BlockSize() #", block.BlockSize())
		return ""
	} //end if
	dcbc := cipher.NewCBCDecrypter(block, []byte(iv))
	dcbc.CryptBlocks(decrypted, decrypted)
	//--
	return cryptoPacketCheckAndDecode(string(decrypted), "ThreefishDecryptCBC", 2)
	//--
} //END FUNCTION


//-----


// PRIVATE : Blowfish key @ v1 # ONLY FOR COMPATIBILITY : DECRYPT SUPPORT ONLY
func blowfishV1SafeKey(plainTextKey string) string {
	//--
	var key string = StrTrimWhitespaces(plainTextKey)
	if(key == "") {
		log.Println("[WARNING] blowfishV1SafeKey:", "Key is Empty !")
		return ""
	} //end if
	//--
	var safeKey string = StrSubstr(Sha512(key), 13, 29+13) + StrToUpper(StrSubstr(Sha1(key), 13, 10+13)) + StrSubstr(Md5(key), 13, 9+13)
	//--
	//log.Println("[DEBUG] BfKey (v1):", safeKey)
	return safeKey
	//--
} //END FUNCTION


// PRIVATE : Blowfish iv @ v1 # ONLY FOR COMPATIBILITY : DECRYPT SUPPORT ONLY
func blowfishV1SafeIv(plainTextKey string) string {
	//--
	var key string = StrTrimWhitespaces(plainTextKey)
	if(key == "") {
		log.Println("[WARNING] blowfishV1SafeKey:", "Key is Empty !")
		return ""
	} //end if
	//--
	var safeIv string = Base64Encode(Sha1("@Smart.Framework-Crypto/BlowFish:" + key + "#" + Sha1("BlowFish-iv-SHA1" + key) + "-" + StrToUpper(Md5("BlowFish-iv-MD5" + key)) + "#"))
	safeIv = StrSubstr(safeIv, 1, 8+1)
	//log.Println("[DEBUG] BfIv (v1):", safeIv)
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
		log.Println("[WARNING] blowfishSafeKey:", "Safe Composed Key is invalid (", len_composedKey, "/", len_trimmed_composedKey, ") !")
		return ""
	} //end if
	//--
	var derivedKey string = base92.Encode([]byte(Hex2Bin(Sha256(composedKey)))) + "'" + base92.Encode([]byte(Hex2Bin(Md5(composedKey))))
	var safeKey string = StrSubstr(derivedKey, 0, 448/8) // 448/8
	//log.Println("[DEBUG] BfKey:", safeKey)
	return safeKey
	//--
} //END FUNCTION


// PRIVATE : Blowfish iv {{{SYNC-BLOWFISH-IV}}}
func blowfishSafeIv(plainTextKey string) string {
	//--
	var key string = StrTrimWhitespaces(plainTextKey) // {{{SYNC-CRYPTO-KEY-TRIM}}}
	if(key == "") {
		log.Println("[WARNING] blowfishSafeIv:", "Key is Empty !")
		return ""
	} //end if
	//--
	var data string = LeftPad2Len(Crc32bB36(key), "0", 8)
	var safeIv string = StrSubstr(data + ":" + Sha1B64(key), 0, 64/8) // 64/8
	//--
	//log.Println("[DEBUG] BfIv:", safeIv)
	return safeIv
	//--
} //END FUNCTION


func BlowfishEncryptCBC(str string, key string) string {
	//--
	defer PanicHandler() // req. by blowfish encrypt panic handler with wrong padded data
	//-- check
	if(str == "") {
		return ""
	} //end if
	//-- prepare string
	str = Base64Encode(str)
	cksum := Sha256B64(str)
	str = str + SEPARATOR_CHECKSUM_V2 + cksum
	//log.Println("[DEBUG] BfTxt: " + str)
	//-- fix padding
	var slen int = len(str)
	var modulus int = slen % blowfish.BlockSize
	if(modulus > 0) {
		var padlen int = blowfish.BlockSize - modulus
		str = RightPad2Len(str, " ", slen + padlen) // pad with spaces
		slen = slen + padlen
	} //end if
	//--
	var derivedKey string = blowfishSafeKey(key) // 56 bytes
	if(len(derivedKey) != 56) {
		log.Println("[WARNING] BlowfishEncryptCBC:", "Derived Key Size must be 56 bytes")
		return ""
	} //end if
	var iv string = blowfishSafeIv(key) // 8 bytes
	if(len(iv) != 8) {
		log.Println("[WARNING] BlowfishEncryptCBC:", "iV Size must be 128 bytes")
		return ""
	} //end if
	//-- create the cipher
	ecipher, err := blowfish.NewCipher([]byte(derivedKey))
	if(err != nil) {
		log.Println("[WARNING] BlowfishEncryptCBC:", err)
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
		log.Println("[WARNING] BlowfishEncryptCBC: Invalid Hex Header")
		return ""
	} //end if
	encTxt = StrTrimWhitespaces(StrSubstr(encTxt, prePaddingSize, 0)) // fix: {{{FIX-GOLANG-BLOWFISH-1ST-8-NULL-BYTES}}} ; there are 16 trailing zeroes that represent the HEX of 8 null bytes ; remove them
	if(encTxt == "") {
		log.Println("[WARNING] BlowfishEncryptCBC: Empty Hex Body") // must be some data after the 8 bytes null header
		return ""
	} //end if
	//--
	return SIGNATURE_BFISH_V2 + Base64sEncode(Hex2Bin(encTxt))
	//--
} //END FUNCTION


func BlowfishDecryptCBC(str string, key string) string {
	//--
	defer PanicHandler() // req. by blowfish decrypt panic handler with malformed data
	//-- check
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	var versionDetected uint8 = 0
	if(StrPos(str, SIGNATURE_BFISH_V2) == 0) {
		versionDetected = 2;
	} else if(StrPos(str, SIGNATURE_BFISH_V1) == 0) {
		versionDetected = 1;
	} else {
		str = SIGNATURE_BFISH_V1 + str // if no signature found consider it is v1 and try to dercypt
		versionDetected = 1;
	} //end if
	//--
	sgnArr := Explode("!", str)
	str = StrTrimWhitespaces(sgnArr[1])
	sgnArr = nil
	if(str == "") {
		log.Println("[WARNING] BlowfishDecryptCBC B64s Part not found")
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
		log.Println("[WARNING] BlowfishDecryptCBC Hex Header Restore and Decode Failed")
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
			log.Println("[WARNING] BlowfishDecryptCBC (v1):", "Derived Key Size must be 48 bytes")
			return ""
		} //end if
	} else { // v2
		derivedKey = blowfishSafeKey(key) // 56 bytes
		if(len(derivedKey) != 56) {
			log.Println("[WARNING] BlowfishDecryptCBC (v2):", "Derived Key Size must be 56 bytes")
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
		log.Println("[WARNING] BlowfishDecryptCBC:", "iV Size must be 128 bytes")
		return ""
	} //end if
	//-- create the cipher
	dcipher, err := blowfish.NewCipher([]byte(derivedKey))
	if(err != nil) {
		//-- fix this. its okay for this tester program, but...
		log.Println("[WARNING] BlowfishDecryptCBC:", err)
		return ""
	} //end if
	//-- make initialisation vector {{{SYNC-BLOWFISH-IV}}}
	div := []byte(iv)
	//-- check last slice of encrypted text, if it's not a modulus of cipher block size, it's a problem
	decrypted := et[blowfish.BlockSize:]
	if(len(decrypted) % blowfish.BlockSize != 0) {
		log.Println("[NOTICE] BlowfishDecryptCBC: decrypted is not a multiple of blowfish.BlockSize")
		return ""
	} //end if
	//-- ok, all good... create the decrypter
	dcbc := cipher.NewCBCDecrypter(dcipher, div)
	//-- decrypt
	dcbc.CryptBlocks(decrypted, decrypted)
	//--
	return cryptoPacketCheckAndDecode(string(decrypted), "BlowfishDecryptCBC", versionDetected)
	//--
} //END FUNCTION


//-----


func GzEncode(str string, level int) string {
	//--
	defer PanicHandler() // req. by gz encode panic handler with malformed data
	//--
	if(str == "") {
		return ""
	} //end if
	//--
	if((level < 1) || (level > 9)) {
		level = -1 // zlib default compression
	} //end if
	//--
	var b bytes.Buffer
	w, err := gzip.NewWriterLevel(&b, level) // RFC 1952 (gzip compatible)
	//--
	if(err != nil) {
		log.Println("[NOTICE] GzDeflate:", err)
		return ""
	} //end if
	//--
	w.Write([]byte(str))
	w.Close()
	//--
	var out string = b.String()
	if(out == "") {
		log.Println("[NOTICE] GzEncode:", "Empty Arch Data")
		return ""
	} //end if
	//--
	return out
	//--
} //END FUNCTION


func GzDecode(str string) string {
	//--
	defer PanicHandler() // req. by gz decode panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	b := bytes.NewReader([]byte(str))
	r, err := gzip.NewReader(b) // RFC 1952 (gzip compatible)
	if(err != nil) {
		log.Println("[NOTICE] GzDecode:", err)
		return ""
	} //end if
	bb2 := new(bytes.Buffer)
	_, _ = io.Copy(bb2, r)
	r.Close()
	byts := bb2.Bytes()
	//--
	var out string = string(byts)
	if(out == "") {
		log.Println("[NOTICE] GzDecode:", "Empty UnArch Data")
		return ""
	} //end if
	//--
	return out
	//--
} //END FUNCTION


//-----


func GzDeflate(str string, level int) string {
	//--
	defer PanicHandler() // req. by gz deflate panic handler with malformed data
	//--
	if(str == "") {
		return ""
	} //end if
	//--
	if((level < 1) || (level > 9)) {
		level = -1 // zlib default compression
	} //end if
	//--
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, level) // RFC 1951
	//--
	if(err != nil) {
		log.Println("[NOTICE] GzDeflate:", err)
		return ""
	} //end if
	//--
	w.Write([]byte(str))
	w.Close()
	//--
	var out string = b.String()
	if(out == "") {
		log.Println("[NOTICE] GzDeflate:", "Empty Arch Data")
		return ""
	} //end if
	//--
	return out
	//--
} //END FUNCTION


func GzInflate(str string) string {
	//--
	defer PanicHandler() // req. by gz inflate panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	b := bytes.NewReader([]byte(str))
	r := flate.NewReader(b) // RFC 1951
	bb2 := new(bytes.Buffer)
	_, _ = io.Copy(bb2, r)
	r.Close()
	byts := bb2.Bytes()
	//--
	var out string = string(byts)
	if(out == "") {
		log.Println("[NOTICE] GzInflate:", "Empty UnArch Data")
		return ""
	} //end if
	//--
	return out
	//--
} //END FUNCTION


//-----


func DataUnArchive(str string) string {
	//--
	defer PanicHandler() // req. by gz hex2bin panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	arr := Explode("\n", str)
	str = ""
	var alen int = len(arr)
	//--
	arr[0] = StrTrimWhitespaces(arr[0])
	if(arr[0] == "") {
		log.Println("[NOTICE] Data Unarchive // Invalid Package Format")
		return ""
	} //end if
	//--
	var versionDetected uint8 = 0
	if(alen < 2) {
		log.Println("[NOTICE] Data Unarchive // Empty Package Signature")
		//arr = append(arr, "") // fix: add missing arr[1] to avoid panic below ; no more needed as will exit below if this err happen
		return ""
	} else {
		arr[1] = StrTrimWhitespaces(arr[1])
		if(arr[1] == SIGNATURE_SFZ_DATA_ARCH_V2) {
			versionDetected = 2
		} else if(arr[1] == SIGNATURE_SFZ_DATA_ARCH_V1) {
			versionDetected = 1
		} //end if else
		if(versionDetected <= 0) {
			log.Println("[NOTICE] Data Unarchive // Invalid Package (version:", versionDetected, ") Signature:", arr[1])
			return ""
		} //end if
	} //end if
	//--
	arr[0] = Base64Decode(arr[0])
	if(arr[0] == "") {
		log.Println("[NOTICE] Data Unarchive // Invalid B64 Data for packet (version:", versionDetected, ") with signature:", arr[1])
		return ""
	} //end if
	//--
	arr[0] = GzInflate(arr[0])
	if(arr[0] == "") {
		log.Println("[NOTICE] Data Unarchive // Invalid Zlib GzInflate Data for packet (version:", versionDetected, ") with signature:", arr[1])
		return ""
	} //end if
	//--
	const txtErrExpl = "This can occur if decompression failed or an invalid packet has been assigned ..."
	//--
	var versionCksumSeparator string = ""
	if(versionDetected == 1) {
		versionCksumSeparator = SEPARATOR_CHECKSUM_V1
	} else { // v2
		versionCksumSeparator = SEPARATOR_CHECKSUM_V2
	} //end if else
	//--
	if((versionCksumSeparator == "") || (!StrContains(arr[0], versionCksumSeparator))) {
		log.Println("[NOTICE] Invalid Packet (version:", versionDetected, "), no Checksum:", txtErrExpl)
		return ""
	} //end if
	//--
	darr := Explode(versionCksumSeparator, arr[0])
	arr = nil
	var dlen int = len(darr)
	if(dlen < 2) {
		log.Println("[NOTICE] Invalid Packet (version:", versionDetected, "), Checksum not found:", txtErrExpl)
		return ""
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		log.Println("[NOTICE] Invalid Packet (version:", versionDetected, "), Checksum is Empty:", txtErrExpl)
		return ""
	} //end if
	if(darr[0] == "") {
		log.Println("[NOTICE] Invalid Packet (version:", versionDetected, "), Data not found:", txtErrExpl)
		return ""
	} //end if
	//--
	if(versionDetected == 1) {
		darr[0] = Hex2Bin(StrToLower(darr[0]))
	} else { // v2
		darr[0] = Hex2Bin(darr[0])
	} //end if else
	if(darr[0] == "") {
		log.Println("[NOTICE] Data Unarchive // Invalid HEX Data for packet (version:", versionDetected, ") with signature:", arr[1])
		return ""
	} //end if
	//--
	var chkSignature bool = false
	if(versionDetected == 1) {
		if(Sha1(darr[0]) == darr[1]) {
			chkSignature = true
		} //end if
	} else { // v2
		if(Sha256(darr[0]) == darr[1]) {
			chkSignature = true
		} //end if
	} //end if else
	//--
	if(chkSignature != true) {
		log.Println("[NOTICE] Data Unarchive // Invalid Packet (version:", versionDetected, "), Checksum FAILED :: A checksum was found but is invalid:", darr[1])
		return ""
	} //end if
	//--
	return darr[0]
	//--
} //END FUNCTION


func DataArchive(str string) string {
	//--
	defer PanicHandler() // req. by gz deflate panic handler with malformed data
	//--
	var ulen int = len(str)
	if((str == "") || (ulen <= 0)) {
		return ""
	} //end if
	//--
	var chksum string = Sha256(str)
	var data string = StrTrimWhitespaces(Bin2Hex(str)) + SEPARATOR_CHECKSUM_V2 + chksum
	str = ""
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
		log.Println("[ERROR] Data Archive // ZLib Data Ratio is zero:", ratio)
		return ""
	} //end if
	if(ratio > 32768) { // check for this bug in ZLib {{{SYNC-GZ-ARCHIVE-ERR-CHECK}}}
		log.Println("[ERROR] Data Archive // ZLib Data Ratio is higher than 32768:", ratio)
		return ""
	} //end if
	//log.Println("[DEBUG] Data Archive // ZLib Data Ratio is: ", ratio, " by division of: ", ulen, " with: (/) ", alen)
	//--
	arch = StrTrimWhitespaces(Base64Encode(arch)) + "\n" + SIGNATURE_SFZ_DATA_ARCH_V2
	//--
	var unarch_chksum string = Sha256(DataUnArchive(arch))
	if(unarch_chksum != chksum) {
		log.Println("[ERROR] Data Archive // Data Encode Check Failed")
		return ""
	} //end if
	//--
	return arch
	//-- str
} //END FUNCTION


//-----


func LeftPad2Len(s string, padStr string, overallLen int) string { // LeftPad2Len https://github.com/DaddyOh/golang-samples/blob/master/pad.go
	//--
	var padCountInt int = 1 + ((overallLen - len(padStr)) / len(padStr))
	var retStr string = strings.Repeat(padStr, padCountInt) + s
	//--
	return retStr[(len(retStr) - overallLen):]
	//--
} //END FUNCTION


func RightPad2Len(s string, padStr string, overallLen int) string { // RightPad2Len https://github.com/DaddyOh/golang-samples/blob/master/pad.go
	//--
	var padCountInt int = 1 + ((overallLen - len(padStr)) / len(padStr))
	var retStr string = s + strings.Repeat(padStr, padCountInt)
	//--
	return retStr[:overallLen]
	//--
} //END FUNCTION


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
	log.Println("[ERROR] BaseEncode:", "Invalid Encoding Base: `" + toBase + "`")
	return ""
	//--
} //END FUNCTION


func BaseDecode(data string, fromBase string) []byte {
	//--
	defer PanicHandler()
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
		err = errors.New("Invalid Decoding Base: `" + fromBase + "`")
	} //end if else
	//--
	if(err != nil) {
		log.Println("[ERROR] BaseDecode:", err)
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
	decoded, err := base64.StdEncoding.DecodeString(data)
	if(err != nil) {
		log.Println("[NOTICE] Base64Decode: ", err)
		//return "" // be flexible, don't return, try to decode as much as possible ...
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
	return LeftPad2Len(StrToLower(base36.Encode(hash.Sum(nil))), "0", 7)
	//--
} //END FUNCTION


//-----


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
		return -1
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
	return StrPos(StrToLower(haystack), StrToLower(needle))
	//--
} //END FUNCTION


// case sensitive, find position of last occurrence of string in a string ; multi-byte safe
// return -1 if can not find the substring or the position of needle in haystack
func StrRPos(haystack string, needle string) int {
	//--
	if((haystack == "") || (needle == "")) {
		return -1
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
	return StrRPos(StrToLower(haystack), StrToLower(needle))
	//--
} //END FUNCTION


//-----


func StrStartsWith(str string, part string) bool {
	//--
	return strings.HasPrefix(str, part)
	//--
} //END FUNCTION


func StrIStartsWith(str string, part string) bool {
	//--
	return strings.HasPrefix(StrToLower(str), StrToLower(part))
	//--
} //END FUNCTION


func StrEndsWith(str string, part string) bool {
	//--
	return strings.HasSuffix(str, part)
	//--
} //END FUNCTION


func StrIEndsWith(str string, part string) bool {
	//--
	return strings.HasSuffix(StrToLower(str), StrToLower(part))
	//--
} //END FUNCTION


func StrContains(str string, part string) bool {
	//--
	return strings.Contains(str, part)
	//--
} //END FUNCTION


func StrIContains(str string, part string) bool {
	//--
	return strings.Contains(StrToLower(str), StrToLower(part))
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


// case sensitive replacer ; for case insensitive must use StrRegexReplaceAll()
func StrReplaceAll(s string, part string, replacement string) string {
	//--
	return strings.ReplaceAll(s, part, replacement)
	//--
} //END FUNCTION


// case sensitive replacer ; for case insensitive write your own function ;-)
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


func ConvertUIntToStr(i uint) string {
	//--
	return strconv.Itoa(int(i))
	//--
} //END FUNCTION


func ConvertInt16ToStr(i int16) string {
	//--
	return strconv.FormatInt(int64(i), 10)
	//--
} //END FUNCTION


func ConvertUInt16ToStr(i uint16) string {
	//--
	return strconv.FormatUint(uint64(i), 10)
	//--
} //END FUNCTION


func ConvertInt32ToStr(i int32) string {
	//--
	return strconv.FormatInt(int64(i), 10)
	//--
} //END FUNCTION


func ConvertUInt32ToStr(i uint32) string {
	//--
	return strconv.FormatUint(uint64(i), 10)
	//--
} //END FUNCTION


func ConvertInt64ToStr(i int64) string {
	//--
	return strconv.FormatInt(i, 10)
	//--
} //END FUNCTION


func ConvertUInt64ToStr(i uint64) string {
	//--
	return strconv.FormatUint(i, 10)
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


func ParseIntegerStrAsUInt(s string) uint {
	//--
	var Int int = ParseIntegerStrAsInt(s)
	//--
	return uint(Int)
	//--
} //END FUNCTION


func ParseIntegerStrAsInt64(s string) int64 {
	//--
	var Int64 int64 = 0 // set the integer as zero Int64, in the case of parseInt Error
	//--
	tmpInt64, err := strconv.ParseInt(s, 10, 64)
	if(err == nil) {
		Int64 = tmpInt64
	} //end if else
	//--
	return Int64
	//--
} //END FUNCTION


func ParseIntegerStrAsUInt64(s string) uint64 {
	//--
	var Int64 int64 = ParseIntegerStrAsInt64(s)
	//--
	return uint64(Int64)
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


func StrToUpper(str string) string {
	//--
	return strings.ToUpper(str)
	//--
} //END FUNCTION


func StrToLower(str string) string {
	//--
	return strings.ToLower(str)
	//--
} //END FUNCTION


// ChunkSplit chunk_split()
func StrChunkSplit(body string, chunklen uint, end string) string { // github.com/syyongx/php2go/blob/master/php.go
	//--
	if(end == "") {
		return body
	} //end if
	//--
	runes, erunes := []rune(body), []rune(end)
	l := uint(len(runes))
	if((l <= 1) || (l < chunklen)) {
		return body + end
	} //end if
	ns := make([]rune, 0, len(runes)+len(erunes))
	var i uint
	for i = 0; i < l; i += chunklen {
		if(i+chunklen > l) {
			ns = append(ns, runes[i:]...)
		} else {
			ns = append(ns, runes[i:i+chunklen]...)
		} //end if else
		ns = append(ns, erunes...)
	} //end for
	//--
	return string(ns)
	//--
} //END FUNCTION


// StrWordCount str_word_count()
func StrWordCount(str string) []string { // github.com/syyongx/php2go/blob/master/php.go
	//--
	return strings.Fields(str)
	//--
} //END FUNCTION


// Strlen strlen()
func StrLen(str string) int {
	//--
	return len(str)
	//--
} //END FUNCTION


// MbStrlen mb_strlen()
func StrUnicodeLen(str string) int { // github.com/syyongx/php2go/blob/master/php.go
	//--
	return utf8.RuneCountInString(str)
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
	defer PanicHandler() // req. by transform panic handler with malformed data
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


func StrRegexMatchString(rexpr string, s string) bool {
	//--
	if((StrTrimWhitespaces(rexpr) == "") || (s == "")) { // s must NOT be trimmed
		return false
	} //end if
	//--
	matched, _ := regexp.MatchString(rexpr, s)
	//--
	return matched
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
	defer PanicHandler() // req. by hex2bin panic handler with malformed data
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


func jsonEncode(data interface{}, prettyprint bool, htmlsafe bool) string {
	//-- no need any panic handler
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(htmlsafe)
	if(prettyprint == true) {
		encoder.SetIndent("", "    ") // 4 spaces
	} //end if
	//--
	err := encoder.Encode(data)
	if(err != nil) {
		log.Println("[NOTICE] JsonEncode Failed:", err)
		return ""
	} //end if
	//--
	return StrTrimWhitespaces(buffer.String()) // must trim as will add a new line at the end ...
	//--
} //END FUNCTION


func JsonEncodePretty(data interface{}) string { // HTML Safe, Pretty
	//--
	return jsonEncode(data, true, true)
	//--
} //END FUNCTION
func JsonRawEncodePretty(data interface{}) string { // HTML Not Safe (raw), Pretty
	//--
	return jsonEncode(data, true, false)
	//--
} //END FUNCTION


func JsonEncode(data interface{}) string { // HTML Safe
	//--
	return jsonEncode(data, false, true)
	//--
} //END FUNCTION
func JsonRawEncode(data interface{}) string { // HTML Not Safe (raw)
	//--
	return jsonEncode(data, false, false)
	//--
} //END FUNCTION


func JsonDecode(data string) map[string]interface{} {
	//-- no need any panic handler
	if(data == "") {
		return nil
	} //end if
	//--
	var dat map[string]interface{}
	dataReader := strings.NewReader(data)
	decoder := json.NewDecoder(dataReader)
	err := decoder.Decode(&dat)
	if(err != nil) {
		log.Println("[NOTICE] JsonDecode Failed:", err)
		return nil
	} //end if
	//--
	return dat
	//--
} //END FUNCTION


func AddCSlashes(s string, c string) string {
	//--
	var tmpRune []rune
	//--
	strRune := []rune(s)
	list := []rune(c)
	for _, ch := range strRune {
		for _, v := range list {
			if ch == v {
				tmpRune = append(tmpRune, '\\')
			} //end if
		} //end for
		tmpRune = append(tmpRune, ch)
	} //end for
	//--
	return string(tmpRune)
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


func EscapeHtml(s string) string { // provides a Smart.Framework ~ EscapeHtml
	//--
	if(s == "") {
		return ""
	} //end if
	//--
	return html.EscapeString(s) // escapes these five characters: < > & ' "
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


func EscapeUrl(s string) string { // provides a Smart.Framework ~ EscapeUrl, an alias to RawUrlEncode
	//--
	return RawUrlEncode(s)
	//--
} //END FUNCTION


func RawUrlEncode(s string) string {
	//--
	return StrReplaceAll(url.QueryEscape(s), "+", "%20")
	//--
} //END FUNCTION


func RawUrlDecode(s string) string {
	//--
	defer PanicHandler() // req. by raw url decode panic handler with malformed data
	//--
	u, _ := url.QueryUnescape(StrReplaceAll(s, "%20", "+"))
	//--
	return u
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


func MimeTypeByFileExtension(fext string) string {
	//--
	fext = StrTrimWhitespaces(fext)
	if(fext == "") {
		return ""
	} //end if
	//--
	return mime.TypeByExtension(fext)
	//--
} //END FUNCTION


func MimeTypeByFilePath(path string) string {
	//--
	path = StrTrimWhitespaces(path)
	if(path == "") {
		return ""
	} //end if
	//--
	return MimeTypeByFileExtension(PathBaseExtension(path))
	//--
} //END FUNCTION


//-----


func PathDirName(filePath string) string { // returns: `a/path/to` from `a/path/to/lastDirInPath|file.extension` | `/a/path/to` from `/a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	return filepath.Dir(filePath)
	//--
} //END FUNCTION


func PathBaseName(filePath string) string { // returns: `file.extenstion` | `lastDirInPath` from `(/)a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	return filepath.Base(filePath)
	//--
} //END FUNCTION


func PathBaseExtension(filePath string) string { // returns: .extenstion (includding dot) from `(/)a/path/to/lastDirInPath|file.extension`
	//--
	if(filePath == "") {
		return ""
	} //end if
	//--
	return filepath.Ext(filePath)
	//--
} //END FUNCTION


func PathIsEmptyOrRoot(filePath string) bool { // dissalow a path under 3 characters
	//--
	filePath = StrReplaceAll(filePath, "/", "")  // test for linux/unix file system
	filePath = StrReplaceAll(filePath, "\\", "") // test for network shares
	filePath = StrReplaceAll(filePath, ":", "")  // test for windows file system
	//--
	filePath = StrTrimWhitespaces(filePath)
	//--
	if(filePath == "") {
		return true
	} //end if
	if(len(filePath) < 3) {
		return true
	} //end if
	//--
	return false
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
	if(StrTrimWhitespaces(thePath) == "") {
		return false
	} //end if
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
	if(StrTrimWhitespaces(thePath) == "") {
		return false
	} //end if
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
	if(StrTrimWhitespaces(thePath) == "") {
		return false
	} //end if
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


func PathGetAbsoluteFromRelative(thePath string) string {
	//--
	if(!PathExists(thePath)) {
		return ""
	} //end if
	//--
	absPath, err := filepath.Abs(thePath)
	//--
	if(err != nil) {
		return ""
	} //end if
	//--
	return absPath
	//--
} //END FUNCTION


func PathGetCurrentExecutableName() string {
	//--
	currentExecutableAbsolutePath, err := os.Executable()
	if(err != nil) {
		return ""
	} //end if
	if(currentExecutableAbsolutePath == "") {
		return ""
	} //end if
	//--
	return PathBaseName(currentExecutableAbsolutePath)
	//--
} //END FUNCTION


func PathGetCurrentExecutableDir() string {
	//--
	currentExecutableAbsolutePath, err := os.Executable()
	if(err != nil) {
		return ""
	} //end if
	if(currentExecutableAbsolutePath == "") {
		return ""
	} //end if
	//--
	return PathDirName(currentExecutableAbsolutePath)
	//--
} //END FUNCTION


func PathAddDirLastSlash(dirPath string) string {
	//--
	dirPath = StrTrimWhitespaces(dirPath)
	if((dirPath == "") || (dirPath == ".") || (dirPath == "..") || (dirPath == "/")) {
		return "./"
	} //end if
	//--
	dirPath = StrTrimRightWhitespaces(StrTrimRight(dirPath, "/"))
	if((dirPath == "") || (dirPath == ".") || (dirPath == "..") || (dirPath == "/")) {
		return "./"
	} //end if
	//--
	return dirPath + "/"
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


func SafePathDirDelete(dirPath string, allowAbsolutePath bool) (isSuccess bool, errMsg string) { // will delete the dir with all it's (recursive) content
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


func SafePathDirScan(dirPath string, recursive bool, allowAbsolutePath bool) (isSuccess bool, errMsg string, arrDirs []string, arrFiles []string) {
	//--
	var dirs  []string
	var files []string
	//--
	if(StrTrimWhitespaces(dirPath) == "") {
		return false, errors.New("WARNING: Dir Path is Empty").Error(), dirs, files
	} //end if
	//--
	dirPath = PathAddDirLastSlash(dirPath)
	//--
	if(PathIsBackwardUnsafe(dirPath) == true) {
		return false, errors.New("WARNING: Dir Path is Backward Unsafe").Error(), dirs, files
	} //end if
	//--
	if(allowAbsolutePath != true) {
		if(PathIsAbsolute(dirPath) == true) {
			return false, errors.New("NOTICE: Dir Path is Absolute but not allowed to be absolute by the calling parameters").Error(), dirs, files
		} //end if
	} //end if
	//--
	if(!PathExists(dirPath)) {
		return false, errors.New("WARNING: Path does not exists").Error(), dirs, files
	} //end if
	if(PathIsFile(dirPath)) {
		return false, errors.New("WARNING: Dir Path is a File not a Directory").Error(), dirs, files
	} //end if
	if(!PathIsDir(dirPath)) {
		return false, errors.New("WARNING: Dir Path is Not a Directory").Error(), dirs, files
	} //end if
	//--
	if(recursive) {
		//--
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if((StrTrimWhitespaces(path) != "") && (StrTrim(path, "/ ") != "") && (path != ".") && (path != "..") && (path != "/") && (StrTrimRight(path, "/") != StrTrimRight(dirPath, "/"))) {
				if(PathIsDir(path)) {
					dirs = append(dirs, path)
				} else {
					files = append(files, path)
				} //end if else
			} //end if
			return nil
		})
		if(err != nil) {
			return false, err.Error(), dirs, files
		} //end if
		//--
	} else {
		//--
		paths, err := ioutil.ReadDir(dirPath)
		if(err != nil) {
			return false, err.Error(), dirs, files
		} //end if
		for _, p := range paths {
			if((StrTrimWhitespaces(p.Name()) != "") && (StrTrim(p.Name(), "/ ") != "") && (p.Name() != ".") && (p.Name() != "..") && (p.Name() != "/")) {
				path   := dirPath + p.Name()
				isDir  := p.IsDir()
				if(isDir) {
					dirs = append(dirs, path)
				} else {
					files = append(files, path)
				} //end if else
			} //end if
		} //end for
		//--
	} //end if else
	//--
	return true, "", dirs, files
	//--
} //END FUNCTION


//-----


func SafePathFileMd5(filePath string, allowAbsolutePath bool) (hashSum string, errMsg string) {
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
	f, err := os.Open(filePath)
	if(err != nil) {
		return "", err.Error()
	} //end if
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err.Error()
	} //end if
	//--
//	hexMd5 := StrToLower(fmt.Sprintf("%x", h.Sum(nil)))
	hexMd5 := StrToLower(hex.EncodeToString(h.Sum(nil)))
	//--
	return hexMd5, ""
	//--
} //END FUNCTION


func SafePathFileSha(mode string, filePath string, allowAbsolutePath bool) (hashSum string, errMsg string) {
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
	var h hash.Hash
	if(mode == "sha512") {
		h = sha512.New()
	} else if(mode == "sha256") {
		h = sha256.New()
	} else if(mode == "sha1") {
		h = sha1.New()
	} //end if else
	if(h == nil) {
		return "", errors.New("WARNING: Invalid Mode: `" + mode + "`").Error()
	} //end if
	//--
	f, err := os.Open(filePath)
	if(err != nil) {
		return "", err.Error()
	} //end if
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err.Error()
	} //end if
	//--
//	hexSha := StrToLower(fmt.Sprintf("%x", h.Sum(nil)))
	hexSha := StrToLower(hex.EncodeToString(h.Sum(nil)))
	//--
	return hexSha, ""
	//--
} //END FUNCTION


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
	fSizeOrigin, errMsg := SafePathFileGetSize(filePath, allowAbsolutePath)
	if(errMsg != "") {
		SafePathFileDelete(fileNewPath, allowAbsolutePath)
		return false, errors.New("WARNING: Failed to Compare After Copy File Sizes (origin)").Error()
	} //end if
	fSizeDest, errMsg := SafePathFileGetSize(fileNewPath, allowAbsolutePath)
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


func MarkersTplEscapeTpl(template string) string {
	//--
	return RawUrlEncode(template)
	//--
} //END FUNCTION


func MarkersTplEscapeSyntaxContent(tpl string, isMainHtml bool) string {
	//--
	if(tpl == "") {
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "[###", "⁅###¦")
	tpl = StrReplaceAll(tpl, "###]", "¦###⁆")
	tpl = StrReplaceAll(tpl, "[%%%", "⁅%%%¦")
	tpl = StrReplaceAll(tpl, "%%%]", "¦%%%⁆")
	tpl = StrReplaceAll(tpl, "[@@@", "⁅@@@¦")
	tpl = StrReplaceAll(tpl, "@@@]", "¦@@@⁆")
	if(isMainHtml == false) { // for a main template these must remain to be able to post replace placeholders
		tpl = StrReplaceAll(tpl, "[:::", "⁅:::¦")
		tpl = StrReplaceAll(tpl, ":::]", "¦:::⁆")
	} //end if
	//--
	return tpl
	//--
} //END FUNCTION


func MarkersTplPrepareNosyntaxHtml(tpl string, isMainHtml bool) string {
	//--
	if(tpl == "") {
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "[###", "&lbrack;&num;&num;&num;")
	tpl = StrReplaceAll(tpl, "###]", "&num;&num;&num;&rbrack;")
	tpl = StrReplaceAll(tpl, "[%%%", "&lbrack;&percnt;&percnt;&percnt;")
	tpl = StrReplaceAll(tpl, "%%%]", "&percnt;&percnt;&percnt;&rbrack;")
	tpl = StrReplaceAll(tpl, "[@@@", "&lbrack;&commat;&commat;&commat;")
	tpl = StrReplaceAll(tpl, "@@@]", "&commat;&commat;&commat;&rbrack;")
	if(isMainHtml == false) { // for a main template these must remain to be able to post replace placeholders
		tpl = StrReplaceAll(tpl, "[:::", "&lbrack;&colon;&colon;&colon;")
		tpl = StrReplaceAll(tpl, ":::]", "&colon;&colon;&colon;&rbrack;")
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "［###", "&lbrack;&num;&num;&num;")
	tpl = StrReplaceAll(tpl, "###］", "&num;&num;&num;&rbrack;")
	tpl = StrReplaceAll(tpl, "［%%%", "&lbrack;&percnt;&percnt;&percnt;")
	tpl = StrReplaceAll(tpl, "%%%］", "&percnt;&percnt;&percnt;&rbrack;")
	tpl = StrReplaceAll(tpl, "［@@@", "&lbrack;&commat;&commat;&commat;")
	tpl = StrReplaceAll(tpl, "@@@］", "&commat;&commat;&commat;&rbrack;")
	tpl = StrReplaceAll(tpl, "［:::", "&lbrack;&colon;&colon;&colon;")
	tpl = StrReplaceAll(tpl, ":::］", "&colon;&colon;&colon;&rbrack;")
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
	tpl = StrReplaceAll(tpl, "[:::", "［:::")
	tpl = StrReplaceAll(tpl, ":::]", ":::］")
	//--
	return tpl
	//--
} //END FUNCTION


func MarkersTplRevertNosyntaxContent(tpl string) string {
	//--
	if(tpl == "") {
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "［###", "[###")
	tpl = StrReplaceAll(tpl, "###］", "###]")
	tpl = StrReplaceAll(tpl, "［%%%", "[%%%")
	tpl = StrReplaceAll(tpl, "%%%］", "%%%]")
	tpl = StrReplaceAll(tpl, "［@@@", "[@@@")
	tpl = StrReplaceAll(tpl, "@@@］", "@@@]")
	tpl = StrReplaceAll(tpl, "［:::", "[:::")
	tpl = StrReplaceAll(tpl, ":::］", ":::]")
	//--
	return tpl
	//--
} //END FUNCTION


func PlaceholdersTplRender(template string, arrpobj map[string]string, isEncoded bool, revertSyntax bool) string {
	//-- syntax: r.20220331
	if(isEncoded == true) {
		template = RawUrlDecode(template)
	} //end if
	if(revertSyntax == true) {
		template = MarkersTplRevertNosyntaxContent(template)
	} //end if
	//-- trim whitespaces
	template = StrTrimWhitespaces(template)
	//--
	const regexPlaceholderVarName = `^[A-Z0-9_\-]+$`
	//--
	if(arrpobj != nil) {
		for k, v := range arrpobj {
			if(k != "") {
				if(StrRegexMatchString(regexPlaceholderVarName, k)) {
					template = StrReplaceAll(template, "[:::" + k + ":::]", v)
				} //end if
			} //end if
		} //end for
	} //end if
	//--
	return template
	//--
} //END FUNCTION


func MarkersTplRender(template string, arrobj map[string]string, isEncoded bool, revertSyntax bool, escapeRemainingSyntax bool, isMainHtml bool) string {
	//-- syntax: r.20220331
	if(isEncoded == true) {
		template = RawUrlDecode(template)
	} //end if
	if(revertSyntax == true) {
		template = MarkersTplRevertNosyntaxContent(template)
	} //end if
	//-- trim whitespaces
	template = StrTrimWhitespaces(template)
	//-- replace out comments
	if((StrContains(template, "[%%%COMMENT%%%]")) && (StrContains(template, "[%%%/COMMENT%%%]"))) {
		template = StrRegexReplaceAll(`(?s)\s??\[%%%COMMENT%%%\](.*?)??\[%%%\/COMMENT%%%\]\s??`, template, "") // regex syntax as in PHP
	} //end if
	//-- process ifs (conditionals)
	const regexIfVarName = `^[a-zA-Z0-9_\-]+$`
	var regexIfs = regexp.MustCompile(`(?s)(\[%%%IF\:([a-zA-Z0-9_\-]+)\:(\=\=|\!\=){1}(.*?)(;%%%\]){1}){1}(.*?)((\[%%%ELSE\:([a-zA-Z0-9_\-]+)%%%\])(.*?)){0,1}(\[%%%\/IF\:([a-zA-Z0-9_\-]+)%%%\]){1}`) // Go lang have no backreferences in regex, thus it is too complex at the moment to process nested ifs, thus does not support also (0..9) terminators ; because there is no support for loops yet, dissalow "." in variable names ; also operations between different data type gets too much overhead ; thus keep is simple: no nested if syntax ; allow only (strings): == != ; {{{SYNC-MTPL-IFS-OPERATIONS}}}
	for c, imatch := range regexIfs.FindAllStringSubmatch(template, -1) {
		//--
		var tmp_ifs_cond_block string 		= string(imatch[0]) 					// the whole conditional block [%%%IF:VARNAME:==xyz;%%%] .. ([%%%ELSE:VARNAME%%%] ..) [%%%/IF:VARNAME%%%]
		var tmp_ifs_part_if string			= string(imatch[6]) 					// the part between IF and ELSE ; or the part between IF and /IF in the case that ELSE is missing
		var tmp_ifs_part_else string		= string(imatch[10]) 					// the part between ELSE and /IF
		var tmp_ifs_tag_if string			= string(imatch[1]) 					// [%%%IF:VARNAME:==xyz;%%%]
		var tmp_ifs_tag_else string			= string(imatch[8]) 					// [%%%ELSE:VARNAME%%%]
		var tmp_ifs_tag_endif string 		= string(imatch[11]) 					// [%%%/IF:VARNAME%%%]
		var tmp_ifs_var_if string 			= string(imatch[2]) 					// the 'VARNAME' part of IF
		var tmp_ifs_var_else string 		= string(imatch[9]) 					// the 'VARNAME' part of ELSE
		var tmp_ifs_var_endif string 		= string(imatch[12]) 					// the 'VARNAME' part of \IF
		var tmp_ifs_operation string 		= string(imatch[3]) 					// the IF operation ; at the moment just '==' or '!=' are supported
		var tmp_ifs_value string 			= string(imatch[4]) 					// the IF value to compare the VARNAME with
		//--
	//	log.Println("[DEBUG] ---------- : `" + tmp_ifs_cond_block + "`")
	//	log.Println("[DEBUG] [IF] : `" + tmp_ifs_tag_if + "`")
	//	log.Println("[DEBUG] [IF] VAR : `" + tmp_ifs_var_if + "`")
	//	log.Println("[DEBUG] [IF] OPERATION : `" + tmp_ifs_operation + "`")
	//	log.Println("[DEBUG] [IF] VALUE : `" + tmp_ifs_value + "`")
	//	log.Println("[DEBUG] [IF] PART : `" + tmp_ifs_part_if + "`")
	//	log.Println("[DEBUG] [ELSE] : `" + tmp_ifs_tag_else + "`")
	//	log.Println("[DEBUG] [ELSE] VAR : `" + tmp_ifs_var_else + "`")
	//	log.Println("[DEBUG] [ELSE] PART : `" + tmp_ifs_part_else + "`")
	//	log.Println("[DEBUG] [/IF] : `" + tmp_ifs_tag_endif + "`")
	//	log.Println("[DEBUG] [/IF] VAR : `" + tmp_ifs_var_endif + "`")
		//--
		var isConditionalBlockERR string = ""
		//-- check the conditional block: should not be empty
		if(isConditionalBlockERR == "") {
			if(StrTrimWhitespaces(tmp_ifs_cond_block) == "") {
				isConditionalBlockERR = "Conditional IF/(ELSE)/IF block is empty"
			} //end if
		} //end if
		//-- check if tag: should not be empty
		if(isConditionalBlockERR == "") {
			if(StrTrimWhitespaces(tmp_ifs_tag_if) == "") {
				isConditionalBlockERR = "IF tag is empty"
			} //end if
		} //end if
		//-- check /if tag: should not be empty
		if(isConditionalBlockERR == "") {
			if(StrTrimWhitespaces(tmp_ifs_tag_endif) == "") {
				isConditionalBlockERR = "/IF tag is empty"
			} //end if
		} //end if
		//-- check if var: should not be empty
		if(isConditionalBlockERR == "") {
			if(StrTrimWhitespaces(tmp_ifs_var_if) == "") {
				isConditionalBlockERR = "IF var name is empty"
			} //end if
		} //end if
		//-- check if var: should match a particular regex
		if(isConditionalBlockERR == "") {
			if(!StrRegexMatchString(regexIfVarName, tmp_ifs_var_if)) {
				isConditionalBlockERR = "IF var name is invalid: `" + tmp_ifs_var_if + "`"
			} //end if
		} //end if
		//-- check if var vs. endif var: should be the same
		if(isConditionalBlockERR == "") {
			if(tmp_ifs_var_if != tmp_ifs_var_endif) {
				isConditionalBlockERR = "IF var `" + tmp_ifs_var_if + "` name does not match /IF var name `" + tmp_ifs_var_endif + "`"
			} //end if
		} //end if
		//-- check if var vs. else var (just in the case that else tag exists): should be the same, in the given case only
		if(isConditionalBlockERR == "") {
			if(tmp_ifs_tag_else != "") { // else tag is missing
				if(tmp_ifs_var_if != tmp_ifs_var_else) {
					isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` does not match ELSE var name `" + tmp_ifs_var_else + "`"
				} //end if
			} //end if
		} //end if
		//-- check if operation
		if(isConditionalBlockERR == "") {
			if((tmp_ifs_operation != "==") && (tmp_ifs_operation != "!=")) { // {{{SYNC-MTPL-IFS-OPERATIONS}}}
				isConditionalBlockERR = "IF operation is invalid: `" + tmp_ifs_operation + "`"
			} //end if
		} //end if
		//-- get the value and exists from arrobj by if var name as key
		iKeyValue, iKeyExists := arrobj[tmp_ifs_var_if]
		//--
		if(isConditionalBlockERR == "") {
			if(!iKeyExists) {
				isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` is invalid: does not exists"
			} //end if
		} //end if
		//--
		if(isConditionalBlockERR == "") {
			//--
			var theConditionalResult = ""
			//--
			if(tmp_ifs_operation == "==") {
				if(iKeyValue == tmp_ifs_value) {
					theConditionalResult = tmp_ifs_part_if
				} else {
					theConditionalResult = tmp_ifs_part_else
				} //end if else
			} else if(tmp_ifs_operation == "!=") {
				if(iKeyValue != tmp_ifs_value) {
					theConditionalResult = tmp_ifs_part_if
				} else {
					theConditionalResult = tmp_ifs_part_else
				} //end if else
			} else { // ERR
				isConditionalBlockERR = "IF operation mismatch: `" + tmp_ifs_operation + "`"
			} //end if else
			//--
			if(isConditionalBlockERR == "") {
				template = StrReplaceWithLimit(template, tmp_ifs_cond_block, theConditionalResult, 1) // MUST REPLACE ONLY THE FIRST OCCURENCE
			} //end if
			//--
		} //end if
		//--
		if(isConditionalBlockERR != "") {
			log.Println("[WARNING] MarkersTplRender: {### Invalid Conditional #" + ConvertIntToStr(c) + ": [" + isConditionalBlockERR + "] for Block `" + tmp_ifs_cond_block + "`" + " ###}")
		} //end if
		//--
	} //end for
	//-- process markers
	var regexMarkers = regexp.MustCompile(`\[\#\#\#([A-Z0-9_\-\.]+)((\|[a-z0-9]+)*)\#\#\#\]`) // regex markers as in Javascript {{{SYNC-REGEX-MARKER-TEMPLATES}}}
	for i, match := range regexMarkers.FindAllStringSubmatch(template, -1) {
		//--
		var tmp_marker_val string			= "" 									// just initialize
		var tmp_marker_id  string			= string(match[0]) 						// [###THE-MARKER|escapings...###]
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
							} else if(escaping == "|idtxt") { // id_txt: Id-Txt
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, "_", "-", -1) // replace all
								tmp_marker_val = strings.Title(StrToLower(tmp_marker_val))
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
								tmp_marker_val = StrToLower(tmp_marker_val)
							} else if(escaping == "|upper") { // apply uppercase
								tmp_marker_val = StrToUpper(tmp_marker_val)
							} else if(escaping == "|ucfirst") { // apply uppercase first character
								x1st := StrToUpper(StrMBSubstr(tmp_marker_val, 0, 1)) // get 1st char
								xrest := StrToLower(StrMBSubstr(tmp_marker_val, 1, 0)) // get the rest of characters
								tmp_marker_val = x1st + xrest
								x1st = ""
								xrest = ""
							} else if(escaping == "|ucwords") { // apply uppercase on each word
								tmp_marker_val = strings.Title(StrToLower(tmp_marker_val))
							} else if(escaping == "|trim") { // apply trim
								tmp_marker_val = StrTrimWhitespaces(tmp_marker_val)
							} else if(escaping == "|url") { // escape URL
								tmp_marker_val = EscapeUrl(tmp_marker_val)
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
							} else if(escaping == "|smartlist") { // Apply SmartList Fix Replacements ; {{{SYNC-SMARTLIST-BRACKET-REPLACEMENTS}}}
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, "<", "‹", -1) // replace all
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, ">", "›", -1) // replace all
							} else if(escaping == "|syntaxhtml") { // fix back markers tpl escapings in html
								tmp_marker_val = MarkersTplPrepareNosyntaxHtml(tmp_marker_val, false)
							} else if(escaping == "|hex") { // Apply Bin2Hex Encode
								tmp_marker_val = Bin2Hex(tmp_marker_val)
							} else if(escaping == "|b64") { // Apply Base64 Encode
								tmp_marker_val = Base64Encode(tmp_marker_val)
							} else if(escaping == "|sha1") { // Apply SHA1 Encode
								tmp_marker_val = Sha1(tmp_marker_val)
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
	if(escapeRemainingSyntax == true) {
		//--
		if(isMainHtml == false) {
			if(StrContains(template, "[:::")) {
				log.Println("[WARNING] MarkersTplRender: {### Undefined Placeholders detected in Template ###}")
			} //end if
		} //end if
		if(StrContains(template, "[###")) {
			log.Println("[WARNING] MarkersTplRender: {### Undefined Markers detected in Template ###}")
		} //end if
		if(StrContains(template, "[%%%")) {
			log.Println("[WARNING] MarkersTplRender: {### Undefined Marker Syntax detected in Template ###}")
		} //end if
		if(StrContains(template, "[@@@")) {
			log.Println("[WARNING] MarkersTplRender: {### Undefined Marker Sub-Templates detected in Template ###}")
		} //end if
		//--
		template = MarkersTplEscapeSyntaxContent(template, isMainHtml) // this will not escape the syntax already prepared by MarkersTplPrepareNosyntaxContent (PrepareNosyntax) that comes from a value, but only remaining syntax
		//--
	} //end if
	//--
	if(isMainHtml == true) {
		template = MarkersTplPrepareNosyntaxHtml(template, true) // this will revert to html entities the Syntax or PrepareNosyntax ; but in the case if syntax is escaped above, will just process PrepareNosyntax
	} //end if
	//--
	return template
	//--
} //END FUNCTION


func RenderMainMarkersTpl(template string, arrobj map[string]string, arrpobj map[string]string) string {
	//--
	template = MarkersTplRender(template, arrobj, false, false, true, true) // escape remaining syntax + is main html
	//--
	template = PlaceholdersTplRender(template, arrpobj, false, false)
	//--
	return template
	//--
} //END FUNCTION


func RenderMarkersTpl(template string, arrobj map[string]string) string {
	//--
	return MarkersTplRender(template, arrobj, false, false, true, false) // escape remaining syntax + is not main html
	//--
} //END FUNCTION


//-----


func HtmlErrorPage(titleText string, htmlMessage string) string {
	//--
	if(StrTrimWhitespaces(htmlMessage) == "") {
		htmlMessage = EscapeHtml(HTML_ERR_DEFAULT_MSG)
	} //end if
	//--
	arr := map[string]string{
		"MESSAGE-TEXT": titleText,
		"MESSAGE-HTML": htmlMessage,
		"LOGO-SERVER-HTML": `<img alt="logo-server" title="Go Standalone Web Server" style="cursor:help;" width="64" height="64" src="data:image/svg+xml,` + EscapeUrl(LOGO_SERVER_SVG) + `">`,
		"LOGO-RUNTIME-HTML": `<img alt="logo-runtime" title="Built with Go Lang" style="cursor:help;" width="64" height="64" src="data:image/svg+xml,` + EscapeUrl(LOGO_RUNTIME_SVG) + `">`,
		"LOGO-FRAMEWORK-HTML": `<img alt="logo-framework" title="Smart.Framework.Go" style="cursor:help;" width="64" height="64" src="data:image/svg+xml,` + EscapeUrl(LOGO_FRAMEWORK_SVG) + `">`,
	}
	//--
	return RenderMainMarkersTpl(HTML_TPL_ERR, arr, nil) + "\n" + "<!-- TPL:Static.Err -->" + "\n"
	//--
} //END FUNCTION

//-----


func IsNetValidPortNum(p int64) bool { // can be a valid NUMERIC port between 1 and 65535
	//--
	if((p < 1) || (p > 65535)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func IsNetValidPortStr(s string) bool { // can be a valid STRING(as NUMERIC) port between 1 and 65535
	//--
	if(StrTrimWhitespaces(s) == "") {
		return false
	} //end if
	//--
	var p int64 = ParseIntegerStrAsInt64(s)
	//--
	return IsNetValidPortNum(p)
	//--
} //END FUNCTION


func IsNetValidIpAddr(s string) bool { // can be IPV4 or IPV6 but non-empty or zero
	//--
	if((StrTrimWhitespaces(s) == "") || (StrTrimWhitespaces(s) == "0.0.0.0") || (StrTrimWhitespaces(s) == "0:0:0:0:0:0:0:0") || (StrTrimWhitespaces(s) == "::0") || (StrTrimWhitespaces(s) == "::")) { // dissalow empty or zero IP v4 / v6 addresses
		return false
	} //end if
	//--
	if(net.ParseIP(s) == nil) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func IsNetValidHostName(s string) bool { // can contains only
	//--
	if(StrTrimWhitespaces(s) == "") {
		return false
	} //end if
	//--
	if(!StrRegexMatchString(REGEX_SMART_SAFE_NET_HOSTNAME, s)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


func cmdExec(stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (isSuccess bool, outStd string, errStd string) {
	//--
	if(stopTimeout > 86400) {
		stopTimeout = 86400 // 0 = no execution timeout ; 1..86400 will stop the cmd execution after this number of seconds
	} //end if
	//--
	captureStdout = StrTrimWhitespaces(captureStdout) // "" | "capture" | "capture+output" | "output"
	captureStderr = StrTrimWhitespaces(captureStderr) // "" | "capture" | "capture+output" | "output"
	//--
	additionalEnv = StrTrimWhitespaces(additionalEnv) // Additional ENVIRONMENT ; Example: additionalEnv = "FOO=bar"
	// inputStdin // The Input to Stdin if any ; DO NOT TRIM, must be passed exact how is get
	//--
	theExe = StrTrimWhitespaces(theExe)
	//--
	var cmd *exec.Cmd = nil
	if(stopTimeout > 0) { // timed command
		ctx := context.Background()
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(stopTimeout)*time.Second)
		defer cancel()
		cmd = exec.CommandContext(ctx, theExe, theArgs...)
	} else { // no timeout
		cmd = exec.Command(theExe, theArgs...)
    } //end if
	//--
	if(additionalEnv != "") {
		newEnv := append(os.Environ(), additionalEnv)
		cmd.Env = newEnv
	} //end if
	if(inputStdin != "") {
		stdin, err := cmd.StdinPipe()
		if(err != nil) {
			return false, "", err.Error()
		} //end if
		go func() { // If the subprocess doesn't continue before the stdin is closed, the io.WriteString() call needs to be wrapped inside an anonymous function
			defer stdin.Close()
			io.WriteString(stdin, inputStdin)
		}()
	} //end if
	//--
	var stdoutBuf, stderrBuf bytes.Buffer
	if(captureStdout == "capture") { // capture stdout
		cmd.Stdout = io.Writer(&stdoutBuf) // cmd.Stdout = &stdoutBuf
	} else if(captureStdout == "capture+output") { // capture stdout and print to stdout
		cmd.Stdout = io.MultiWriter(os.Stdout, &stdoutBuf)
	} else if(captureStdout == "output") { // print stdout
		cmd.Stdout = io.Writer(os.Stdout)
	} //end if
	if(captureStderr == "capture") { // capture stderr
		cmd.Stderr = io.Writer(&stderrBuf) // cmd.Stderr = &stderrBuf
	} else if(captureStderr == "capture+output") { // capture stderr and print to stderr
		cmd.Stderr = io.MultiWriter(os.Stderr, &stderrBuf)
	} else if(captureStderr == "output") { // print to stderr
		cmd.Stderr = io.Writer(os.Stderr)
	} //end if
	//--
	err := cmd.Run()
	if(err != nil) { // [ALTERNATIVE] e, ok := err.(*exec.ExitError) // cast the error as *exec.ExitError and compare the result
		return false, string(stdoutBuf.Bytes()), string(stderrBuf.Bytes()) + "\n" + CMD_EXEC_ERR_SIGNATURE + " " + err.Error()
	} //end if
	//--
	outStr, errStr := string(stdoutBuf.Bytes()), string(stderrBuf.Bytes())
	//--
	return true, outStr, errStr
	//--
} //END FUNCTION


func ExecCmd(captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (isSuccess bool, outStd string, errStd string) {
	//--
	return cmdExec(0, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
} //END FUNCTION


func ExecTimedCmd(stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (isSuccess bool, outStd string, errStd string) {
	//--
	return cmdExec(stopTimeout, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
} //END FUNCTION


//-----


const(
	HTML_CONTENT_HEADER = "text/html; charset=UTF-8" 					// keep separate, can be used also by HTTP Headers: Content-Type
	HTML_TPL = `<!DOCTYPE html>
<!-- TPL.SmartGo -->
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Type" content="` + HTML_CONTENT_HEADER + `">
<link rel="icon" href="data:,">
<title>[###TITLE|html###]</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
[:::HEAD-CSS-JS:::]
[###HEAD-HTML###]
</head>
<body>
[###BODY-HTML###]
</body>
</html>
<!-- #end TPL -->
`

	HTML_STYLE_ERR_PAGE_MSG_DIV = "line-height: 36px; text-align: left; font-size: 1.25rem; font-weight: bold; font-style: normal; padding-left: 16px; padding-right: 16px; padding-top: 12px; padding-bottom: 8px; margin-top: 8px; margin-bottom: 8px; max-width: calc(100% - 10px) !important; min-width: 100px; min-height: 40px; height: auto !important; border-radius: 5px; box-sizing: content-box !important; opacity: 1 !important; background-color: #C62828 !important; color: #FFFFFF !important;"
	HTML_STYLE_THIN_HR = "height:1px; border:none 0; border-top:1px solid #CCCCCC;"
	HTML_ERR_DEFAULT_MSG = `The request could not be completed ...`
	HTML_TPL_ERR = `
<!DOCTYPE html>
<!-- TPL.SmartGo.ERR -->
<html>
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Type" content="` + HTML_CONTENT_HEADER + `">
<link rel="icon" href="data:,">
<title>[###MESSAGE-TEXT|html###]</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>* { font-family: 'IBM Plex Sans', 'Noto Sans', arial, sans-serif; font-smooth: always; }</style>
</head>
<body>
<h1 style="display:inline; font-size:4rem; color:#333333;">[###MESSAGE-TEXT|html###]</h1>
<br>
<br>
<hr style="` + HTML_STYLE_THIN_HR + `">
<div style="` + HTML_STYLE_ERR_PAGE_MSG_DIV + `">[###MESSAGE-HTML###]</div>
<hr style="` + HTML_STYLE_THIN_HR + `">
<br>
<div align="right">[###LOGO-SERVER-HTML###] &nbsp; [###LOGO-RUNTIME-HTML###] &nbsp; [###LOGO-FRAMEWORK-HTML###]</div>
</body>
</html>
<!-- #end TPL -->
`

	LOGO_SERVER_SVG = `<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="14" height="16" viewBox="0 0 14 16"><path style="fill:#888888;" fill-rule="evenodd" d="M7 1C3.14 1 0 4.14 0 8s3.14 7 7 7c.48 0 .94-.05 1.38-.14-.17-.08-.2-.73-.02-1.09.19-.41.81-1.45.2-1.8-.61-.35-.44-.5-.81-.91-.37-.41-.22-.47-.25-.58-.08-.34.36-.89.39-.94.02-.06.02-.27 0-.33 0-.08-.27-.22-.34-.23-.06 0-.11.11-.2.13-.09.02-.5-.25-.59-.33-.09-.08-.14-.23-.27-.34-.13-.13-.14-.03-.33-.11s-.8-.31-1.28-.48c-.48-.19-.52-.47-.52-.66-.02-.2-.3-.47-.42-.67-.14-.2-.16-.47-.2-.41-.04.06.25.78.2.81-.05.02-.16-.2-.3-.38-.14-.19.14-.09-.3-.95s.14-1.3.17-1.75c.03-.45.38.17.19-.13-.19-.3 0-.89-.14-1.11-.13-.22-.88.25-.88.25.02-.22.69-.58 1.16-.92.47-.34.78-.06 1.16.05.39.13.41.09.28-.05-.13-.13.06-.17.36-.13.28.05.38.41.83.36.47-.03.05.09.11.22s-.06.11-.38.3c-.3.2.02.22.55.61s.38-.25.31-.55c-.07-.3.39-.06.39-.06.33.22.27.02.5.08.23.06.91.64.91.64-.83.44-.31.48-.17.59.14.11-.28.3-.28.3-.17-.17-.19.02-.3.08-.11.06-.02.22-.02.22-.56.09-.44.69-.42.83 0 .14-.38.36-.47.58-.09.2.25.64.06.66-.19.03-.34-.66-1.31-.41-.3.08-.94.41-.59 1.08.36.69.92-.19 1.11-.09.19.1-.06.53-.02.55.04.02.53.02.56.61.03.59.77.53.92.55.17 0 .7-.44.77-.45.06-.03.38-.28 1.03.09.66.36.98.31 1.2.47.22.16.08.47.28.58.2.11 1.06-.03 1.28.31.22.34-.88 2.09-1.22 2.28-.34.19-.48.64-.84.92s-.81.64-1.27.91c-.41.23-.47.66-.66.8 3.14-.7 5.48-3.5 5.48-6.84 0-3.86-3.14-7-7-7L7 1zm1.64 6.56c-.09.03-.28.22-.78-.08-.48-.3-.81-.23-.86-.28 0 0-.05-.11.17-.14.44-.05.98.41 1.11.41.13 0 .19-.13.41-.05.22.08.05.13-.05.14zM6.34 1.7c-.05-.03.03-.08.09-.14.03-.03.02-.11.05-.14.11-.11.61-.25.52.03-.11.27-.58.3-.66.25zm1.23.89c-.19-.02-.58-.05-.52-.14.3-.28-.09-.38-.34-.38-.25-.02-.34-.16-.22-.19.12-.03.61.02.7.08.08.06.52.25.55.38.02.13 0 .25-.17.25zm1.47-.05c-.14.09-.83-.41-.95-.52-.56-.48-.89-.31-1-.41-.11-.1-.08-.19.11-.34.19-.15.69.06 1 .09.3.03.66.27.66.55.02.25.33.5.19.63h-.01z"/></svg>`

	LOGO_RUNTIME_SVG = `<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="128" height="128" viewBox="0 0 128.0 128.0" id="golang-logo">
 <defs id="d1" />
 <g id="g1" transform="matrix(0.75306336,0,0,0.74544188,-52.462259,-44.044334)">
  <g id="g2">
   <g id="g3">
    <path d="m 153.1,99.3 c -6.3,1.6 -10.6,2.8 -16.8,4.4 -1.5,0.4 -1.6,0.5 -2.9,-1 -1.5,-1.7 -2.6,-2.8 -4.7,-3.8 -6.3,-3.1 -12.4,-2.2 -18.1,1.5 -6.8,4.4 -10.3,10.9 -10.2,19 0.1,8 5.6,14.6 13.5,15.7 6.8,0.9 12.5,-1.5 17,-6.6 0.9,-1.1 1.7,-2.3 2.7,-3.7 -3.6,0 -8.1,0 -19.3,0 -2.1,0 -2.6,-1.3 -1.9,-3 1.3,-3.1 3.7,-8.3 5.1,-10.9 0.3,-0.6 1,-1.6 2.5,-1.6 5.1,0 23.9,0 36.4,0 -0.2,2.7 -0.2,5.4 -0.6,8.1 -1.1,7.2 -3.8,13.8 -8.2,19.6 -7.2,9.5 -16.6,15.4 -28.5,17 -9.8,1.3 -18.9,-0.6 -26.9,-6.6 -7.4,-5.6 -11.6,-13 -12.7,-22.2 -1.3,-10.9 1.9,-20.7 8.5,-29.3 7.1,-9.3 16.5,-15.2 28,-17.3 9.4,-1.7 18.4,-0.6 26.5,4.9 5.3,3.5 9.1,8.3 11.6,14.1 0.6,0.9 0.2,1.4 -1,1.7 z" id="path28" style="fill:#00aed8;fill-opacity:1" />
   </g>
   <g id="g4">
    <path d="m 186.2,154.6 c -9.1,-0.2 -17.4,-2.8 -24.4,-8.8 -5.9,-5.1 -9.6,-11.6 -10.8,-19.3 -1.8,-11.3 1.3,-21.3 8.1,-30.2 7.3,-9.6 16.1,-14.6 28,-16.7 10.2,-1.8 19.8,-0.8 28.5,5.1 7.9,5.4 12.8,12.7 14.1,22.3 1.7,13.5 -2.2,24.5 -11.5,33.9 -6.6,6.7 -14.7,10.9 -24,12.8 -2.7,0.5 -5.4,0.6 -8,0.9 z M 210,114.2 c -0.1,-1.3 -0.1,-2.3 -0.3,-3.3 -1.8,-9.9 -10.9,-15.5 -20.4,-13.3 -9.3,2.1 -15.3,8 -17.5,17.4 -1.8,7.8 2,15.7 9.2,18.9 5.5,2.4 11,2.1 16.3,-0.6 7.9,-4.1 12.2,-10.5 12.7,-19.1 z" id="path32" style="fill:#00aed8;fill-opacity:1" />
   </g>
  </g>
 </g>
 <g id="g5" transform="matrix(1.1,0,0,1.1,6.855,-17.56)">
  <g id="g6">
   <path d="m 40.2,101.1 c -0.4,0 -0.5,-0.2 -0.3,-0.5 L 42,97.9 c 0.2,-0.3 0.7,-0.5 1.1,-0.5 h 35.7 c 0.4,0 0.5,0.3 0.3,0.6 l -1.7,2.6 c -0.2,0.3 -0.7,0.6 -1,0.6 z" id="path4" style="fill:#00aed8;fill-opacity:1" />
  </g>
  <g id="g7">
   <path d="m 25.1,110.3 c -0.4,0 -0.5,-0.2 -0.3,-0.5 l 2.1,-2.7 c 0.2,-0.3 0.7,-0.5 1.1,-0.5 h 45.6 c 0.4,0 0.6,0.3 0.5,0.6 l -0.8,2.4 c -0.1,0.4 -0.5,0.6 -0.9,0.6 z" id="path12" style="fill:#00aed8;fill-opacity:1" />
  </g>
  <g id="g8">
   <path d="m 49.3,119.5 c -0.4,0 -0.5,-0.3 -0.3,-0.6 l 1.4,-2.5 c 0.2,-0.3 0.6,-0.6 1,-0.6 h 20 c 0.4,0 0.6,0.3 0.6,0.7 l -0.2,2.4 c 0,0.4 -0.4,0.7 -0.7,0.7 z" id="path20" style="fill:#00aed8;fill-opacity:1" />
  </g>
 </g>
</svg>`

	LOGO_FRAMEWORK_SVG = `<svg xmlns="http://www.w3.org/2000/svg" id="smart.framework-logo" version="1.1" viewBox="0 0 128 128" height="128px" width="128px">
<defs id="defs1466"/>
<g id="layer1">
    <g id="g3346" style="fill:#ffffff;fill-opacity:1;fill-rule:evenodd;stroke:none" transform="matrix(1.6895803,0,0,1.6895803,2.9648469,2.9648477)">
        <path style="fill:#ED2839;fill-opacity:1;fill-rule:evenodd;stroke:#ED2839;stroke-width:14.12108517;stroke-opacity:1" id="path3011" d="m 62.930573,36.124446 a 26.806128,26.806128 0 1 1 -53.6122531,0 26.806128,26.806128 0 1 1 53.6122531,0 z"/>
        <g id="text3758" style="fill:#000000;fill-opacity:1;stroke:none"/>
        <g id="text1442" style="fill:#000000;fill-opacity:1;stroke:none;stroke-width:0.54972863" transform="scale(0.92881066,1.0766457)">
            <path id="path1444" style="fill:#ffffff;stroke-width:0.54972863" d="M 12.135835,46.916975 V 40.346 l 2.222535,0.01933 q 0.09663,3.285487 1.893987,4.870251 1.816681,1.565439 5.508023,1.565439 3.440099,0 5.237454,-1.352848 1.816681,-1.372174 1.816681,-3.981238 0,-2.087251 -1.101605,-3.208182 -1.082278,-1.120931 -4.599682,-2.183882 l -3.8073,-1.140258 q -4.135849,-1.256215 -5.836572,-3.130876 -1.681396,-1.87466 -1.681396,-5.140821 0,-3.672016 2.609063,-5.701287 2.609064,-2.029272 7.324704,-2.029272 2.009946,0 4.406419,0.444507 2.396473,0.425181 5.102168,1.256216 v 6.145794 h -2.183882 q -0.328549,-3.053571 -2.048598,-4.406418 -1.700723,-1.372174 -5.198801,-1.372174 -3.053571,0 -4.657662,1.256215 -1.584764,1.23689 -1.584764,3.614036 0,2.067925 1.198237,3.246835 1.198236,1.17891 5.082842,2.338494 l 3.575383,1.062952 q 3.923258,1.17891 5.585329,3.014918 1.681396,1.816681 1.681396,4.889578 0,4.193828 -2.686369,6.319731 -2.686369,2.125904 -8.001128,2.125904 -2.377147,0 -4.850926,-0.48316 -2.454452,-0.48316 -5.005536,-1.468806 z"/>
            <path id="path1446" style="fill:#C2203F;stroke-width:0.54972863" d="m 39.714602,46.29853 q 0,-1.082278 0.734403,-1.836007 0.75373,-0.75373 1.836008,-0.75373 1.082278,0 1.816681,0.75373 0.75373,0.753729 0.75373,1.836007 0,1.082278 -0.734404,1.836008 -0.734403,0.734403 -1.836007,0.734403 -1.101605,0 -1.836008,-0.734403 -0.734403,-0.75373 -0.734403,-1.836008 z m 0,-12.60081 q 0,-1.082278 0.734403,-1.816681 0.75373,-0.75373 1.836008,-0.75373 1.101604,0 1.836007,0.734403 0.734404,0.734403 0.734404,1.836008 0,1.101604 -0.734404,1.836008 -0.734403,0.734403 -1.836007,0.734403 -1.082278,0 -1.836008,-0.734403 -0.734403,-0.75373 -0.734403,-1.836008 z"/>
            <path id="path1448" style="fill:#222222;stroke-width:0.54972863" d="m 65.9985,23.087528 h -1.874661 q -0.01933,-1.449479 -0.831035,-2.203209 -0.792382,-0.753729 -2.319167,-0.753729 -1.990619,0 -2.802328,1.101604 -0.811708,1.082278 -0.811708,3.884606 v 2.647716 h 5.739939 v 2.067925 h -5.739939 v 16.427436 h 4.561029 v 2.048598 H 50.402098 v -2.048598 h 3.401446 V 29.832441 h -3.401446 v -2.067925 h 3.401446 v -2.57041 q 0,-3.440099 1.778028,-5.198801 1.797355,-1.758702 5.25678,-1.758702 1.294869,0 2.589737,0.231917 1.294869,0.231916 2.570411,0.715076 z"/>
        </g>
    </g>
</g>
</svg>`
)


//-----


// #END
