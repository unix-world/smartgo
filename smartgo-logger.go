
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20251229.2358 :: STABLE
// [ LOGGER ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"
	"fmt"

	"io"
	"os"

	logutils "github.com/unix-world/smartgo/utils/log-utils"
	color    "github.com/unix-world/smartgo/ui/colorstring"
)

const (
	LOG_MAX_MSG_LEN uint16 = 65535 // max log message length
)

//-----


//func FatalError(logMessages ...interface{}) {
func FatalError(logMessages ...any) {
	//--
//	log.Println("[ERROR] ! FATAL !", fmt.Sprint(logMessages...))
	//-- fix for above, does not expand with between spaces
	var txtLog string = ""
	for _, e := range logMessages {
		txtLog += fmt.Sprint(e) + " "
	} //end for
	log.Println("[ERROR] ! FATAL !", StrTrimWhitespaces(txtLog))
	//--
	os.Exit(1)
	//--
} //END FUNCTION


//-----


func LogUseUtcTime() {
	//--
	logUseLocalTime = false // default
	//--
} //END FUNCTION


func LogUseLocalTime() {
	//--
	logUseLocalTime = true
	//--
} //END FUNCTION


//-----


func LogToStdErr(level string) {
	//--
	setLogLevelOutput(level, os.Stderr)
	//--
} //END FUNCTION


func LogToConsole(level string, withColorsOnConsole bool) {
	//--
	if(AppGetRunInBackground()) {
		withColorsOnConsole = false
	} //end if
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
	pathForLogs = SafePathFixSeparator(pathForLogs)
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
		LogToConsole(level, withColorsOnConsole)
		//--
		log.Fatal("[ERROR] !!!!!!! Cannot Log to File !!!!!!! the Log Path is Invalid or does not exists: `" + pathForLogs + "` !!!!!!!")
		//--
	} //end if
	//--
} //END FUNCTION


//-----


// PRIVATES
var logFilePath string = ""
var logFileFormat string = "plain" // can be: "plain" | "json"
var logToFileAlsoOnConsole bool = false
var logColoredOnConsole bool = false
var logUseLocalTime bool = false // default, logs will use UTC

// PRIVATES
type logWriterWithColors struct {}
func (writer logWriterWithColors) Write(bMsg []byte) (int, error) {
	//--
	if(len(bMsg) > int(LOG_MAX_MSG_LEN)) {
		bMsg = bMsg[0:LOG_MAX_MSG_LEN]
	} //end if
	//--
	var theMsg string = StrTrimWhitespaces(StrNormalizeSpaces(string(bMsg)))
	var hdrMsg string = StrToUpper(StrSubstr(theMsg, 0, 16))
	//--
	if(logColoredOnConsole) {
		if(StrStartsWith(hdrMsg, "[PANIC]") == true) { // {{{SYNC-SMARTGO-ERR:LEVELS+COLORS}}}
			theMsg = color.MagentaString(StrTrimWhitespaces(string(bMsg))) // for data preserve the string how it is, except trim ! ; brown
		} else if(StrStartsWith(hdrMsg, "[ERROR]") == true) {
			theMsg = color.RedString(theMsg)
		} else if(StrStartsWith(hdrMsg, "[WARNING]") == true) {
			theMsg = color.HiRedString(theMsg)
		} else if(StrStartsWith(hdrMsg, "[OK]") == true) {
			theMsg = color.HiGreenString(theMsg)
		} else if(StrStartsWith(hdrMsg, "[LOG]") == true) {
			theMsg = color.WhiteString(theMsg)
		} else if(StrStartsWith(hdrMsg, "[INFO]") == true) {
			theMsg = color.HiYellowString(theMsg)
		} else if(StrStartsWith(hdrMsg, "[NOTICE]") == true) {
			theMsg = color.HiBlueString(theMsg)
		} else if(StrStartsWith(hdrMsg, "[META]") == true) {
			theMsg = color.HiCyanString(theMsg)
		} else if(StrStartsWith(hdrMsg, "[DATA]") == true) {
			theMsg = color.YellowString(StrTrimWhitespaces(string(bMsg))) // for data preserve the string how it is, except trim ! ; brown
		} else if(StrStartsWith(hdrMsg, "[DEBUG]") == true) {
			theMsg = color.HiMagentaString(theMsg)
		} else { // ALL OTHER CASES
			theMsg = color.HiGreyString(theMsg)
		} //end if else
	} //end if
	//--
	var dTime string = ""
	if(logUseLocalTime) {
		dTime = DateNowLocal()
	} else {
		dTime = DateNowUtc()
	} //end if else
	//--
	if(logColoredOnConsole) {
		return fmt.Println(color.GreyString("LOG | " + dTime + " | ") + theMsg)
	} else {
		return fmt.Println("LOG | " + dTime + " | " + theMsg)
	} //end if else
	//--
} //END FUNCTION

// PRIVATES
type logWriterFile struct {}
type logWriteJsonStruct struct {
	Type     string `json:"type"`
	DateTime string `json:"dateTime"`
	Message  string `json:"message"`
}
func (writer logWriterFile) Write(bMsg []byte) (int, error) {
	//--
	if(len(bMsg) > int(LOG_MAX_MSG_LEN)) {
		bMsg = bMsg[0:LOG_MAX_MSG_LEN]
	} //end if
	//--
	var dTime string = ""
	if(logUseLocalTime) {
		dTime = DateNowLocal()
	} else {
		dTime = DateNowUtc()
	} //end if else
	//--
	var theErr string = ""
	var theMsg string = StrTrimWhitespaces(string(bMsg))
	var hdrMsg string = StrToUpper(StrSubstr(theMsg, 0, 16))
	//--
	var theType string = ""
	var colorMsg string = theMsg
	if(StrStartsWith(hdrMsg, "[PANIC]") == true) {
		theType = "panic"
		if(logColoredOnConsole) {
			colorMsg = color.MagentaString(colorMsg)
		} //end if
	} else if(StrStartsWith(hdrMsg, "[ERROR]") == true) { // {{{SYNC-SMARTGO-ERR:LEVELS+COLORS}}}
		theType = "error"
		if(logColoredOnConsole) {
			colorMsg = color.RedString(colorMsg)
		} //end if
	} else if(StrStartsWith(hdrMsg, "[WARNING]") == true) {
		theType = "warning"
		if(logColoredOnConsole) {
			colorMsg = color.HiRedString(colorMsg)
		} //end if
	} else if(StrStartsWith(hdrMsg, "[OK]") == true) {
		theType = "ok"
		if(logColoredOnConsole) {
			colorMsg = color.HiGreenString(colorMsg)
		} //end if
	} else if(StrStartsWith(hdrMsg, "[LOG]") == true) {
		theType = "log"
		if(logColoredOnConsole) {
			colorMsg = color.WhiteString(colorMsg)
		} //end if
	} else if(StrStartsWith(hdrMsg, "[INFO]") == true) {
		theType = "info"
		if(logColoredOnConsole) {
			colorMsg = color.HiYellowString(colorMsg)
		} //end if
	} else if(StrStartsWith(hdrMsg, "[NOTICE]") == true) {
		theType = "notice"
		if(logColoredOnConsole) {
			colorMsg = color.HiBlueString(colorMsg)
		} //end if
	} else if(StrStartsWith(hdrMsg, "[META]") == true) {
		theType = "meta"
		if(logColoredOnConsole) {
			colorMsg = color.HiCyanString(colorMsg)
		} //end if
	} else if(StrStartsWith(hdrMsg, "[DATA]") == true) {
		theType = "data"
		if(logColoredOnConsole) {
			colorMsg = color.YellowString(colorMsg) // brown
		} //end if
	} else if(StrStartsWith(hdrMsg, "[DEBUG]") == true) {
		theType = "debug"
		if(logColoredOnConsole) {
			colorMsg = color.HiMagentaString(colorMsg)
		} //end if
	} else { // ALL OTHER CASES
		theType = ""
		if(logColoredOnConsole) {
			colorMsg = color.HiGreyString(colorMsg)
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
		return 0, NewError(theErr)
	} //end if
	//--
	var theErrFmtMsg error = nil
	var theFmtMsg string = ""
	var theLogPfx string = ""
	if(logFileFormat == "json") {
		theLogPfx = "json"
		jsonLogStruct := logWriteJsonStruct {
			Type     : theType,
			DateTime : dTime,
			Message  : theMsg, // not necessary to normalize spaces
		}
		theFmtMsg, theErrFmtMsg = JsonEncode(jsonLogStruct, false, false)
		if(theErrFmtMsg != nil) {
			theFmtMsg = ""
			fmt.Println(color.RedString("[ERROR] SmartGo Log JSON Encoding") + " : " + theErrFmtMsg.Error())
		} //end if
	} else if(logFileFormat == "plain") {
		theFmtMsg = StrNormalizeSpaces(theMsg)
	} else {
		theErr = "[ERROR] SmartGo LogFile Invalid Format (" + logFileFormat + ") for LogPath `" + logFilePath + "`"
		if(logColoredOnConsole) {
			fmt.Println(color.RedString(theErr) + " : " + colorMsg)
		} else {
			fmt.Println(theErr + " : " + theMsg)
		} //end if else
		return 0, NewError(theErr)
	} //end if else
	//--
	dtObjUtc := DateTimeStructUtc("")
	//--
	var theLogFile string = logFilePath + theLogPfx + "log" + "-" + dtObjUtc.Years + "-" + dtObjUtc.Months + "-" + dtObjUtc.Days + "-" + dtObjUtc.Hours + ".log"
	//--
	isSuccess, errMsg := SafePathFileWrite(theLogFile, "a", true, theFmtMsg + LINE_FEED)
	//--
	if(errMsg != nil) {
		theErr = "[ERROR] SmartGo LogFile (" + logFileFormat + ") write Error `" + theLogFile + "` :: " + errMsg.Error()
		if(logColoredOnConsole) {
			fmt.Println(color.RedString(theErr) + " : " + colorMsg)
		} else {
			fmt.Println(theErr + " : " + theMsg)
		} //end if else
		return 0, NewError(theErr)
	} //end if
	//--
	if(isSuccess != true) {
		theErr = "[ERROR] SmartGo LogFile (" + logFileFormat + ") :: FAILED to write to the log File: `" + theLogFile + "`"
		if(logColoredOnConsole) {
			fmt.Println(color.RedString(theErr) + " : " + colorMsg)
		} else {
			fmt.Println(theErr + " : " + theMsg)
		} //end if else
		return 0, NewError(theErr)
	} //end if
	//--
	if(logToFileAlsoOnConsole) {
		if(logColoredOnConsole) {
			return fmt.Println(color.GreyString("LOG | " + dTime + " | ") + colorMsg)
		} else {
			return fmt.Println("LOG | " + dTime + " | " + colorMsg)
		} //end if else
	} //end if
	//--
	return len(bMsg), nil
	//--
} //END FUNCTION


// PRIVATE
func setLogLevelOutput(level string, output io.Writer) { // Example: setLogLevelOutput("WARNING", os.Stderr)
	//--
	level = StrToUpper(StrTrimWhitespaces(level))
	//--
	var mLevel string = "PANIC"
	if(level == "ERROR") {
		mLevel = "ERROR"
	} else if(level == "WARNING") {
		mLevel = "WARNING"
	} else if(level == "OK") {
		mLevel = "OK"
	} else if(level == "LOG") {
		mLevel = "LOG"
	} else if(level == "INFO") {
		mLevel = "INFO"
	} else if(level == "NOTICE") {
		mLevel = "NOTICE"
	} else if(level == "META") {
		mLevel = "META"
	} else if(level == "DATA") {
		mLevel = "DATA"
	} else if(level == "DEBUG") {
		mLevel = "DEBUG"
	} //end if else
	//--
	filter := &logutils.LevelFilter{
		Levels: []logutils.LogLevel{"DEBUG", "DATA", "META", "NOTICE", "INFO", "LOG", "OK", "WARNING", "ERROR", "PANIC"},
		MinLevel: logutils.LogLevel(mLevel),
		Writer: output,
	}
	//--
	log.SetOutput(filter)
	//--
} //END FUNCTION


// PRIVATE
func isLogPathSafeDir(pathForLogs string) bool {
	//--
	if((!PathIsSafeValidSafePath(pathForLogs)) ||
		(PathIsEmptyOrRoot(pathForLogs)) ||
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


//-----


// #END
