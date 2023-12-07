
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231207.0658 :: STABLE
// [ RUNTIME ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"errors"
	"log"
	"fmt"

	"time"
	"context"

	"io"
	"bytes"

	color "github.com/unix-world/smartgo/colorstring"
	"github.com/unix-world/smartgo/logutils"
)

const (
	CMD_EXEC_HAMMER_SIGNATURE string = "[»»»»»»»[SmartGo:{!HAMMER!}:Abort:(Exit):KILL.SIGNAL]«««««««]" // INTERNAL FLAG FOR CMD FORCE EXIT HAMMER
)


//-----


//func FatalError(logMessages ...interface{}) {
func FatalError(logMessages ...any) {
	//--
	log.Println("[ERROR] ! FATAL !", fmt.Sprint(logMessages...))
	os.Exit(1)
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
func (writer logWriterWithColors) Write(bytes []byte) (int, error) {
	//--
	var theMsg string = StrTrimWhitespaces(StrNormalizeSpaces(string(bytes)))
	//--
	if(logColoredOnConsole) {
		if(StrIPos(theMsg, "[ERROR]") == 0) { // {{{SYNC-SMARTGO-ERR:LEVELS+COLORS}}}
			theMsg = color.RedString(theMsg)
		} else if(StrIPos(theMsg, "[WARNING]") == 0) {
			theMsg = color.HiRedString(theMsg)
		} else if(StrIPos(theMsg, "[INFO]") == 0) {
			theMsg = color.HiYellowString(theMsg)
		} else if(StrIPos(theMsg, "[NOTICE]") == 0) {
			theMsg = color.HiBlueString(theMsg)
		} else if(StrIPos(theMsg, "[DATA]") == 0) {
			theMsg = color.YellowString(StrTrimWhitespaces(string(bytes))) // for data preserve the string how it is, except trim ! ; brown
		} else if(StrIPos(theMsg, "[DEBUG]") == 0) {
			theMsg = color.HiMagentaString(theMsg)
		} else { // ALL OTHER CASES
			if(StrIPos(theMsg, "[OK]") == 0) {
				theMsg = color.HiGreenString(theMsg)
			} else { // message
				theMsg = color.HiCyanString(theMsg)
			} //end if else
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
func (writer logWriterFile) Write(bytes []byte) (int, error) {
	//--
	var dTime string = ""
	if(logUseLocalTime) {
		dTime = DateNowLocal()
	} else {
		dTime = DateNowUtc()
	} //end if else
	//--
	var theErr string = ""
	var theMsg string = StrTrimWhitespaces(string(bytes))
	//--
	var theType string = ""
	var colorMsg string = theMsg
	if(StrIPos(theMsg, "[ERROR]") == 0) { // {{{SYNC-SMARTGO-ERR:LEVELS+COLORS}}}
		theType = "error"
		if(logColoredOnConsole) {
			colorMsg = color.RedString(colorMsg)
		} //end if
	} else if(StrIPos(theMsg, "[WARNING]") == 0) {
		theType = "warning"
		if(logColoredOnConsole) {
			colorMsg = color.HiRedString(colorMsg)
		} //end if
	} else if(StrIPos(theMsg, "[INFO]") == 0) {
		theType = "info"
		if(logColoredOnConsole) {
			colorMsg = color.HiYellowString(colorMsg)
		} //end if
	} else if(StrIPos(theMsg, "[NOTICE]") == 0) {
		theType = "notice"
		if(logColoredOnConsole) {
			colorMsg = color.HiBlueString(colorMsg)
		} //end if
	} else if(StrIPos(theMsg, "[DATA]") == 0) {
		theType = "data"
		if(logColoredOnConsole) {
			colorMsg = color.YellowString(colorMsg) // brown
		} //end if
	} else if(StrIPos(theMsg, "[DEBUG]") == 0) {
		theType = "debug"
		if(logColoredOnConsole) {
			colorMsg = color.HiMagentaString(colorMsg)
		} //end if
	} else { // ALL OTHER CASES
		theType = "message"
		if(logColoredOnConsole) {
			if(StrIPos(theMsg, "[OK]") == 0) {
				theType = "ok"
				colorMsg = color.HiGreenString(colorMsg)
			} else { // message
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
		}
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
	isSuccess, errMsg := SafePathFileWrite(theLogFile, "a", true, theFmtMsg + LINE_FEED)
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
		if(logColoredOnConsole) {
			return fmt.Println(color.GreyString("LOG | " + dTime + " | ") + colorMsg)
		} else {
			return fmt.Println("LOG | " + dTime + " | " + colorMsg)
		} //end if else
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
	} else if(level == "INFO") {
		mLevel = "INFO"
	} else if(level == "NOTICE") {
		mLevel = "NOTICE"
	} else if(level == "DATA") {
		mLevel = "DATA"
	} else if(level == "DEBUG") {
		mLevel = "DEBUG"
	} //end if else
	//--
	filter := &logutils.LevelFilter{
		Levels: []logutils.LogLevel{"DEBUG", "DATA", "NOTICE", "INFO", "WARNING", "ERROR"},
		MinLevel: logutils.LogLevel(mLevel),
		Writer: output,
	}
	log.SetOutput(filter)
	//--
} //END FUNCTION


// PRIVATE
func isLogPathSafeDir(pathForLogs string) bool {
	//--
	if((!PathIsSafeValidPath(pathForLogs)) ||
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


func LogToStdErr(level string) {
	//--
	setLogLevelOutput(level, os.Stderr)
	//--
} //END FUNCTION


func LogToConsole(level string, withColorsOnConsole bool) {
	//--
	if(ini_RUN_IN_BACKGROUND) {
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


func HandleAbortCtrlC(delay uint32) {
	//--
	if(delay < 0) {
		delay = 0
	} else if(delay > 60) {
		delay = delay
	} //end if
	//--
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		if(ini_RUN_IN_BACKGROUND) { // no colors ; weird characters should not appear in logs ...
			fmt.Println(LINE_FEED + "»»»»»»»»", "[ Hammer (Abort) ]", "... KILL.SIGNAL ...", "[ Exit Delay: " + ConvertUInt32ToStr(delay) + " sec. ]", "««««««««" + LINE_FEED)
		} else {
			fmt.Println(LINE_FEED + color.GreenString("»»»»»»»»"), color.MagentaString("[ Hammer (Abort) ]"), color.BlueString("... KILL.SIGNAL ..."), color.BlackString("[ Exit Delay: " + ConvertUInt32ToStr(delay) + " sec. ]"), color.GreenString("««««««««") + LINE_FEED)
		} //end if else
		log.Println("[INFO]", CMD_EXEC_HAMMER_SIGNATURE, "Exit Delay:", delay, "sec.")
		time.Sleep(time.Duration(int(delay)) * time.Second)
		os.Exit(1)
	}()
	//--
} //END FUNCTION


//-----


// set terminal theme Dark (bg:black ; fg:white) : print("\033[0;37;40m")
func ClearPrintTerminal() {
	//--
	if(ini_RUN_IN_BACKGROUND) {
		return // stop here, weird characters should not appear in logs ...
	} //end if
	//--
	print("\033[H\033[2J") // try to clear the terminal (should work on *nix and windows) ; for *nix only it can be: fmt.Println("\033[2J")
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
		return false, string(stdoutBuf.Bytes()), string(stderrBuf.Bytes()) + LINE_FEED + CMD_EXEC_HAMMER_SIGNATURE + ": [" + err.Error() + "]"
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


// #END
