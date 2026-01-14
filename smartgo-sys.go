
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260114.2358 :: STABLE
// [ SYS (OS SYSTEM) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"fmt"
	"log"

	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"time"
	"context"

	"io"
	"bytes"

	color "github.com/unix-world/smartgo/ui/colorstring"
)

const (
	CMD_EXEC_HAMMER_SIGNATURE string = "[»»»»»»»[SmartGo:{!HAMMER!}:Abort:(Exit):KILL.SIGNAL]«««««««]" // INTERNAL FLAG FOR CMD FORCE EXIT HAMMER
	CMD_EXEC_TIMED_MAX_TIMEOUT uint  = 86400
)


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
		if(AppGetRunInBackground()) { // no colors ; weird characters should not appear in logs ...
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
	if(AppGetRunInBackground()) {
		return // stop here, weird characters should not appear in logs ...
	} //end if
	//--
	print("\033[H\033[2J") // try to clear the terminal (should work on *nix and windows) ; for *nix only it can be: fmt.Println("\033[2J")
	//--
} //END FUNCTION


//-----


// kills a command executed with StartCmd() -> WaitCmd()
func KillCmd(cmd *exec.Cmd) error {
	//--
	if(cmd == nil) {
		return NewError("Command is NULL")
	} //end if
	//--
	return cmd.Process.Kill()
	//--
} //END FUNCTION


// wait for a command started with StartCmd() to finalize ; may be defered or executed async in order to call KillCmd after it
func WaitCmd(cmd *exec.Cmd) error {
	//--
	if(cmd == nil) {
		return NewError("Command is NULL")
	} //end if
	//--
	return cmd.Wait()
	//--
} //END FUNCTION


// starts a command to be used with WaitCmd() -> KillCmd()
func StartCmd(additionalEnv string, inputStdin string, theExe string, theArgs ...string) (isSuccess bool, errMsg error, stdoutRdr io.ReadCloser, stderrRdr io.ReadCloser, cmd *exec.Cmd) {
	//-- {{{SYNC-SMARTGO-CMD-MANAGE}}}
	additionalEnv = StrTrimWhitespaces(additionalEnv) // Additional ENVIRONMENT ; Example: additionalEnv = "FOO=bar"
	// inputStdin // The Input to Stdin if any ; DO NOT TRIM, must be passed exact how is get
	//--
	theExe = StrTrimWhitespaces(theExe)
	if(theExe == "") {
		return false, NewError("ERR: EXECUTABLE Name/Path is Empty"), stdoutRdr, stderrRdr, cmd
	} //end if
	//--
	theExe = SafePathFixClean(theExe)
	//--
	if(PathIsEmptyOrRoot(theExe) == true) {
		return false, NewError("ERR: EXECUTABLE Name/Path is Empty/Root"), stdoutRdr, stderrRdr, cmd
	} //end if
	if(PathIsSafeValidPath(theExe) != true) {
		return false, NewError("ERR: EXECUTABLE Name/Path is Invalid Unsafe"), stdoutRdr, stderrRdr, cmd
	} //end if
	if(PathIsBackwardUnsafe(theExe) == true) {
		return false, NewError("ERR: EXECUTABLE Name/Path is Backward Unsafe"), stdoutRdr, stderrRdr, cmd
	} //end if
	//--
	// do not check if path exists, can be a simple executable name as `ping` only !
	//--
	cmd = exec.Command(theExe, theArgs...)
	//--
	if(additionalEnv != "") {
		newEnv := append(os.Environ(), additionalEnv)
		cmd.Env = newEnv
	} //end if
	if(inputStdin != "") {
		stdin, err := cmd.StdinPipe()
		if(err != nil) {
			return false, err, stdoutRdr, stderrRdr, cmd
		} //end if
		go func() { // If the subprocess doesn't continue before the stdin is closed, the io.WriteString() call needs to be wrapped inside an anonymous function
			defer stdin.Close()
			io.WriteString(stdin, inputStdin)
		}()
	} //end if
	//--
	stdoutRdr, _ = cmd.StdoutPipe()
	stderrRdr, _ = cmd.StderrPipe()
	//--
	err := cmd.Start()
	if(err != nil) {
		return false, err, stdoutRdr, stderrRdr, cmd
	} //end if
	//--
	return true, nil, stdoutRdr, stderrRdr, cmd
	//--
} //END FUNCTION


//-----


// do execute a command with/without timeout and after it finalizes (or timeouts, if apply) it returns the output
func cmdExec(stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (isSuccess bool, outStd string, errStd string) {
	//-- {{{SYNC-SMARTGO-CMD-MANAGE}}}
	if(stopTimeout > CMD_EXEC_TIMED_MAX_TIMEOUT) {
		stopTimeout = CMD_EXEC_TIMED_MAX_TIMEOUT // 0 = no execution timeout ; 1..86400 will stop the cmd execution after this number of seconds
	} //end if
	//--
	captureStdout = StrTrimWhitespaces(captureStdout) // "" | "capture" | "capture+output" | "output"
	captureStderr = StrTrimWhitespaces(captureStderr) // "" | "capture" | "capture+output" | "output"
	//--
	additionalEnv = StrTrimWhitespaces(additionalEnv) // Additional ENVIRONMENT ; Example: additionalEnv = "FOO=bar"
	// inputStdin // The Input to Stdin if any ; DO NOT TRIM, must be passed exact how is get
	//--
	theExe = StrTrimWhitespaces(theExe)
	if(theExe == "") {
		return false, "", "ERR: EXECUTABLE Name/Path is Empty"
	} //end if
	//--
	theExe = SafePathFixClean(theExe)
	//--
	if(PathIsEmptyOrRoot(theExe) == true) {
		return false, "", "ERR: EXECUTABLE Name/Path is Empty/Root"
	} //end if
	if(PathIsSafeValidPath(theExe) != true) {
		return false, "", "ERR: EXECUTABLE Name/Path is Invalid Unsafe"
	} //end if
	if(PathIsBackwardUnsafe(theExe) == true) {
		return false, "", "ERR: EXECUTABLE Name/Path is Backward Unsafe"
	} //end if
	//--
	// do not check if path exists, can be a simple executable name as `ping` only !
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


// execute command and after it finalizes it returns the output
func ExecCmd(captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (isSuccess bool, outStd string, errStd string) {
	//--
	return cmdExec(0, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
} //END FUNCTION


// execute a command with timeout and after it finalizes or timeouts it returns the output
func ExecTimedCmd(stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (isSuccess bool, outStd string, errStd string) {
	//--
	return cmdExec(stopTimeout, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
} //END FUNCTION


//-----


// #END
