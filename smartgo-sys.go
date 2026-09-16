
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE
// [ SYS (OS SYSTEM) ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"fmt"
	"log"

	"time"
	"context"

	"bytes"
	"io"

	"os"
	"os/exec"
	"os/signal"
	"syscall"

	color "github.com/unix-world/smartgo/ui/colorstring"
)

const (
	CMD_EXEC_TIMED_MAX_TIMEOUT 		   uint = 86400

	CMD_EXEC_HAMMER_SIGNATURE 		 string = "[»»»»»»»[SmartGo:{!HAMMER!}:Abort:(Exit):KILL.SIGNAL]«««««««]" // INTERNAL FLAG FOR CMD FORCE EXIT HAMMER
	CMD_ERR_SIGNATURE_KILLED  		 string = "[signal: killed]"
	CMD_EXEC_HAMMER_KILLED_SIGNATURE string = CMD_EXEC_HAMMER_SIGNATURE + ": " + CMD_ERR_SIGNATURE_KILLED
	CMD_EXEC_HAMMER_KILLED_EXITCODE     int = -1234567890 // {{{SYNC-EXIT-CODE-ZERO-ON-HAMMER-KILLED}}} ; need to have a fixed exit code here, on windows the hammer signature does not work ...

	CMD_EXEC_MODE_CAPTURE 			 string = "capture"
	CMD_EXEC_MODE_OUT_PLUS_CAPTURE 	 string = "capture+output"
	CMD_EXEC_MODE_OUTPUT 			 string = "output"
)


//-----


type ShutdownFn func()

func handleDoAbortCtrlC(delay uint32, sFn ShutdownFn) {
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
		if(sFn != nil) {
			sFn()
		} //end if
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


func HandleAbortCtrlCWithShutdownHandler(delay uint32, sFn ShutdownFn) {
	//--
	handleDoAbortCtrlC(delay, sFn)
	//--
} //END FUNCTION


func HandleAbortCtrlC(delay uint32) {
	//--
	handleDoAbortCtrlC(delay, nil)
	//--
} //END FUNCTION


//-----


func GetProcPid() int {
	//--
	return os.Getpid()
	//--
} //END FUNCTION


func GetParentProcPid() int {
	//--
	return os.Getppid()
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
func WaitCmd(cmd *exec.Cmd) (int, error) {
	//--
	if(cmd == nil) {
		return -1001, NewError("Command is NULL")
	} //end if
	//--
	err := cmd.Wait()
	//--
	var exitCode int = 0
	exitErr, okExit := err.(*exec.ExitError) // {{{SYNC-GET-EXEC-CMD-EXIT-CODE}}}
	if(okExit) {
		if(exitErr != nil) {
			exitCode = exitErr.ExitCode() // {{{SYNC-GET-EXEC-CMD-EXIT-CODE}}}
		} //end if
	} //end if
	//--
	if(err != nil) {
		if(exitCode == 0) {
			exitCode = -4001 // {{{SYNC-EXIT-CODE-ZERO-ON-ERR-STD}}}
		} //end if
	} //end if
	//--
	return exitCode, err
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


// do execute a command with/without timeout and after it finalizes (or timeouts, if apply) it returns the std output as pipe and err output as []byte
func CmdBytPipeExec(stdoutWriter io.Writer, stderrWriter io.Writer, stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (int, error) {
	//--
	if(stdoutWriter == nil) {
		return -1001, NewError("ERR: STD Out Writer is Null")
	} //end if
	if(stderrWriter == nil) {
		return -1002, NewError("ERR: STD ERR Writer is Null")
	} //end if
	//-- {{{SYNC-SMARTGO-CMD-MANAGE}}}
	if(stopTimeout > CMD_EXEC_TIMED_MAX_TIMEOUT) {
		stopTimeout = CMD_EXEC_TIMED_MAX_TIMEOUT // 0 = no execution timeout ; 1..86400 will stop the cmd execution after this number of seconds
	} //end if
	//--
	captureStdout = StrToLower(StrTrimWhitespaces(captureStdout)) // "" | CMD_EXEC_MODE_CAPTURE | CMD_EXEC_MODE_OUT_PLUS_CAPTURE | CMD_EXEC_MODE_OUTPUT
	captureStderr = StrToLower(StrTrimWhitespaces(captureStderr)) // "" | CMD_EXEC_MODE_CAPTURE | CMD_EXEC_MODE_OUT_PLUS_CAPTURE | CMD_EXEC_MODE_OUTPUT
	//--
	additionalEnv = StrTrimWhitespaces(additionalEnv) // Additional ENVIRONMENT ; Example: additionalEnv = "FOO=bar"
	// inputStdin // The Input to Stdin if any ; DO NOT TRIM, must be passed exact how is get
	//--
	theExe = StrTrimWhitespaces(theExe)
	if(theExe == "") {
		return -2001, NewError("ERR: EXECUTABLE Name/Path is Empty")
	} //end if
	//--
	theExe = SafePathFixClean(theExe)
	//--
	if(PathIsEmptyOrRoot(theExe) == true) {
		return -2002, NewError("ERR: EXECUTABLE Name/Path is Empty/Root")
	} //end if
	if(PathIsSafeValidPath(theExe) != true) {
		return -2003, NewError("ERR: EXECUTABLE Name/Path is Invalid Unsafe")
	} //end if
	if(PathIsBackwardUnsafe(theExe) == true) {
		return -2004, NewError("ERR: EXECUTABLE Name/Path is Backward Unsafe")
	} //end if
	//--
	// do not check if path exists, can be a simple executable name as `ping` only !
	//--
	var commandKilled bool = false
	var cmd *exec.Cmd = nil
	if(stopTimeout > 0) { // timed command
		ctx := context.Background()
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(stopTimeout)*time.Second)
		defer cancel()
		var afterCancelFx = func() {
			commandKilled = true
			stderrWriter.Write([]byte(LINE_FEED + CMD_EXEC_HAMMER_KILLED_SIGNATURE)) // DO NOT MODIFY THIS, this is a special flag for context cancelation to catch the cause being canceled
		} //end fx
		context.AfterFunc(ctx, afterCancelFx)
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
			return -3001, NewError("StdinPipe Failed: " + err.Error())
		} //end if
		go func() { // If the subprocess doesn't continue before the stdin is closed, the io.WriteString() call needs to be wrapped inside an anonymous function
			defer stdin.Close()
			io.WriteString(stdin, inputStdin)
		}()
	} //end if
	//--
	if(captureStdout == CMD_EXEC_MODE_CAPTURE) { // capture stdout
		cmd.Stdout = stdoutWriter // cmd.Stdout = &stdoutBuf
	} else if(captureStdout == CMD_EXEC_MODE_OUT_PLUS_CAPTURE) { // capture stdout and print to stdout
		cmd.Stdout = io.MultiWriter(os.Stdout, stdoutWriter)
	} else if(captureStdout == CMD_EXEC_MODE_OUTPUT) { // print stdout
		cmd.Stdout = io.Writer(os.Stdout)
	} //end if
	if(captureStderr == CMD_EXEC_MODE_CAPTURE) { // capture stderr
		cmd.Stderr = stderrWriter // cmd.Stderr = &stderrBuf
	} else if(captureStderr == CMD_EXEC_MODE_OUT_PLUS_CAPTURE) { // capture stderr and print to stderr
		cmd.Stderr = io.MultiWriter(os.Stderr, stderrWriter)
	} else if(captureStderr == CMD_EXEC_MODE_OUTPUT) { // print to stderr
		cmd.Stderr = io.Writer(os.Stderr)
	} //end if
	//--
	var exitCode int = 0
	err := cmd.Run()
	if(err != nil) {
		//--
		exitErr, okExit := err.(*exec.ExitError) // {{{SYNC-GET-EXEC-CMD-EXIT-CODE}}}
		if(okExit) {
			if(exitErr != nil) {
				exitCode = exitErr.ExitCode() // {{{SYNC-GET-EXEC-CMD-EXIT-CODE}}}
			} //end if
		} //end if
		//--
		if(commandKilled) { // {{{SYNC-COMMAND-KILLED-ERR}}} ; special case: must be a non-null error, but empty, to know was not a success ; if empty will not append to stderr as in this case stderr must end with a special flag: CMD_EXEC_HAMMER_KILLED_SIGNATURE ; also this error may differ from linux to windows so the message of this error does not really matter, important is to know was killed not raising other error ! ...
			return CMD_EXEC_HAMMER_KILLED_EXITCODE, NewError("Killed: Real ExitCode=" + ConvertIntToStr(exitCode)) // {{{SYNC-EXIT-CODE-ZERO-ON-HAMMER-KILLED}}} ; need to have a fixed exit code here, on windows the hammer signature does not work ...
		} //end if
		//--
		if(exitCode == 0) { // this is normally non-zero on error, but just in case if zero map bellow to a non-zero exit code
			exitCode = -4001 // {{{SYNC-EXIT-CODE-ZERO-ON-ERR-STD}}}
		} //end if
		return exitCode, NewError("Command Execution Failed: [" + err.Error() + "]")
	} //end if
	//--
	return exitCode, nil
	//--
} //END FUNCTION


// do execute a command with/without timeout and after it finalizes (or timeouts, if apply) it returns the outputs as []byte
func cmdBytExec(stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (exitCode int, outStd []byte, errStd []byte) {
	//--
	var outBytStd bytes.Buffer
	wStd := io.Writer(&outBytStd)
	//--
	var errBytStd bytes.Buffer
	wErr := io.Writer(&errBytStd)
	//--
	cmdExitCode, err := CmdBytPipeExec(wStd, wErr, stopTimeout, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	if(err != nil) {
		wErr.Write([]byte(LINE_FEED + err.Error())) // needs a leading new line to make pretty output
	} //end if
	//--
	return cmdExitCode, outBytStd.Bytes(), errBytStd.Bytes()
	//--
} //END FUNCTION


// execute command and after it finalizes it returns the outputs as []byte
func ExecBytCmd(captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (exitCode int, outStd []byte, errStd []byte) {
	//--
	return cmdBytExec(0, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
} //END FUNCTION


// execute a command with timeout and after it finalizes or timeouts it returns the outputs as []byte
func ExecBytTimedCmd(stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (exitCode int, outStd []byte, errStd []byte) {
	//--
	return cmdBytExec(stopTimeout, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
} //END FUNCTION


// do execute a command with/without timeout and after it finalizes (or timeouts, if apply) it returns the outputs as string
func cmdExec(stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (exitCode int, outStd string, errStd string) {
	//--
	cmdExitCode, outBytStd, errBytStd := cmdBytExec(stopTimeout, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
	return cmdExitCode, string(outBytStd), string(errBytStd)
	//--
} //END FUNCTION


// execute command and after it finalizes it returns the outputs as string
func ExecCmd(captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (exitCode int, outStd string, errStd string) {
	//--
	return cmdExec(0, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
} //END FUNCTION


// execute a command with timeout and after it finalizes or timeouts it returns the outputs as string
func ExecTimedCmd(stopTimeout uint, captureStdout string, captureStderr string, additionalEnv string, inputStdin string, theExe string, theArgs ...string) (exitCode int, outStd string, errStd string) {
	//--
	return cmdExec(stopTimeout, captureStdout, captureStderr, additionalEnv, inputStdin, theExe, theArgs ...)
	//--
} //END FUNCTION


//-----


// #END
