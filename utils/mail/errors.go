
package mail

// modified by unixman # r.20260915

import (
	"fmt"
	"log"

	"runtime/debug"
)


// A SendError represents the failure to transmit a Message, detailing the cause of the failure and index of the Message within a batch.
type SendError struct {
	Index uint 		// Index specifies the index of the Message within a batch.
	Cause error
}


func (err *SendError) Error() string {
	return fmt.Sprintf("gomail: could not send email %d: %v", err.Index + 1, err.Cause)
}


//-- unixman
func panicHandler() {
	const crrFnName string = "gomail.panicHandler"
	if panicInfo := recover(); panicInfo != nil {
		log.Println("[ERROR] !!! PANIC Recovered:", panicInfo, "by", crrFnName)
		log.Println("[PANIC] !!! Debug Stack Trace:", string(debug.Stack()), "from", crrFnName)
	} //end if
} //END FUNCTION
//-- #


// #end
