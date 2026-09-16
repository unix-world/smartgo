
// Validate :: Email
// (c) 2026-present, unix-world.org
// r.20260910.2358

package validate_email_address

import (
	"errors"
	"strings"
	"net/mail"
)

const (
	MAX_ALLOWED_LENGTH int = 254 // RFC
)

//-----


func Validate(emailAddr string) (string, error) {
	//--
	// can contain a-z A-Z 0-9 . - _
	// can also contain unquoted, when used as separators: ! # \$ % & ' * + / = ? ^ ` { | } ~
	// can also contain unicode characters such as: ± § (or others)
	// will allow also input like `Alice <alice@example.com>`
	// will return sanitized email as `alice@example.com`
	//--
	if(emailAddr == "") {
		return "", errors.New("Email Address is Empty")
	} //end if
	if(len(emailAddr) > MAX_ALLOWED_LENGTH) {
		return "", errors.New("Email Address is Oversized")
	} //end if
	//--
	if(!strings.Contains(emailAddr, "@")) {
		return "", errors.New("Email Address must contain @")
	} //end if
	//--
	eml, err := mail.ParseAddress(emailAddr)
	if(err != nil) {
		return "", errors.New("Email Address is Invalid: " + err.Error())
	} //end if
	//--
	return eml.Address, nil
	//--
} //END FUNCTION


func IsValid(emailAddr string) bool {
	//--
	validStr, err := Validate(emailAddr)
	if(err != nil) {
		return false
	} //end if
	if(strings.TrimSpace(validStr) == "") {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


// #end
