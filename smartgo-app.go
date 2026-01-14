
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260114.2358 :: STABLE
// [ APP ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"
)

const (
	REGEX_SAFE_APP_NAMESPACE string = `^[_a-z0-9\-\.]+$` 		// Safe App Namespace Regex
)

var (
	app_RUN_IN_BACKGROUND bool 			= false 				// if this is set no escape characters are sent in logs (ex: supervisor capture stdout/stderr and log it with color / clear terminal escape sequences, should not appear in logs)
	app_SMART_SOFTWARE_NAMESPACE string = "smart-framework.go" 	// set via AppSetNamespace
)

var (
	app_SMART_FRAMEWORK_SECURITY_KEY string = "Private-Key#0987654321" // set via AppSetSecurityKey ; 16..256 ; {{{SYNC-GO-SMART-CRYPTO-SECURITY-KEY-OR-AUTH-PKEY}}}
)

//-----


func AppSetSecurityKey(key string) bool {
	//--
	key = StrTrimWhitespaces(key)
	//--
	if(key == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "SmartGo Security Key is Empty, will use the Default Built-in Key ...")
		return false
	} //end if
	//--
	var kLen int = len(key)
	if((kLen < 16) || (kLen > 256)) { // {{{SYNC-GO-SMART-CRYPTO-SECURITY-KEY-OR-AUTH-PKEY}}}
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo Security Key must be between 16 and 255 caracters long ...")
		return false
	} //end if
	//--
	app_SMART_FRAMEWORK_SECURITY_KEY = key
	//--
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo Security Key was Set (size is `" + ConvertIntToStr(len(app_SMART_FRAMEWORK_SECURITY_KEY)) + "` bytes): Success")
	//--
	return true
	//--
} //END FUNCTION


func AppGetSecurityKey() (string, error) {
	//--
	var key string = StrTrimWhitespaces(app_SMART_FRAMEWORK_SECURITY_KEY)
	//--
	var kLen int = len(key)
	if((kLen < 16) || (kLen > 256)) { // {{{SYNC-GO-SMART-CRYPTO-SECURITY-KEY-OR-AUTH-PKEY}}}
		return "", NewError("SmartGo Security Key must be between 16 and 255 caracters long")
	} //end if
	//--
	return key, nil
	//--
} //END FUNCTION


//-----


func AppSetRunInBackground() bool {
	//--
	app_RUN_IN_BACKGROUND = true
	//--
	return app_RUN_IN_BACKGROUND
	//--
} //END FUNCTION


func AppGetRunInBackground() bool {
	//--
	return app_RUN_IN_BACKGROUND
	//--
} //END FUNCTION


//-----


func AppSetNamespace(ns string) bool {
	//--
	ns = StrTrimWhitespaces(ns)
	var nLen int = len(ns)
	if((nLen < 4) || (nLen > 63)) {
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo App Namespace must be between 4 and 63 caracters long ...")
		return false
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_APP_NAMESPACE, ns)) {
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo App Namespace contains invalid characters ...")
		return false
	} //end if
	//--
	app_SMART_SOFTWARE_NAMESPACE = ns
	//--
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo App Namespace was Set to `" + app_SMART_SOFTWARE_NAMESPACE + "`: Success")
	//--
	return true
	//--
} //END FUNCTION


func AppGetNamespace() (string, error) {
	//--
	var ns string = StrTrimWhitespaces(app_SMART_SOFTWARE_NAMESPACE)
	//--
	var nLen int = len(ns)
	if((nLen < 4) || (nLen > 63)) {
		return "", NewError("SmartGo App Namespace must be between 16 and 255 caracters long")
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_APP_NAMESPACE, ns)) {
		return "", NewError("SmartGo App Namespace contains invalid characters")
	} //end if
	//--
	return ns, nil
	//--
} //END FUNCTION


//-----


// #END
