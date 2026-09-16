
// Validate :: DataURL
// (c) 2026-present, unix-world.org
// r.20260910.2358

package validate_data_url

import (
	"errors"
	"strings"
	"regexp"

	validate_url "github.com/unix-world/smartgo/validate/url"
)

const ( // {{{SYNC-REGEX-VALIDATE-DATA-URL-GO}}}
	REGEX_VALID_DATA_URL string = `(?i)^\s*data:([a-z]+\/[a-z0-9\-\+\.]+(;[a-z\-]+\=[a-z0-9\-]+)?)?(;base64)?,([a-z0-9\!\$&',\(\)\*\+;\=\-\._~\:@\/\?%]*)\s*$` // based on from gist.github.com/bgrins/6194623 but removed last [space]
)


//-----


func Validate(dataUrl string) (string, error) {
	//--
	if(dataUrl == "") {
		return "", errors.New("DataURL is Empty")
	} //end if
	if(len(dataUrl) > validate_url.MAX_ALLOWED_DATA_LENGTH) {
		return "", errors.New("DataURL is Oversized")
	} //end if
	//--
	dataLowerUrl := strings.ToLower(dataUrl)
	//--
	if(strings.HasPrefix(dataLowerUrl, strings.ToLower("data:,http:"))) {
		return "", errors.New("DataURL contains disallowed prefix, data:http")
	} //end if
	if(strings.HasPrefix(dataLowerUrl, strings.ToLower("data:,https:"))) {
		return "", errors.New("DataURL contains disallowed prefix, data:https")
	} //end if
	if(strings.HasPrefix(dataLowerUrl, strings.ToLower("data:,mailto:"))) {
		return "", errors.New("DataURL contains disallowed prefix, data:mailto:")
	} //end if
	//--
	matched, errRx := regexp.MatchString(REGEX_VALID_DATA_URL, dataUrl)
	if(errRx != nil) {
		return "", errors.New("Invalid Regexp Expression: " + errRx.Error())
	} //end if
	if(!matched) {
		return "", errors.New("DataURL is Invalid")
	} //end if
	//--
	u, errValidate := validate_url.Validate(dataUrl, true) // allow opaque
	if(errValidate != nil) {
		return "", errors.New("DataURL is Invalid: " + errValidate.Error())
	} //end if
	//--
	return u, nil
	//--
} //END FUNC


func IsValid(dataUrl string) bool {
	//--
	validStr, err := Validate(dataUrl)
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
