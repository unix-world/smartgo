
// Validate :: URL
// (c) 2026-present, unix-world.org
// r.20260910.2358

package validate_url

import (
	"errors"
	"strings"
	"net/url"
)

const (
	MAX_ALLOWED_LENGTH 		int =        4096 // some browser can't but this is a kind of standard

	MAX_ALLOWED_DATA_LENGTH int = 2 * 1048576 // disallow longer data URLs than 4MB
)

//-----


func Validate(theUrl string, useDataUrlScheme bool) (string, error) {
	//--
	// if useDataUrlScheme is set to TRUE will validate `data:` kind of urls, otherwise just `http:` and `https:`
	//--
	if(theUrl == "") {
		return "", errors.New("URL is Empty")
	} //end if
	if(useDataUrlScheme == true) {
		if(len(theUrl) > MAX_ALLOWED_DATA_LENGTH) {
			return "", errors.New("Data URL is Oversized")
		} //end if
	} else {
		if(len(theUrl) > MAX_ALLOWED_LENGTH) {
			return "", errors.New("URL is Oversized")
		} //end if
	} //end if else
	//--
	u, err := url.Parse(theUrl)
	if(err != nil) {
		return "", errors.New("URL is Invalid: " + err.Error())
	} //end if
	//--
	if(useDataUrlScheme == true) {
		if(u.Scheme != "data") {
			return "", errors.New("URL Data Scheme is Unsupported: " + u.Scheme)
		} //end if else
	} else {
		if(len(u.Opaque) > 0) {
			return "", errors.New("URL is a DataURL")
		} //end if
		switch u.Scheme {
			case "http":  fallthrough
			case "https": fallthrough
			case "": // this is for relative URLs, ex: `//example.com`
				break
			default:
				return "", errors.New("URL Scheme is Unsupported: " + u.Scheme)
		} //end switch
	} //end if else
	//--
	return u.String(), nil // sanitized
	//--
} //END FUNC


func IsValid(theUrl string, useDataUrlScheme bool) bool {
	//--
	validStr, err := Validate(theUrl, useDataUrlScheme)
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
