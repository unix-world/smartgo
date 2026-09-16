
package dkim

// by unixman
// r.20260915

import(
	"errors"
	"strings"
	"strconv"
	"regexp"
)

const (
	REGEX_SAFE_B64_STR  string = `^[a-zA-Z0-9\+\/\=]+$`
)


func LookUpPrefixWithSelector(selector string) string {
	//--
	selector = strings.TrimSpace(selector)
	//--
	return selector + LookUpPrefix
	//--
} //END FUNCTION


func CreateTxtDkimRecord(thePublicKey string, typ string) (string, error) {
	//--
	thePublicKey = strings.TrimSpace(thePublicKey)
	if(thePublicKey == "") {
		return "", errors.New("B64 Public Key is Empty")
	} //end if
	if(len(thePublicKey) > 768) { // {{{SYNC-DKIM:MAX-KEY.SIZE-VS-MAX-TXT.RECORD.SIZE}}}
		return "", errors.New("B64 Public Key is Oversized")
	} //end if
	matched, errRx := regexp.MatchString(REGEX_SAFE_B64_STR, thePublicKey)
	if(errRx != nil) {
		return "", errors.New("B64 Public Key could not be validated")
	} //end if
	if(!matched) {
		return "", errors.New("B64 Public Key contains invalid characters")
	} //end if
	//--
	switch(typ) {
		case "rsa": 		fallthrough
		case "ecdsa256": 	fallthrough
		case "ecdsa384": 	fallthrough
		case "ecdsa521": 	fallthrough
		case "ed25519":
			break
		default:
			return "", errors.New("Unsupported Public Key Type: `" + typ + "`")
	} //end switch
	//--
	params := []string{
		"v=DKIM1",
		"k=" + typ,
		"p=" + thePublicKey,
	}
	//--
	var txtRec string = strings.TrimSpace(strings.Join(params, "; "))
	var lRec int = len(txtRec)
	if(lRec <= 0) {
		return "", errors.New("TXT record is empty")
	} //end if
	if(lRec > 1024) { // {{{SYNC-DKIM:MAX-KEY.SIZE-VS-MAX-TXT.RECORD.SIZE}}} ; max supported by DNS is 255 but for RSA this value is not enough, 4096 key is ~ 768 bytes with the rest of DKIM TXT record info
		return "", errors.New("TXT record is oversized: " + strconv.Itoa(lRec) + " bytes")
	} //end if
	//--
	return txtRec, nil
	//--
} //END FUNCTION


// #end
