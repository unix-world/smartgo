
// Package dkim creates and verifies DKIM signatures, as specified in RFC 6376.
//
// # FAQ
//
// Why can't I verify a [net/mail.Message] directly? A [net/mail.Message]
// header is already parsed, and whitespace characters (especially continuation
// lines) are removed. Thus, the signature computed from the parsed header is
// not the same as the one computed from the raw header.
//
// How can I publish my public key? You have to add a TXT record to your DNS
// zone. See [RFC 6376 appendix C]. You can use the dkim-keygen tool included
// in go-msgauth to generate the key and the TXT record.
//
// [RFC 6376 appendix C]: https://tools.ietf.org/html/rfc6376#appendix-C
package dkim

// modified by unixman
// r.20260915

import (
	"errors"
	"time"
	"bytes"
	"strings"
)

var now = time.Now

const (
	LookUpPrefix string = "._domainkey."

	txtRecordPrefixVar string = "v="
	txtRecordPrefixVal string = "DKIM1"

	TxtRecordPrefix    string = txtRecordPrefixVar + txtRecordPrefixVal

	headerFieldName    string = "DKIM-Signature"
)


//-- unixman
func SignMimeMessage(dkimOpts *SignOptions, messageToSign []byte) (string, error) {
	//--
	if(dkimOpts == nil) {
		return "", errors.New("DKIM Options are Null")
	} //end if
	if(len(messageToSign) <= 0) {
		return "", errors.New("DKIM Message To Sign is Empty or Null")
	} //end if
	//--
	dKimSigner, errDkimInitSign := NewSigner(dkimOpts)
	if(errDkimInitSign != nil) {
		return "", errors.New("DKIM Signer Init Failed: " + errDkimInitSign.Error())
	} //end if
	if(dKimSigner == nil) {
		return "", errors.New("DKIM Signer Init Failed, Null")
	} //end if
	numBytes, errWrite := dKimSigner.Write(messageToSign)
	if(errWrite != nil) {
		return "", errors.New("DKIM Signer Write Failed: " + errWrite.Error())
	} //end if
	if(numBytes != len(messageToSign)) {
		return "", errors.New("DKIM Signer Write Failed, Invalid Length")
	} //end if
	errClose := dKimSigner.Close()
	if(errClose != nil) {
		return "", errors.New("DKIM Signer Close Failed: " + errClose.Error())
	} //end if
	//--
	var theSignature string = strings.TrimSpace(dKimSigner.Signature())
	if(theSignature == "") {
		return "", errors.New("DKIM Signature is Empty")
	} //end if
	//--
	return theSignature, nil
	//--
} //END FUNCTION


func VerifySignedMimeMessage(dkimVfyOpts *VerifyOptions, signedMimeMessage []byte) (bool, []*Verification, error) {
	//--
	if(dkimVfyOpts == nil) {
		return false, nil, errors.New("DKIM Verify Options are Null")
	} //end if
	if(len(signedMimeMessage) <= 0) {
		return false, nil, errors.New("DKIM Message To Verify is Empty or Null")
	} //end if
	//--
	r := bytes.NewBuffer([]byte(signedMimeMessage))
	verifications, errVfy := VerifyWithOptions(r, dkimVfyOpts)
	if(errVfy != nil) {
		return false, nil, errors.New("DKIM Verify Failed: " + errVfy.Error())
	} //end if
	//--
	var ok bool = true
	var err error = nil
	if(len(verifications) > 0) {
		for _, v := range verifications {
			if(v != nil) {
				if(v.Err != nil) {
					ok = false
					break
				} //end if else
			} //end if
		} //end for
	} else {
		ok = false
		verifications = nil // reset
		err = errors.New("No DKIM Verification was made")
	} //end if else
	//--
	return ok, verifications, err
	//--
} //END FUNCTION
//-- #


// #end
