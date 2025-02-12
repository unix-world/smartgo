
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250210.2358 :: STABLE
// [ CRYPTO / SIGNIFY ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	signify "github.com/unix-world/smartgo/crypto/signify"
)

//-----


func SignifyVerify(pubkeyTxt []byte, signatureText []byte, isDetached bool, dataToCheck []byte) error {
	//--
	// dataToCheck can be binary data but only if isDetached is TRUE
	//--
	defer PanicHandler()
	//--
	pubkeyTxt = BytTrimWhitespaces(pubkeyTxt)
	if(pubkeyTxt == nil) {
		return NewError("Public Key Text is Empty")
	} //end if
	//--
	signatureText = BytTrimWhitespaces(signatureText)
	if(signatureText == nil) {
		return NewError("Signature Text is Empty")
	} //end if
	//-- DO NOT TRIM dataToCheck, it may be binary data !
	if(isDetached != true) { // embedded
		if(dataToCheck != nil) {
			return NewError("Data must Empty for Non-Detached Signature, as the Data is Embedded after the Signature") // see OpenBSD ...
		} //end if
	} else { // detached
		if(dataToCheck == nil) {
			return NewError("Data is Empty for Detached Signature")
		} //end if
	} //end if
	//--
	commentPubKey, sRawPubKey, errRdSgn := signify.ReadData(pubkeyTxt)
	if(errRdSgn != nil) {
		return NewError("Parse Public Key Text Failed: " + errRdSgn.Error())
	} //end if
	if(sRawPubKey == nil) {
		return NewError("Parse Public Key Text Failed: PubKey is Null")
	} //end if
	commentPubKey = StrTrimWhitespaces(commentPubKey)
	if(commentPubKey == "") {
		return NewError("Parse Public Key Text Failed: Comment is Empty")
	} //end if
	//--
	pubKey, errPubKey := signify.ParsePublicKey(sRawPubKey)
	if(errPubKey != nil) {
		return NewError("Parse Public Key Failed: " + errPubKey.Error())
	} //end if
	if(pubKey == nil) {
		return NewError("Parse Public Key Failed: PubKey is Null")
	} //end if
	//--
	commentData, dataBytSgn, errRdData := signify.ReadData(signatureText)
	if(errRdData != nil) {
		return NewError("Parse Signature Text Failed: " + errRdData.Error())
	} //end if
	if(dataBytSgn == nil) {
		return NewError("Parse Signature Text Failed: Signature is Null")
	} //end if
	commentData = StrTrimWhitespaces(commentData)
	if(commentData == "") {
		return NewError("Parse Signature Text Failed: Comment is Empty")
	} //end if
	//--
	if(isDetached != true) { // embedded
		//--
		var dataB64BytSgn []byte = nil
		dataB64BytSgn = append(dataB64BytSgn, '\n')
		dataB64BytSgn = append(dataB64BytSgn, Base64BytEncode(dataBytSgn)...)
		dataB64BytSgn = append(dataB64BytSgn, '\n')
		if(BytContains(signatureText, dataB64BytSgn) != true) {
			return NewError("Parse Signature Text Failed: B64 Signature does not match")
		} //end if
		//--
		dataToCheck = nil // make sure ...
		arrData := BExplodeWithLimit(dataB64BytSgn, signatureText, 2)
		if(len(arrData) != 2) {
			return NewError("Parse Signature with Data Text Failed: Invalid Parts")
		} //end if
		dataToCheck = arrData[1]
		arrData = nil
		dataToCheck = BytTrimWhitespaces(dataToCheck) // embedded data must be trimmed, is not detached, so can be only safe text data
		if(BytTrimWhitespaces(dataToCheck) == nil) {
			return NewError("Parse Signature with Data Text Failed: Invalid Data Part")
		} //end if
		//--
	} //end if
	//--
	dataToCheck = append(dataToCheck, '\n') // verified data also must end with a single LF ; this is for all cases: binary/detached or embedded
	//--
	signature, errSgn := signify.ParseSignature(dataBytSgn)
	if(errSgn != nil) {
		return NewError("Parse Data Signature Failed: " + errSgn.Error())
	} //end if
	if(signature == nil) {
		return NewError("Parse Data Signature Failed: Ed25519 Signature is Null")
	} //end if
	//--
	var vfyData bool = signify.Verify(pubKey, dataToCheck, signature)
	if(vfyData != true) {
		return NewError("Ed25519 Signature is Invalid, Verification Failed, does Not Match Data")
	} //end if
	//--
	return nil // Ed25519 Signature Verified
	//--
} //END FUNCTION


//-----


// #END
