
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260806.2358 :: STABLE
// [ CRYPTO / SIGNIFY ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	cryptorand "crypto/rand"

	signify "github.com/unix-world/smartgo/crypto/signify"
)


//-----

const (
	SignifyErrInvalidSignature string = "Signify (Ed25519) Signature is Invalid, Verification Failed, does Not Match Data"
)

//----- how to verify detached signature: signify -C -p signify-key.pub -x signify-signature.sig file1 file2 ... fileN


func SignifyGenerateKeys(privKeyPass []byte, allowEmptyPass bool) (string, string, error) { // pubKey, privKey, err
	//--
	defer PanicHandler()
	//--
	if((allowEmptyPass != true) && (privKeyPass == nil)) {
		return "", "", NewError("Priv Key Pass Phrase is Empty")
	} //end if
	//--
	pubKey, privKey, errKeys := signify.GenerateKey(cryptorand.Reader)
	if(errKeys != nil) {
		return "", "", errKeys
	} //end if
	if(privKey == nil) {
		return "", "", NewError("Priv Key is Null")
	} //end if
	if(pubKey == nil) {
		return "", "", NewError("Pub Key is Null")
	} //end if
	//--
	bytPrivKey, errMPrivKey := signify.MarshalPrivateKey(privKey, cryptorand.Reader, privKeyPass, -1) // -1 is for: defaultKDFRounds
	if(errMPrivKey != nil) {
		return "", "", errMPrivKey
	} //end if
	if(bytPrivKey == nil) {
		return "", "", NewError("Marshal Priv Key is Null")
	} //end if
	//--
	var commntPrivKey string = "signify private key"
	if(privKeyPass != nil) {
		commntPrivKey += " (protected)"
	} //end if
	commntPrivKey += " # " + DateNowUtc()
	privDataKey, errWrPrivKey := signify.WriteData(commntPrivKey, bytPrivKey)
	if(errWrPrivKey != nil) {
		return "", "", NewError("Failed to Compose Priv Key: " + errWrPrivKey.Error())
	} //end if
	privDataKey = BytTrimWhitespaces(privDataKey)
	if(privDataKey == nil) {
		return "", "", NewError("Priv Key is Empty")
	} //end if
	//--
	bytPubKey := signify.MarshalPublicKey(pubKey)
	if(bytPubKey == nil) {
		return "", "", NewError("Marshal Pub Key is Null")
	} //end if
	//--
	var commntPubKey string = "signify public key" + " # " + DateNowUtc()
	pubDataKey, errWrPubKey := signify.WriteData(commntPubKey, bytPubKey)
	if(errWrPubKey != nil) {
		return "", "", NewError("Failed to Compose Pub Key: " + errWrPubKey.Error())
	} //end if
	pubDataKey = BytTrimWhitespaces(pubDataKey)
	if(pubDataKey == nil) {
		return "", "", NewError("Pub Key is Empty")
	} //end if
	//--
	return string(pubDataKey) + "\n", string(privDataKey) + "\n", nil // fix: add endline LF terminator to be compatible with OpenBSD's Signify
	//--
} //END FUNCTION


//-----


func SignifyVerify(pubkeyTxt []byte, signatureText []byte, isDetached bool, dataToCheck []byte) error {
	//--
	// dataToCheck can be binary data but only if isDetached is TRUE
	//--
	defer PanicHandler()
	//--
	pubkeyTxt = BytTrimWhitespaces(pubkeyTxt)
	if(pubkeyTxt == nil) {
		return NewError("Public Key Text is Empty, Null")
	} //end if
	//--
	if(BytTrimWhitespaces(signatureText) == nil) {
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
			return NewError("Parse Signature Text Failed: Text Signature does not match")
		} //end if
		//--
		dataToCheck = nil // make sure ...
		arrData := BExplodeWithLimit(dataB64BytSgn, signatureText, 2)
		if(len(arrData) != 2) {
			return NewError("Parse Signature with Data Text Failed: Invalid Parts")
		} //end if
		dataToCheck = arrData[1]
		arrData = nil
		if(BytTrimWhitespaces(dataToCheck) == nil) {
			return NewError("Parse Signature with Data Text Failed: Invalid Data Part")
		} //end if
		//--
	} //end if
	//--
	signature, errSgn := signify.ParseSignature(dataBytSgn)
	if(errSgn != nil) {
		return NewError("Parse Data Signature Failed: " + errSgn.Error())
	} //end if
	if(signature == nil) {
		return NewError("Parse Data Signature Failed: Signature is Null")
	} //end if
	//--
	var vfyData bool = signify.Verify(pubKey, dataToCheck, signature)
	if(vfyData != true) {
		return NewError(SignifyErrInvalidSignature)
	} //end if
	//--
	return nil // Signature Verified
	//--
} //END FUNCTION


//-----


func SignifySign(privKeyTxt []byte, privKeyPass []byte, pubkeyTxt []byte, dataToSign []byte, comment string, isDetached bool) (error, string) {
	//--
	defer PanicHandler()
	//--
	privKeyTxt = BytTrimWhitespaces(privKeyTxt)
	if(privKeyTxt == nil) {
		return NewError("Private Key Text is Empty, Null"), ""
	} //end if
	//--
	pubkeyTxt = BytTrimWhitespaces(pubkeyTxt)
	if(pubkeyTxt == nil) {
		return NewError("Public Key Text is Empty, Null"), ""
	} //end if
	//--
	commentPrivKey, sRawPrivKey, errRdSgn := signify.ReadData(privKeyTxt)
	if(errRdSgn != nil) {
		return NewError("Parse Private Key Text Failed: " + errRdSgn.Error()), ""
	} //end if
	if(sRawPrivKey == nil) {
		return NewError("Parse Private Key Text Failed: PrivKey is Null"), ""
	} //end if
	commentPrivKey = StrTrimWhitespaces(commentPrivKey)
	if(commentPrivKey == "") {
		return NewError("Parse Private Key Text Failed: Comment is Empty"), ""
	} //end if
	//--
	if(dataToSign == nil) {
		return nil, ""
	} //end if
	//--
	comment = StrNormalizeSpaces(comment)
	comment = StrTrimWhitespaces(comment)
	if(len(comment) > 87) {
		return NewError("Comment is Too Long"), ""
	} //end if
	//--
	privKey, errPrivKey := signify.ParsePrivateKey(sRawPrivKey, privKeyPass)
	if(errPrivKey != nil) {
		return errPrivKey, ""
	} //end if
	if(privKey == nil) {
		return NewError("Private Key Parsing Failed, Null"), ""
	} //end if
	//--
	signature := signify.Sign(privKey, dataToSign)
	if(signature == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	//--
	bytSignature := signify.MarshalSignature(signature)
	if(bytSignature == nil) {
		return NewError("Sign Marshal Signature Failed, Null"), ""
	} //end if
	//--
	signedData, errWrSgn := signify.WriteData(comment + " # " + DateNowUtc(), bytSignature)
	if(errWrSgn != nil) {
		return errWrSgn, ""
	} //end if
	if(signedData == nil) {
		return NewError("Sign Signature Failed, Null"), ""
	} //end if
	//--
	if(isDetached == false) {
		signedData = append(signedData, []byte(dataToSign)...)
	} else {
		signedData = BytTrimWhitespaces(signedData)
	} //end if
	//--
	dataToVfy := dataToSign
	if(isDetached == false) {
		dataToVfy = nil
	} //end if
	errVfy := SignifyVerify(pubkeyTxt, signedData, isDetached, dataToVfy)
	if(errVfy != nil) {
		return NewError("Sign Verification Failed: " + errVfy.Error()), ""
	} //end if
	//--
	return nil, string(signedData)
	//--
} //END FUNCTION


//-----


// #END
