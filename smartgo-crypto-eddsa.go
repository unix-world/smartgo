
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260821.2358 :: STABLE
// [ CRYPTO / EDDSA ]

// REQUIRE: go 1.22 or later
package smartgo

import (
	"bytes"
	"io"

	cryptorand "crypto/rand"

	"crypto/ed25519"
	"github.com/unix-world/smartgo/crypto/eddsa/edx25519"

	"github.com/unix-world/smartgo/crypto/eddsa/ed448"
	"github.com/unix-world/smartgo/crypto/eddsa/edx448"
)


//-----

const (
	EdDsaErrInvalidSignature = "Signature is Invalid, Verification Failed, does Not Match Data"
)

//----- ed25519


func Ed25519NewKeyPair(secretSeed []byte) (string, string, error) { // pubKey, privKey, err
	//--
	// if secret is Null will use a random secret ; if non-Null will use the secret as the seed, as in PHP
	//--
	defer PanicHandler()
	//--
	var randOrSeedReader io.Reader
	//--
	if(secretSeed == nil) { // random secret
		randOrSeedReader = cryptorand.Reader
	} else { // seeded secret
		if(len(secretSeed) != 32) {
			return "", "", NewError("Secret must be exact 32 bytes")
		} //end if
		randOrSeedReader = bytes.NewReader(secretSeed)
	} //end if
	//--
	if(randOrSeedReader == nil) {
		return "", "", NewError("IO Reader is Null")
	} //end if
	//--
	pubKey, privKey, err := ed25519.GenerateKey(randOrSeedReader)
	if(err != nil) {
		return "", "", NewError("Generate Key Failed: " + err.Error())
	} //end if
	//--
	var privateKey string = string(privKey) // plain, not password protected !
	var publicKey  string = string(pubKey)
	if(privateKey == "") {
		return "", "", NewError("Generate Key Failed, Private Key is Empty")
	} //end if
	if(publicKey == "") {
		return "", "", NewError("Generate Key Failed, Public Key is Empty")
	} //end if
	//--
	privateKey = StrTrimWhitespaces(Base64Encode(privateKey))
	publicKey  = StrTrimWhitespaces(Base64Encode(publicKey))
	if(privateKey == "") {
		return "", "", NewError("B64 Encoding Failed, Private Key is Empty")
	} //end if
	if(publicKey == "") {
		return "", "", NewError("B64 Encoding Failed, Public Key is Empty")
	} //end if
	//--
	return publicKey, privateKey, nil
	//--
} //END FUNCTION


func Ed25519Verify(pubKeyB64 []byte, sigDataB64 []byte, dataToCheck []byte) error {
	//--
	defer PanicHandler()
	//--
	pubKeyB64 = BytTrimWhitespaces(pubKeyB64)
	if(pubKeyB64 == nil) {
		return NewError("B64 Public Key is Empty, Null")
	} //end if
	//--
	var pubKeyRaw []byte = Base64BytDecode(pubKeyB64)
	if(pubKeyRaw == nil) {
		return NewError("Public Key B64 Decode Failed, Null")
	} //end if
	//--
	sigDataB64 = BytTrimWhitespaces(sigDataB64)
	if(sigDataB64 == nil) {
		return NewError("B64 Signature is Empty, Null")
	} //end if
	//--
	var sigDataRaw []byte = Base64BytDecode(sigDataB64)
	if(sigDataRaw == nil) {
		return NewError("Signature B64 Decode Failed, Null")
	} //end if
	//--
	if(dataToCheck == nil) {
		return NewError("Message Data is Empty, Null")
	} //end if
	//--
	if(ed25519.Verify(pubKeyRaw[:], dataToCheck, sigDataRaw[:]) != true) {
		return NewError(EdDsaErrInvalidSignature)
	} //end if
	//--
	return nil // Signature Verified
	//--
} //END FUNCTION


func Ed25519Sign(privKeyB64 []byte, pubKeyB64 []byte, dataToSign []byte) (error, string) {
	//--
	defer PanicHandler()
	//--
	privKeyB64 = BytTrimWhitespaces(privKeyB64)
	if(privKeyB64 == nil) {
		return NewError("B64 Private Key is Empty, Null"), ""
	} //end if
	//--
	var privKeyRaw []byte = Base64BytDecode(privKeyB64)
	if(privKeyRaw == nil) {
		return NewError("Private Key B64 Decode Failed, Null"), ""
	} //end if
	//--
	pubKeyB64 = BytTrimWhitespaces(pubKeyB64)
	if(pubKeyB64 == nil) {
		return NewError("B64 Public Key is Empty, Null"), ""
	} //end if
	//--
	var pubKeyRaw []byte = Base64BytDecode(pubKeyB64)
	if(pubKeyRaw == nil) {
		return NewError("Public Key B64 Decode Failed, Null"), ""
	} //end if
	//--
	if(dataToSign == nil) {
		return nil, ""
	} //end if
	//--
	sigData := ed25519.Sign(privKeyRaw[:], dataToSign)
	if(sigData == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	sigData = BytTrimWhitespaces(Base64BytEncode(sigData))
	if(sigData == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	//--
	errVfy := Ed25519Verify(pubKeyB64, sigData, dataToSign)
	if(errVfy != nil) {
		return NewError("Sign Verification Failed: " + errVfy.Error()), ""
	} //end if
	//--
	return nil, string(sigData)
	//--
} //END FUNCTION


//----- edx25519


func Edx25519NewKeyPair(secretSeed []byte) (string, string, error) { // pubKey, privKey, err
	//--
	// if secret is Null will use a random secret ; if non-Null will use the secret as the seed, as in PHP
	//--
	defer PanicHandler()
	//--
	var randOrSeedReader io.Reader
	//--
	if(secretSeed == nil) { // random secret
		randOrSeedReader = cryptorand.Reader
	} else { // seeded secret
		if(len(secretSeed) != 32) {
			return "", "", NewError("Secret must be exact 32 bytes")
		} //end if
		randOrSeedReader = bytes.NewReader(secretSeed)
	} //end if
	//--
	if(randOrSeedReader == nil) {
		return "", "", NewError("IO Reader is Null")
	} //end if
	//--
	pubKey, privKey, err := edx25519.GenerateKey(randOrSeedReader)
	if(err != nil) {
		return "", "", NewError("Generate Key Failed: " + err.Error())
	} //end if
	//--
	var privateKey string = string(privKey) // plain, not password protected !
	var publicKey  string = string(pubKey)
	if(privateKey == "") {
		return "", "", NewError("Generate Key Failed, Private Key is Empty")
	} //end if
	if(publicKey == "") {
		return "", "", NewError("Generate Key Failed, Public Key is Empty")
	} //end if
	//--
	privateKey = StrTrimWhitespaces(Base64Encode(privateKey))
	publicKey  = StrTrimWhitespaces(Base64Encode(publicKey))
	if(privateKey == "") {
		return "", "", NewError("B64 Encoding Failed, Private Key is Empty")
	} //end if
	if(publicKey == "") {
		return "", "", NewError("B64 Encoding Failed, Public Key is Empty")
	} //end if
	//--
	return publicKey, privateKey, nil
	//--
} //END FUNCTION


func Edx25519Verify(pubKeyB64 []byte, sigDataB64 []byte, dataToCheck []byte) error {
	//--
	defer PanicHandler()
	//--
	pubKeyB64 = BytTrimWhitespaces(pubKeyB64)
	if(pubKeyB64 == nil) {
		return NewError("B64 Public Key is Empty, Null")
	} //end if
	//--
	var pubKeyRaw []byte = Base64BytDecode(pubKeyB64)
	if(pubKeyRaw == nil) {
		return NewError("Public Key B64 Decode Failed, Null")
	} //end if
	//--
	sigDataB64 = BytTrimWhitespaces(sigDataB64)
	if(sigDataB64 == nil) {
		return NewError("B64 Signature is Empty, Null")
	} //end if
	//--
	var sigDataRaw []byte = Base64BytDecode(sigDataB64)
	if(sigDataRaw == nil) {
		return NewError("Signature B64 Decode Failed, Null")
	} //end if
	//--
	if(dataToCheck == nil) {
		return NewError("Message Data is Empty, Null")
	} //end if
	//--
	if(edx25519.Verify(pubKeyRaw[:], dataToCheck, sigDataRaw[:]) != true) {
		return NewError(EdDsaErrInvalidSignature)
	} //end if
	//--
	return nil // Signature Verified
	//--
} //END FUNCTION


func Edx25519Sign(privKeyB64 []byte, pubKeyB64 []byte, dataToSign []byte) (error, string) {
	//--
	defer PanicHandler()
	//--
	privKeyB64 = BytTrimWhitespaces(privKeyB64)
	if(privKeyB64 == nil) {
		return NewError("B64 Private Key is Empty, Null"), ""
	} //end if
	//--
	var privKeyRaw []byte = Base64BytDecode(privKeyB64)
	if(privKeyRaw == nil) {
		return NewError("Private Key B64 Decode Failed, Null"), ""
	} //end if
	//--
	pubKeyB64 = BytTrimWhitespaces(pubKeyB64)
	if(pubKeyB64 == nil) {
		return NewError("B64 Public Key is Empty, Null"), ""
	} //end if
	//--
	var pubKeyRaw []byte = Base64BytDecode(pubKeyB64)
	if(pubKeyRaw == nil) {
		return NewError("Public Key B64 Decode Failed, Null"), ""
	} //end if
	//--
	if(dataToSign == nil) {
		return nil, ""
	} //end if
	//--
	sigData := edx25519.Sign(privKeyRaw[:], dataToSign)
	if(sigData == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	sigData = BytTrimWhitespaces(Base64BytEncode(sigData))
	if(sigData == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	//--
	errVfy := Edx25519Verify(pubKeyB64, sigData, dataToSign)
	if(errVfy != nil) {
		return NewError("Sign Verification Failed: " + errVfy.Error()), ""
	} //end if
	//--
	return nil, string(sigData)
	//--
} //END FUNCTION


//----- ed448


func Ed448NewKeyPair(secretSeed []byte) (string, string, error) { // pubKey, privKey, err
	//--
	// if secret is Null will use a random secret ; if non-Null will use the secret as the seed, as in PHP
	//--
	defer PanicHandler()
	//--
	var randOrSeedReader io.Reader
	//--
	if(secretSeed == nil) { // random secret
		randOrSeedReader = cryptorand.Reader
	} else { // seeded secret
		if(len(secretSeed) != 57) {
			return "", "", NewError("Secret must be exact 57 bytes")
		} //end if
		randOrSeedReader = bytes.NewReader(secretSeed)
	} //end if
	//--
	if(randOrSeedReader == nil) {
		return "", "", NewError("IO Reader is Null")
	} //end if
	//--
	pubKey, privKey, err := ed448.GenerateKey(randOrSeedReader)
	if(err != nil) {
		return "", "", NewError("Generate Key Failed: " + err.Error())
	} //end if
	//--
	var privateKey string = string(privKey) // plain, not password protected !
	var publicKey  string = string(pubKey)
	if(privateKey == "") {
		return "", "", NewError("Generate Key Failed, Private Key is Empty")
	} //end if
	if(publicKey == "") {
		return "", "", NewError("Generate Key Failed, Public Key is Empty")
	} //end if
	//--
	privateKey = StrTrimWhitespaces(Base64Encode(privateKey))
	publicKey  = StrTrimWhitespaces(Base64Encode(publicKey))
	if(privateKey == "") {
		return "", "", NewError("B64 Encoding Failed, Private Key is Empty")
	} //end if
	if(publicKey == "") {
		return "", "", NewError("B64 Encoding Failed, Public Key is Empty")
	} //end if
	//--
	return publicKey, privateKey, nil
	//--
} //END FUNCTION


func Ed448Verify(pubKeyB64 []byte, sigDataB64 []byte, dataToCheck []byte, collisionContext string) error {
	//--
	defer PanicHandler()
	//--
	// as standard the collisionContext is empty ; if non empty will be like a namespace separation ; max 255 characters
	//--
	if(len(collisionContext) > 255) { // sync with Ed448 ContextMaxSize
		return NewError("Collision Context can be max 255 characters")
	} //end if
	//--
	pubKeyB64 = BytTrimWhitespaces(pubKeyB64)
	if(pubKeyB64 == nil) {
		return NewError("B64 Public Key is Empty, Null")
	} //end if
	//--
	var pubKeyRaw []byte = Base64BytDecode(pubKeyB64)
	if(pubKeyRaw == nil) {
		return NewError("Public Key B64 Decode Failed, Null")
	} //end if
	//--
	sigDataB64 = BytTrimWhitespaces(sigDataB64)
	if(sigDataB64 == nil) {
		return NewError("B64 Signature is Empty, Null")
	} //end if
	//--
	var sigDataRaw []byte = Base64BytDecode(sigDataB64)
	if(sigDataRaw == nil) {
		return NewError("Signature B64 Decode Failed, Null")
	} //end if
	//--
	if(dataToCheck == nil) {
		return NewError("Message Data is Empty, Null")
	} //end if
	//--
	if(ed448.Verify(pubKeyRaw, dataToCheck, sigDataRaw[:], collisionContext) != true) {
		return NewError(EdDsaErrInvalidSignature)
	} //end if
	//--
	return nil // Signature Verified
	//--
} //END FUNCTION


func Ed448Sign(privKeyB64 []byte, pubKeyB64 []byte, dataToSign []byte, collisionContext string) (error, string) {
	//--
	defer PanicHandler()
	//--
	// as standard the collisionContext is empty ; if non empty will be like a namespace separation ; max 255 characters
	//--
	if(len(collisionContext) > 255) { // sync with Ed448 ContextMaxSize
		return NewError("Collision Context can be max 255 characters"), ""
	} //end if
	//--
	privKeyB64 = BytTrimWhitespaces(privKeyB64)
	if(privKeyB64 == nil) {
		return NewError("B64 Private Key is Empty, Null"), ""
	} //end if
	//--
	var privKeyRaw []byte = Base64BytDecode(privKeyB64)
	if(privKeyRaw == nil) {
		return NewError("Private Key B64 Decode Failed, Null"), ""
	} //end if
	//--
	pubKeyB64 = BytTrimWhitespaces(pubKeyB64)
	if(pubKeyB64 == nil) {
		return NewError("B64 Public Key is Empty, Null"), ""
	} //end if
	//--
	var pubKeyRaw []byte = Base64BytDecode(pubKeyB64)
	if(pubKeyRaw == nil) {
		return NewError("Public Key B64 Decode Failed, Null"), ""
	} //end if
	//--
	if(dataToSign == nil) {
		return nil, ""
	} //end if
	//--
	sigData := ed448.Sign(privKeyRaw, dataToSign, collisionContext)
	if(sigData == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	sigData = BytTrimWhitespaces(Base64BytEncode(sigData))
	if(sigData == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	//--
	errVfy := Ed448Verify(pubKeyB64, sigData, dataToSign, collisionContext)
	if(errVfy != nil) {
		return NewError("Sign Verification Failed: " + errVfy.Error()), ""
	} //end if
	//--
	return nil, string(sigData)
	//--
} //END FUNCTION


//----- edx448


func Edx448NewKeyPair(secretSeed []byte) (string, string, error) { // pubKey, privKey, err
	//--
	// if secret is Null will use a random secret ; if non-Null will use the secret as the seed, as in PHP
	//--
	defer PanicHandler()
	//--
	var randOrSeedReader io.Reader
	//--
	if(secretSeed == nil) { // random secret
		randOrSeedReader = cryptorand.Reader
	} else { // seeded secret
		if(len(secretSeed) != 57) {
			return "", "", NewError("Secret must be exact 57 bytes")
		} //end if
		randOrSeedReader = bytes.NewReader(secretSeed)
	} //end if
	//--
	if(randOrSeedReader == nil) {
		return "", "", NewError("IO Reader is Null")
	} //end if
	//--
	pubKey, privKey, err := edx448.GenerateKey(randOrSeedReader)
	if(err != nil) {
		return "", "", NewError("Generate Key Failed: " + err.Error())
	} //end if
	//--
	var privateKey string = string(privKey) // plain, not password protected !
	var publicKey  string = string(pubKey)
	if(privateKey == "") {
		return "", "", NewError("Generate Key Failed, Private Key is Empty")
	} //end if
	if(publicKey == "") {
		return "", "", NewError("Generate Key Failed, Public Key is Empty")
	} //end if
	//--
	privateKey = StrTrimWhitespaces(Base64Encode(privateKey))
	publicKey  = StrTrimWhitespaces(Base64Encode(publicKey))
	if(privateKey == "") {
		return "", "", NewError("B64 Encoding Failed, Private Key is Empty")
	} //end if
	if(publicKey == "") {
		return "", "", NewError("B64 Encoding Failed, Public Key is Empty")
	} //end if
	//--
	return publicKey, privateKey, nil
	//--
} //END FUNCTION


func Edx448Verify(pubKeyB64 []byte, sigDataB64 []byte, dataToCheck []byte, collisionContext string) error {
	//--
	defer PanicHandler()
	//--
	// as standard the collisionContext is empty ; if non empty will be like a namespace separation ; max 255 characters
	//--
	if(len(collisionContext) > 255) { // sync with Edx448 ContextMaxSize
		return NewError("Collision Context can be max 255 characters")
	} //end if
	//--
	pubKeyB64 = BytTrimWhitespaces(pubKeyB64)
	if(pubKeyB64 == nil) {
		return NewError("B64 Public Key is Empty, Null")
	} //end if
	//--
	var pubKeyRaw []byte = Base64BytDecode(pubKeyB64)
	if(pubKeyRaw == nil) {
		return NewError("Public Key B64 Decode Failed, Null")
	} //end if
	//--
	sigDataB64 = BytTrimWhitespaces(sigDataB64)
	if(sigDataB64 == nil) {
		return NewError("B64 Signature is Empty, Null")
	} //end if
	//--
	var sigDataRaw []byte = Base64BytDecode(sigDataB64)
	if(sigDataRaw == nil) {
		return NewError("Signature B64 Decode Failed, Null")
	} //end if
	//--
	if(dataToCheck == nil) {
		return NewError("Message Data is Empty, Null")
	} //end if
	//--
	if(edx448.Verify(pubKeyRaw, dataToCheck, sigDataRaw[:], collisionContext) != true) {
		return NewError(EdDsaErrInvalidSignature)
	} //end if
	//--
	return nil // Signature Verified
	//--
} //END FUNCTION


func Edx448Sign(privKeyB64 []byte, pubKeyB64 []byte, dataToSign []byte, collisionContext string) (error, string) {
	//--
	defer PanicHandler()
	//--
	// as standard the collisionContext is empty ; if non empty will be like a namespace separation ; max 255 characters
	//--
	if(len(collisionContext) > 255) { // sync with Edx448 ContextMaxSize
		return NewError("Collision Context can be max 255 characters"), ""
	} //end if
	//--
	privKeyB64 = BytTrimWhitespaces(privKeyB64)
	if(privKeyB64 == nil) {
		return NewError("B64 Private Key is Empty, Null"), ""
	} //end if
	//--
	var privKeyRaw []byte = Base64BytDecode(privKeyB64)
	if(privKeyRaw == nil) {
		return NewError("Private Key B64 Decode Failed, Null"), ""
	} //end if
	//--
	pubKeyB64 = BytTrimWhitespaces(pubKeyB64)
	if(pubKeyB64 == nil) {
		return NewError("B64 Public Key is Empty, Null"), ""
	} //end if
	//--
	var pubKeyRaw []byte = Base64BytDecode(pubKeyB64)
	if(pubKeyRaw == nil) {
		return NewError("Public Key B64 Decode Failed, Null"), ""
	} //end if
	//--
	if(dataToSign == nil) {
		return nil, ""
	} //end if
	//--
	sigData := edx448.Sign(privKeyRaw, dataToSign, collisionContext)
	if(sigData == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	sigData = BytTrimWhitespaces(Base64BytEncode(sigData))
	if(sigData == nil) {
		return NewError("Sign Failed, Null"), ""
	} //end if
	//--
	errVfy := Edx448Verify(pubKeyB64, sigData, dataToSign, collisionContext)
	if(errVfy != nil) {
		return NewError("Sign Verification Failed: " + errVfy.Error()), ""
	} //end if
	//--
	return nil, string(sigData)
	//--
} //END FUNCTION


//----- #


// #END
