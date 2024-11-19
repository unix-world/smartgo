
// (c) 2021-2024 unix-world.org
// r.20241105.2358

//=======
// This is an implementation of Diffie-Hellman Key Exchange algorithm for a Client/Server suite, based on: github.com/monnand/dhkx
// The algorithm is used to establish a shared key between two communication peers without sharing secret information.
// TYPICAL PROCESS:
// First, Server and Client should agree on which group to use.
// If you are not sure, choose group 14. GetGroup() will return the desired group by a given id.
// GetGroup(0) will return a default group, which is usually safe enough to use this group.
// It is totally safe to share the group's information.
//=======
// Sequence (shard key or priv key are never exchanged ; client will send at the final a test crypto 3Fish which can be decrypted by server only if the shared key of the server matches, otherwise server will return an error ...):
// 1. DhKxServerInitExchange
// 2. DhKxClientExchange
// 3. DhKxServerFinalizeExchange
//=======

// REQUIRE: go 1.16 or later
package dhkx

import (
	smart "github.com/unix-world/smartgo"
)

const (
	VERSION = "r.20241105.2358"
)


type HandleDhkxSrvSendFunc func([]byte, int) (string) 				// (srvPubKey []byte, grpID int) : (err string) 		# Server Send to Client
type HandleDhkxSrvRecvFunc func([]byte) (string, []byte, []byte) 	// () : (err string, cliPubKey []byte, cliExch []byte) 	# Server Recv from Client

type HandleDhkxCliSendFunc func([]byte, []byte) (string) 			// (cliPubKey []byte, cliExch []byte) : (err string) 	# Client Send to Server
type HandleDhkxCliRecvFunc func() (string, []byte, int) 			// () : (err string, srvPubKey []byte, grpId, int) 		# Client Recv from Server


func DhKxGetRandomGroup(highOnly bool) int {
	//--
	var randGrp uint64 = smart.NanoTimeRandInt63N(0, 15) // balance one bit more to the 14 ...
	var grpID int = 0
	switch(randGrp) {
		case 14:
			if(highOnly == true) {
				grpID = 18
			} else {
				grpID = 101
			} //end if else
			break
		case 13:
			if(highOnly == true) {
				grpID = 17
			} else {
				grpID = 102
			}
			break
		case 12:
			if(highOnly == true) {
				grpID = 16
			} else {
				grpID = 103
			}
			break
		case 11:
			if(highOnly == true) {
				grpID = 15
			} else {
				grpID = 104
			}
			break
		case 10:
			if(highOnly == true) {
				grpID = 5
			} else {
				grpID = 105
			}
			break
		case 9:
			if(highOnly == true) {
				grpID = 2
			} else {
				grpID = 106
			}
			break
		case 8:
			if(highOnly == true) {
				grpID = 1
			} else {
				grpID = 107
			}
			break
		case 7:
			grpID = 18
			break
		case 6:
			grpID = 17
			break
		case 5:
			grpID = 16
			break
		case 4:
			grpID = 15
			break
		case 3:
			grpID = 5
			break
		case 2:
			grpID = 2
			break
		case 1:
			grpID = 1
			break
		case 0:  fallthrough
		case 15: fallthrough
		default:
			grpID = 14
	} //end switch
	//--
	return grpID
	//--
} //END FUNCTION


func DhKxValidateGroup(grpID int) bool {
	//-- validate group
	switch(grpID) {
		case 1, 2, 14: // originals
			return true
		case 5, 15, 16, 17, 18: // extra high (unixman)
			return true
		case 101, 102, 103, 104, 105, 106, 107: // extra low (unixman)
			return true
		default:
			// invalid
	} //end switch
	//--
	return false
	//--
} //END FUNCTION


func dhKxStep1(grpID int) (string, *DHGroup, *DHKey, []byte) {

	//-- validate group
	if(DhKxValidateGroup(grpID) != true) {
		return "Invalid Group ID: " + smart.ConvertIntToStr(grpID), nil, nil, nil
	} //end if
	//--

	//-- Get a group. Use the default one would be enough.
	g := GetGroup(grpID)
	//--

	//-- Generate a private key from the group. Use the default random number generator.
	priv, errGen := g.GeneratePrivateKey(nil)
	if(errGen != nil) {
		return "Failed to Generate Private Key: " + errGen.Error(), nil, nil, nil
	} //end if
	if(priv == nil) {
		return "Private Key is NULL", nil, nil, nil
	} //end if
	if(!priv.IsPrivateKey()) {
		return "Private Key is wrong", nil, nil, nil
	} //end if
	//--

	//-- Get the public key from the private key.
	pub := priv.Bytes()
	//--

	//--
	return "", &g, priv, pub
	//--

} //END FUNCTION


func dhKxStep2(g *DHGroup, priv *DHKey, otherSidePub []byte) (string, []byte, []byte) {

	//-- recover others's side public key
	otherSidePubKey := NewPublicKey(otherSidePub)
	//log.Println("[DEBUG] Other Side Pub Key is:", keyAlgoEncode(otherSidePubKey.Bytes()))
	//--

	//-- Compute the key
	k, err := g.ComputeKey(otherSidePubKey, priv)
	if(err != nil) {
		return "Failed to Compute Key: " + err.Error(), nil, nil
	} //end if

	//-- Get the key in the form of []byte
	key := k.Bytes()
	//--

	//-- Get the public key from the private key.
	pub := priv.Bytes()
	//--

	//--
	return "", key, pub
	//--

} //END FUNCTION


func DhKxServerInitExchange(grpID int, handleDhkxSrvSendFunc HandleDhkxSrvSendFunc) (e string, g *DHGroup, priv *DHKey, pub []byte) { // STEP1

	defer smart.PanicHandler()

	if(DhKxValidateGroup(grpID) != true) {
		return "ERR: Invalid Group: " + smart.ConvertIntToStr(grpID), nil, nil, nil
	} //end if

	errSrvStep1, grpSrv, privSrv, pubSrv := dhKxStep1(grpID)
	if(errSrvStep1 != "") {
		return "ERR dhKxStep1: " + errSrvStep1, nil, nil, nil
	} //end if
	if(grpSrv == nil) {
		return "ERR dhKxStep1: Group is NULL", nil, nil, nil
	} //end if
	if(privSrv == nil) {
		return "ERR dhKxStep1: PrivKey is NULL", nil, nil, nil
	} //end if
	if(pubSrv == nil) {
		return "ERR dhKxStep1: PubKey is NULL", nil, nil, nil
	} //end if

	errSendSrvSend := handleDhkxSrvSendFunc(pubSrv, grpID)
	if(errSendSrvSend != "") {
		return "ERR Send to Client: " + errSendSrvSend, grpSrv, privSrv, pubSrv
	} //end if

	return "", grpSrv, privSrv, pubSrv

} //END FUNCTION


func DhKxServerFinalizeExchange(g *DHGroup, priv *DHKey, handleDhkxSrvRecvFunc HandleDhkxSrvRecvFunc) (e string, pubCli []byte, shardSec string) { // STEP3

	defer smart.PanicHandler()

	//-- Get the public key from the private key.
	pub := priv.Bytes()
	//--

	errRecvCli, pubKeyClient, shardExchCli := handleDhkxSrvRecvFunc(pub)
	if(errRecvCli != "") {
		return "ERR Finalize Exchange: " + errRecvCli, nil, ""
	} //end if
	if(pubKeyClient == nil) {
		return "ERR Finalize Exchange: Client PubKey is NULL", nil, ""
	} //end if
	if(shardExchCli == nil) {
		return "ERR Finalize Exchange: Client ShardExch is NULL", pubKeyClient, ""
	} //end if

	errSrvStep2, sharedSecret, pubSrv := dhKxStep2(g, priv, pubKeyClient)
	if(errSrvStep2 != "") {
		return "ERR dhKxStep2: " + errSrvStep2, pubKeyClient, ""
	} //end if
	if(sharedSecret == nil) {
		return "ERR dhKxStep2: Shared Secret is NULL", pubKeyClient, ""
	} //end if
	if(string(pub) != string(pubSrv)) {
		return "ERR dhKxStep2: Server Public Key Mismatch:", pubKeyClient, ""
	} //end if

	var chkSrvPubKey string = smart.ThreefishDecryptCBC(string(shardExchCli), smart.Sha384B64(string(sharedSecret)), false)
	chkSrvPubKey = smart.Base64Decode(chkSrvPubKey)
	if(smart.StrTrimWhitespaces(chkSrvPubKey) == "") {
		return "ERR Finalize Exchange: Shared Exchange is Empty or Invalid", pubKeyClient, ""
	} //end if
	if(smart.Crc32b(string(chkSrvPubKey)) != smart.Crc32b(string(pubSrv))) {
		return "ERR Finalize Exchange: Shared Exchange Checksum Compare Failed", pubKeyClient, ""
	} //end if
	if(smart.Sha512(string(chkSrvPubKey)) != smart.Sha512(string(pubSrv))) {
		return "ERR Finalize Exchange: Shared Exchange Hash Compare Failed", pubKeyClient, ""
	} //end if
	if(string(chkSrvPubKey) != string(pubSrv)) {
		return "ERR Finalize Exchange: Shared Exchange Data Compare Failed", pubKeyClient, ""
	} //end if

	return "", pubKeyClient, smart.Base64Encode(string(sharedSecret))

} //END FUNCTION


func DhKxClientExchange(handleDhkxCliRecvFunc HandleDhkxCliRecvFunc, handleDhkxCliSendFunc HandleDhkxCliSendFunc) (e string, g *DHGroup, priv *DHKey, pub []byte, pubSrv []byte, shardSec string, shardExc string) { // STEP2

	defer smart.PanicHandler()

	errRecvSrv, pubKeyServer, grpID := handleDhkxCliRecvFunc()
	if(errRecvSrv != "") {
		return "ERR Recv from Server: " + errRecvSrv, nil, nil, nil, nil, "", ""
	} //end if
	if(DhKxValidateGroup(grpID) != true) {
		return "ERR Recv from Server: Invalid Group: " + smart.ConvertIntToStr(grpID), nil, nil, nil, nil, "", ""
	} //end if
	if(pubKeyServer == nil) {
		return "ERR Recv from Server: PubKey is NULL", nil, nil, nil, nil, "", ""
	} //end if

	errCliStep1, grpCli, privCli, pubCli := dhKxStep1(grpID)
	if(errCliStep1 != "") {
		return "ERR dhKxStep1: " + errCliStep1, nil, nil, nil, pubKeyServer, "", ""
	} //end if
	if(grpCli == nil) {
		return "ERR dhKxStep1: Group is NULL", nil, nil, nil, pubKeyServer, "", ""
	} //end if
	if(privCli == nil) {
		return "ERR dhKxStep1: PrivKey is NULL", nil, nil, nil, pubKeyServer, "", ""
	} //end if
	if(pubCli == nil) {
		return "ERR dhKxStep1: PubKey is NULL", nil, nil, nil, pubKeyServer, "", ""
	} //end if

	errCliStep2, shardCli, _ := dhKxStep2(grpCli, privCli, pubKeyServer)
	if(errCliStep2 != "") {
		return "ERR dhKxStep2: " + errCliStep2, grpCli, privCli, pubCli, pubKeyServer, "", ""
	} //end if
	if(shardCli == nil) {
		return "ERR dhKxStep2: Shared Secret is NULL", grpCli, privCli, pubCli, pubKeyServer, "", ""
	} //end if

	var shardExch string = smart.ThreefishEncryptCBC(smart.Base64Encode(string(pubKeyServer)), smart.Sha384B64(string(shardCli)), false)
	errSendCliSend := handleDhkxCliSendFunc(pubCli, []byte(shardExch))
	if(errSendCliSend != "") {
		return "ERR Send to Server: " + errSendCliSend, grpCli, privCli, pubCli, pubKeyServer, "", ""
	} //end if

	return "", grpCli, privCli, pubCli, pubKeyServer, smart.Base64Encode(string(shardCli)), shardExch

} //END FUNCTION


// #END
