
// GO Lang :: SmartGo / WebSocket Message Pack - Internal :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240114.2007 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websocketsrvclimsgpak

import (
	"sync"

	"log"
	"time"

	smart 			"github.com/unix-world/smartgo"
	uid 			"github.com/unix-world/smartgo/crypto/uuid"

	dhkx 			"github.com/unix-world/smartgo/crypto/dhkx"
	websocket 		"github.com/unix-world/smartgo/web-socket/websocket"
)

const (
	VERSION string = "r.20240114.2007"

	CERTIFICATES_DEFAULT_PATH string = "./ssl"
	CERTIFICATE_PEM_CRT string = "cert.crt"
	CERTIFICATE_PEM_KEY string = "cert.key"

	MAX_META_MSG_SIZE uint32 	=  1 * 1000 * 1000 	//  1 MB
	MAX_MSG_SIZE uint32 		= 16 * 1000 * 1000 	// 16 MB
	MAX_QUEUE_MESSAGES uint8 	= 100 				// must be between: 1..255

	LIMIT_INTERVAL_SECONDS_MIN uint32 = 10 			// {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
	LIMIT_INTERVAL_SECONDS_MAX uint32 = 3600 		// {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}

	DEBUG bool = false
)

//--


func MsgPakGenerateUUID() string {
	//--
	return uid.Uuid10Str() + "-" + uid.Uuid13Str() + "-" + uid.Uuid17Seq()
	//--
} //END FUNCTION


//--

type HandleMessagesFunc func(bool, string, string, string, string, string, string) (string, string)

type messagePack struct {
	Cmd        string `json:"cmd"`
	Data       string `json:"data"`
	CheckSum   string `json:"checksum"`
}

var websockWriteMutex sync.Mutex // connections allow concurrent reads but not concurrent writes, thus protect writes with a simple mutex (not with a RWMutex)

//--


func connCloseSocket(conn *websocket.Conn) {
	//--
	defer smart.PanicHandler()
	//--
	if(conn != nil) {
		conn.Close()
		conn = nil
	} //end if
	//--
} //END FUNCTION


func connWriteTxtMsgToSocket(conn *websocket.Conn, msg []byte, maxLimitSeconds uint32) error {
	//--
	defer smart.PanicHandler()
	//--
	websockWriteMutex.Lock()
	defer websockWriteMutex.Unlock()
	//--
	if(conn == nil) {
		return smart.NewError("WARNING: Cannot write TxtMsg to Empty Connection")
	} //end if
	//--
	if(maxLimitSeconds < LIMIT_INTERVAL_SECONDS_MIN) { // {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
		maxLimitSeconds = LIMIT_INTERVAL_SECONDS_MIN
	} else if(maxLimitSeconds > LIMIT_INTERVAL_SECONDS_MAX) { // {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
		maxLimitSeconds = LIMIT_INTERVAL_SECONDS_MAX
	} //end if
	//--
	conn.SetWriteDeadline(time.Now().Add(time.Duration(int(maxLimitSeconds - 1)) * time.Second))
	return conn.WriteMessage(websocket.TextMessage, msg)
	//--
} //END FUNCTION


func connReadFromSocket(conn *websocket.Conn, maxLimitSeconds uint32) (msgType int, msg []byte, err error) {
	//--
	defer smart.PanicHandler()
	//--
	if(conn == nil) {
		return -1, nil, smart.NewError("WARNING: Cannot read Msg from Empty Connection")
	} //end if
	//--
	if(maxLimitSeconds < LIMIT_INTERVAL_SECONDS_MIN) { // {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
		maxLimitSeconds = LIMIT_INTERVAL_SECONDS_MIN
	} else if(maxLimitSeconds > LIMIT_INTERVAL_SECONDS_MAX) { // {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
		maxLimitSeconds = LIMIT_INTERVAL_SECONDS_MAX
	} //end if
	//--
	conn.SetReadLimit(int64(MAX_MSG_SIZE + MAX_META_MSG_SIZE))
	conn.SetReadDeadline(time.Now().Add(time.Duration(int(maxLimitSeconds + 1)) * time.Second))
	//--
	messageType, message, rdErr := conn.ReadMessage()
	//--
	return messageType, message, rdErr
	//--
} //END FUNCTION


//--


func dhkxCliHandler(remoteId string, isServer bool, cmd string, data string) (answerMsg string, answerData string, extraData string) {
	//--
	defer smart.PanicHandler()
	//--
	if(isServer == true) {
		return "<ERR:DHKX:CLI>", "Invalid Server Command: " + cmd, ""
	} //end if
	if(cmd != "<DHKX:CLI>") {
		return "<ERR:DHKX:CLI>", "Invalid Command: " + cmd, ""
	} //end if
	//--
	var clientRecvDhKxFromServer dhkx.HandleDhkxCliRecvFunc = func() (string, []byte, int) {
		//--
		defer smart.PanicHandler()
		//--
		arr := smart.Explode(":", smart.StrTrimWhitespaces(data))
		if(len(arr) != 2) {
			return "Invalid Message Format", nil, 0
		} //end if
		//--
		var grpId int = int(smart.ParseStrAsInt64(arr[0]))
		if(!dhkx.DhKxValidateGroup(grpId)) {
			return "Invalid Message Format: Group: " + arr[0], nil, 0
		} //end if
		var srvPubKey []byte = smart.BaseDecode(arr[1], "b62")
		//--
		return "", srvPubKey, grpId
		//--
	} //END FUNCTION
	//--
	var clientSendDhKxToServer dhkx.HandleDhkxCliSendFunc = func(cliPubKey []byte, cliExch []byte) string {
		//--
		// This will be handled back by dhkxCliHandler -> msgPakHandleMessage
		//--
		return ""
		//--
	} //END FUNCTION
	//--
	errCliRecvSend1, grpCli, privCli, pubCli, recvPubSrv, shardCli, shardExch := dhkx.DhKxClientExchange(clientRecvDhKxFromServer, clientSendDhKxToServer)
	if(errCliRecvSend1 != "") {
		return "<ERR:DHKX:CLI>", errCliRecvSend1, ""
	} //end if
	if(grpCli == nil) {
		return "<ERR:DHKX:CLI>", "Client Group is NULL", ""
	} //end if
	if(privCli == nil) {
		return "<ERR:DHKX:CLI>", "Client PrivKey is NULL", ""
	} //end if
	if(pubCli == nil) {
		return "<ERR:DHKX:CLI>", "Client PubKey is NULL", ""
	} //end if
	if(recvPubSrv == nil) {
		return "<ERR:DHKX:CLI>", "Received Server PubKey is NULL", ""
	} //end if
	if(shardCli == "") {
		return "<ERR:DHKX:CLI>", "Client SharedKey is Empty", ""
	} //end if
	if(shardExch == "") {
		return "<ERR:DHKX:CLI>", "Client SharedExchange is Empty", ""
	} //end if
	//--
	if(DEBUG == true) {
		log.Println("[DEBUG] DhKx SharedSecret:", shardCli)
	} //end if
	//--
	return "<DHKX:SRV>", smart.BlowfishEncryptCBC(smart.BaseEncode(pubCli, "b58") + ":" + smart.BaseEncode([]byte(shardExch), "b62"), smart.BaseEncode(recvPubSrv, "b92")), shardCli
	//--
} //END FUNCTION


//--


func msgPakHandleMessage(conn *websocket.Conn, isServer bool, id string, remoteId string, msgHash string, maxLimitSeconds uint32, message string, sharedPrivateKey string, sharedSecret string, authUsername string, authPassword string, handleMessagesFunc HandleMessagesFunc) (okRecv bool, okRepl bool, errMsg string, extData string) {
	//--
	defer smart.PanicHandler()
	//--
	var isRecvOk bool = false
	//--
	msg, errMsg := msgPakParseMessage(message, sharedPrivateKey, sharedSecret)
	lenMessage := len(smart.StrTrimWhitespaces(message))
	message = ""
	if(errMsg != "") {
		return isRecvOk, false, errMsg, ""
	} //end if
	isRecvOk = true
	//--
	var area string = "client"
	var rarea string = "server"
	if(isServer == true) {
		area = "server"
		rarea = "client"
	} //end if
	//--
	var identRepl string = "*** MsgPak.Handler." + area
	if(DEBUG == true) {
		identRepl += "{" + id + "}"
	} //end if
	identRepl += " <- " + rarea + "[" + remoteId + "](" + msgHash + "):"
	//--
	log.Println("[INFO] " + identRepl + " Received Command `" + msg.Cmd + "` Data-Size: " + smart.ConvertIntToStr(len(msg.Data)) + " / Package-Size: " + smart.ConvertIntToStr(lenMessage) + " bytes")
	if(DEBUG == true) {
		log.Println("[DATA] " + identRepl + " Command `" + msg.Cmd + "` Data-Size:", len(msg.Data), " / Package-Size:", lenMessage, "bytes ; Data: `" + msg.Data + "`")
	} //end if else
	//--
	var answerMsg string = ""
	var answerData string = ""
	var extraData string = ""
	//--
	var shouldAnswer bool = true
	switch(msg.Cmd) {
		case "<DHKX:CLI>": // client DHKX Key Exchange
			if(isServer != true) {
				answerMsg, answerData, extraData = dhkxCliHandler(remoteId, isServer, msg.Cmd, msg.Data)
			} //end if
			break
		case "<PING>": // ping (zero)
			if(isServer != true) {
				answerMsg = "<OK:PING>"
				answerData = msg.Cmd
			} //end if
			break
		case "<PONG>": // pong (one)
			if(isServer == true) {
				answerMsg = "<OK:PONG>"
				answerData = msg.Cmd
			} //end if
			break
		case "<OK:PING>", "<OK:PONG>":
			if(DEBUG == true) {
				log.Println("[DEBUG] " + identRepl + " # Command `" + msg.Cmd + "` Confirmation for: " + remoteId)
			} //end if
			shouldAnswer = false
			break
		case "<OK>":
			log.Println("[OK] " + identRepl + " # Command `" + msg.Cmd + "` @ `" + msg.Data + "`")
			shouldAnswer = false
			break
		case "<INFO>":
			log.Println("[INFO] " + identRepl + " # Command `" + msg.Cmd + "` @ `" + msg.Data + "`")
			shouldAnswer = false
			break
		case "<ERR>":
			log.Println("[WARNING] " + identRepl + ": " + "Invalid Message ! <ERR> is reserved for internal use ...")
			shouldAnswer = false
			break
		default: // custom handler or unhandled
			if(smart.StrStartsWith(msg.Cmd, "<ERR:")) { // for commands starting with <ERR: just forward them to <INFO>
				log.Println("[WARNING] " + identRepl + ": " + msg.Cmd + " # " + msg.Data)
				shouldAnswer = false
			} else {
				/*
				handleMessagesFunc := func(isServer bool, id string, remoteId string, cmd string, data string, authUsername string, authPassword string) (bool, string, string) {
					//--
					defer smart.PanicHandler()
					//--
					var answerMsg string = ""
					var answerData string = ""
					//--
					switch(cmd) { // see below how to implement commands ...
						default: // unhandled
							answerMsg = "<ERR:UNHANDLED>" // return an error answer
							answerData = "Error description goes here"
					} //end switch
					//--
					// if both answerMsg and answerData are empty will return no answer
					// if answerMsg is empty and answerData is non-empty the answerData will be considered as an error message to display
					// if answerMsg is non-empty will reply back with answerMsg and answerData
					//--
					return answerMsg, answerData
					//--
				} //END FUNCTION
				*/
				answerMsg, answerData = handleMessagesFunc(isServer, id, remoteId, msg.Cmd, msg.Data, authUsername, authPassword)
				if(smart.StrStartsWith(answerMsg, "<ERR:")) {
					log.Println("[WARNING] " + identRepl + ": " + msg.Cmd + " # FAILED: " + answerMsg + " # " + answerData)
				} else if((answerMsg == "") && (answerData != "")) {
					log.Println("[ERROR] " + identRepl + ": " + msg.Cmd + " # FAILED: # " + answerData)
				} else if((answerMsg == "") && (answerData == "")) {
					shouldAnswer = false
				} //end if
			} //end if else
	} //end switch
	//--
	if(shouldAnswer != true) {
		if((answerMsg != "") || (answerData != "")) {
			log.Println("[WARNING] " + identRepl + ": " + msg.Cmd + " # Command is Marked as Should-Not-Answer but have a non-empty Message/Data: `" + answerMsg + "` / `" + answerData + "`")
		} //end if
		return isRecvOk, false, "", "" // there is no other message to be sent
	} //end if
	//--
	if(conn == nil) { // do not return any message in this case ...
		return isRecvOk, false, identRepl + " # Cannot Send Back Reply to `" + msg.Cmd + "` @ No connection available ...", ""
	} //end if
	wrOK, lenPakMsg, errWrMsg := msgPakWriteMessage(conn, maxLimitSeconds, answerMsg, answerData, sharedPrivateKey, sharedSecret)
	if((wrOK != true) || (errWrMsg != "")) {
		if(errWrMsg == "") {
			errWrMsg = "Unknown Error"
		} //end if
		if(DEBUG == true) {
			log.Println("[DEBUG] " + identRepl + " # Message Reply FAILED to [" + rarea + "] @ " + errWrMsg)
		} //end if
		return isRecvOk, true, errWrMsg, ""
	} //end if
	//--
	log.Println("[NOTICE] " + identRepl + " Message Reply to [" + rarea + "] # `" + answerMsg + "` ; Data-Size:", len(answerData), " / Package-Size:", lenPakMsg, "bytes")
	//--
	return isRecvOk, true, "", extraData
	//--
} //END FUNCTION


func msgPakWriteMessage(conn *websocket.Conn, maxLimitSeconds uint32, cmd string, data string, sharedPrivateKey string, sharedSecret string) (ok bool, msgSize int, errMsg string) {
	//--
	defer smart.PanicHandler()
	//--
	cmd = smart.StrTrimWhitespaces(cmd)
	if(cmd == "") {
		return false, 0, ""
	} //end if
	//--
	msg, errMsg := msgPakComposeMessage(cmd, data, sharedPrivateKey, sharedSecret)
	if(errMsg != "") {
		return false, 0, "MsgPak: Write Message Compose Error: " + errMsg
	} //end if
	if(msg == "") {
		return false, 0, ""
	} //end if
	//--
	err := connWriteTxtMsgToSocket(conn, []byte(msg), maxLimitSeconds)
	if(err != nil) {
		return false, 0, "MsgPak: Errors encountered during write message to websocket: " + err.Error()
	} //end if
	//--
	return true, len(msg), ""
	//--
} //END FUNCTION


func msgPakComposeMessage(cmd string, data string, sharedPrivateKey string, sharedSecret string) (msg string, errMsg string) {
	//--
	defer smart.PanicHandler()
	//--
	cmd = smart.StrTrimWhitespaces(cmd)
	if(cmd == "") {
		return "", "MsgPak: Command is empty"
	} //end if
	//--
	polySum, errPoly := smart.Poly1305(smart.Md5(sharedSecret + "\v" + sharedPrivateKey), sharedSecret + "\v" + cmd + "\v" + sharedPrivateKey, true)
	if(errPoly != nil) {
		return "", "MsgPak: Poly Checksum Failed: " + errPoly.Error()
	} //end if
	//--
	var dataEnc string = smart.StrTrimWhitespaces(smart.ThreefishEncryptCBC(smart.DataArchive(data), sharedPrivateKey + "\v" + smart.Sh3a512B64(cmd + "\v" + sharedSecret + "\v" + polySum), false))
	if(dataEnc == "") {
		return "", "MsgPak: Encrypt Failed: Empty Data"
	} //end if
	//--
	hMac, errHmac := smart.HashHmac("sha3-384", dataEnc + "\v" + cmd, dataEnc + "\v" + data, true)
	if(errHmac != nil) {
		return "", "MsgPak: Hmac Checksum Failed: " + errHmac.Error()
	} //end if
	//--
	var sMsg messagePack = messagePack{
		Cmd: cmd,
		Data: dataEnc,
		CheckSum: hMac,
	}
	//--
	dataEnc = smart.StrTrimWhitespaces(smart.JsonNoErrChkEncode(sMsg, false, true))
	if(dataEnc == "") {
		return "", "MsgPak: JSON Encode Failed: Empty Data"
	} //end if
	dataEnc = smart.StrTrimWhitespaces(smart.Base64sEncode(dataEnc))
	if(dataEnc == "") {
		return "", "MsgPak: B64sE Failed: Empty Data"
	} //end if
	//--
	var crrLen int = len(dataEnc)
	if(crrLen > int(MAX_MSG_SIZE)) {
		return "", "MsgPak: Package is Oversized: Max allowed is: " + smart.ConvertIntToStr(int(MAX_MSG_SIZE)) + " < Current Package is: " + smart.ConvertIntToStr(crrLen) + " bytes"
	} //end if
	//--
	return dataEnc, ""
	//--
} //END FUNCTION


func msgPakParseMessage(msg string, sharedPrivateKey string, sharedSecret string) (msgStruct messagePack, errMsg string) {
	//--
	defer smart.PanicHandler()
	//--
	var sMsg messagePack
	//--
	msg = smart.StrTrimWhitespaces(msg)
	if(msg == "") {
		return sMsg, "MsgPak: Message is empty"
	} //end if
	//--
	msg = smart.StrTrimWhitespaces(smart.Base64sDecode(msg))
	if(msg == "") {
		return sMsg, "MsgPak: Message is empty after B64sD"
	} //end if
	//--
	D, DErr := smart.JsonObjDecode(msg)
	if(DErr != nil) {
		return sMsg, "MsgPak: Message JSON Decoding Error: " + DErr.Error()
	} else if(D == nil) {
		return sMsg, "MsgPak: Message JSON Decoding Failed"
	} //end if
	//--
	sMsg = messagePack{
		Cmd: D["cmd"].(string),
		Data: D["data"].(string),
		CheckSum: D["checksum"].(string),
	}
	//--
	polySum, errPoly := smart.Poly1305(smart.Md5(sharedSecret + "\v" + sharedPrivateKey), sharedSecret + "\v" + sMsg.Cmd + "\v" + sharedPrivateKey, true)
	if(errPoly != nil) {
		sMsg = messagePack{} // reset
		return sMsg, "MsgPak: Poly Checksum Failed: " + errPoly.Error()
	} //end if
	//--
	sMsg.Data = smart.StrTrimWhitespaces(smart.ThreefishDecryptCBC(sMsg.Data, sharedPrivateKey + "\v" + smart.Sh3a512B64(sMsg.Cmd + "\v" + sharedSecret + "\v" + polySum), false))
	if(sMsg.Data == "") {
		sMsg = messagePack{} // reset
		return sMsg, "MsgPak: Decrypt Failed: empty data"
	} //end if
	sMsg.Data = smart.DataUnArchive(sMsg.Data)
	if(sMsg.Data == "") {
		sMsg = messagePack{} // reset
		return sMsg, "MsgPak: Unarchive Failed: empty data"
	} //end if
	//--
	hMac, errHmac := smart.HashHmac("sha3-384", D["data"].(string) + "\v" + sMsg.Cmd, D["data"].(string) + "\v" + sMsg.Data, true)
	if(errHmac != nil) {
		sMsg = messagePack{} // reset
		return sMsg, "MsgPak: Hmac Checksum Failed: " + errHmac.Error()
	} //end if
	//--
	if((smart.StrTrimWhitespaces(sMsg.CheckSum) == "") || (sMsg.CheckSum != hMac)) {
		sMsg = messagePack{} // reset
		return sMsg, "MsgPak: Invalid Message Checksum"
	} //end if
	//--
	return sMsg, ""
	//--
} //END FUNCTION


func msgPakGenerateMessageHash(msg []byte) string {
	//--
	return smart.Crc32b(string(msg))
	//--
} //END FUNCTION



// #END
