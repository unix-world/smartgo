
// GO Lang :: SmartGo / WebSocket Message Pack - Client :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241216.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websocketsrvclimsgpak

import (
	"os"
	"os/signal"
	"sync"

	"log"
	"fmt"
	"time"

	fifolist 		"container/list"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"

	websocket 		"github.com/unix-world/smartgo/web-socket/websocket"
)

const (
	WAIT_CLOSE_LIMIT_SECONDS  uint32 	=  2 		// default is 2
	HANDSHAKE_TIMEOUT_SECONDS uint32 	= 45 		// default is 45

	MAX_NUM_ERR_MSG_RECV uint8 			=  8 		// default is 8 ; after this number of reecive errors, reset connection and force re-connect ; Implemented just for Client ; TODO: implement also for Server
)


var cliCustomMsgs *fifolist.List = fifolist.New()
var mtxCliCustomMsgs sync.Mutex


func connWriteCloseMsgToSocket(conn *websocket.Conn, msg []byte) error {
	//--
	defer smart.PanicHandler()
	//--
	websockWriteMutex.Lock()
	defer websockWriteMutex.Unlock()
	//--
	if(conn == nil) {
		return smart.NewError("WARNING: Cannot write CloseMsg to Empty Connection")
	} //end if
	//--
	conn.SetWriteDeadline(time.Now().Add(time.Duration(WAIT_CLOSE_LIMIT_SECONDS) * time.Second))
	return conn.WriteMessage(websocket.CloseMessage, msg)
	//--
} //END FUNCTION


func MsgPakSetClientTaskCmd(cmd string, data string) string {
	//--
	defer smart.PanicHandler()
	//--
	cmd = smart.StrTrimWhitespaces(smart.StrTrim(smart.StrTrimWhitespaces(cmd), "<>"))
	data = smart.StrTrimWhitespaces(data)
	//--
	if((len(cmd) < 1) || (len(cmd) > 255) || (cmd == "") || (!smart.StrRegexMatch(`^[a-zA-Z0-9\-\.\:]+$`, cmd))) { // {{{SYNC-MSGPAK-CMD-CHECKS-FORMAT}}}
		return "Format is Invalid `" + cmd + "`"
	} //end if
//	if(smart.StrContains(cmd, ":")) { // indirect commands are dissalowed ... (must not contain `:`) // {{{SYNC-MSGPAK-CMD-CHECKS-SPECIALS}}}
//		return "Disallowed `" + theMsgCmd + "`" // on client side, this must be allowed
//	} //end if
	//--
	var lenData int = len(data)
	if(lenData > int(MAX_MSG_SIZE)) {
		return "Data is Oversized: " + smart.ConvertIntToStr(lenData) + " bytes"
	} //end if
	//--
	cmd = "<" + smart.StrToUpper(cmd) + ">"
	//--
	mtxCliCustomMsgs.Lock()
	if(cliCustomMsgs.Len() <= int(MAX_QUEUE_MESSAGES)) {
		cliCustomMsgs.PushBack(smart.Base64Encode(cmd) + "|" + smart.Base64Encode(data) + "|" + smart.Base64Encode(smart.DateNowIsoUtc())) // add at the end
	} else {
		log.Println("[WARNING] !!!!!!! Failed to Register new Task Command # Queue is full: `" + cmd + "`")
	} //end if else
	mtxCliCustomMsgs.Unlock()
	//--
	return ""
	//--
} //END FUNCTION


func MsgPakClientRun(clientID string, serverPool []string, tlsMode string, certifPath string, authUsername string, authPassword string, sharedEncPrivKey string, intervalMsgSeconds uint32, handleMessagesFunc HandleMessagesFunc) int16 {

	//--
	defer smart.PanicHandler()
	//--

	//--

	if(serverPool == nil) {
		serverPool = []string{}
	} //end if

	clientID = smart.StrTrimWhitespaces(clientID)
	if(clientID == "") {
		clientID = MsgPakGenerateUUID()
		log.Println("[NOTICE] MsgPak Server: No Client ID provided, assigning an UUID as ID:", clientID)
	} //end if
	if(clientID == "") {
		log.Println("[ERROR] MsgPak Client: Empty Client ID")
		return 1001
	} //end if
	if(len(clientID) > 64) {
		log.Println("[ERROR] MsgPak Client: Client ID is too long")
		return 1002
	} //end if

	certifPath = smart.StrTrimWhitespaces(certifPath)
	certifPath = smart.SafePathFixSeparator(certifPath)
	if((certifPath == "") || (smart.PathIsBackwardUnsafe(certifPath) == true)) {
		certifPath = CERTIFICATES_DEFAULT_PATH
	} //end if
	certifPath = smart.PathGetAbsoluteFromRelative(certifPath)
	certifPath = smart.PathAddDirLastSlash(certifPath)

	authUsername = smart.StrTrimWhitespaces(authUsername)
	if(authUsername == "") {
		log.Println("[ERROR] MsgPak Client: Empty Auth UserName")
		return 1003
	} //end if
	if(smart.AuthIsValidUserName(authUsername) != true) {
		log.Println("[ERROR] MsgPak Client: Invalid Auth UserName Length: must be between 5 and 25 characters")
		return 1004
	} //end if

	// do not trim authPassword !
	if(smart.StrTrimWhitespaces(authPassword) == "") {
		log.Println("[ERROR] MsgPak Client: Empty Auth Password")
		return 1005
	} //end if
	if(smart.AuthIsValidPassword(authPassword) != true) {
		log.Println("[ERROR] MsgPak Client: Invalid Auth Password Length: must be between 7 and 57 characters")
		return 1006
	} //end if

	sharedEncPrivKey = smart.StrTrimWhitespaces(sharedEncPrivKey)
	if(sharedEncPrivKey == "") {
		log.Println("[ERROR] MsgPak Client: Empty Auth Shared PrivKey")
		return 1007
	} //end if
	if(smart.AuthIsValidPrivKey(sharedEncPrivKey) != true) {
		log.Println("[ERROR] MsgPak Client: Invalid Auth Shared PrivKey Length: must be between 16 and 256 characters")
		return 1008
	} //end if

	if(intervalMsgSeconds < LIMIT_INTERVAL_SECONDS_MIN) { // {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
		log.Println("[ERROR] MsgPak Client: Min allowed Message Interval Seconds is", LIMIT_INTERVAL_SECONDS_MIN, "seconds but is set to:", intervalMsgSeconds)
		return 1009
	} else if(intervalMsgSeconds > LIMIT_INTERVAL_SECONDS_MAX) { // {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
		log.Println("[ERROR] MsgPak Client: Max allowed Message Interval Seconds is", LIMIT_INTERVAL_SECONDS_MAX, "seconds but is set to:", intervalMsgSeconds)
		return 1010
	} //end if

	//--

	var done chan interface{}
	var interrupt chan os.Signal

	var connectedServers sync.Map
	var dhkxCliKeysServers sync.Map

	var errHandlerReceive uint8 = 0

	receiveHandler := func(conn *websocket.Conn, theServerAddr string) {
		//--
		defer smart.PanicHandler()
		//--
		if(conn == nil) {
			log.Println("[ERROR] receiveHandler Failed:", "No Connection ...")
			// DO NOT INCREMENT errHandlerReceive here ; it is not a RECV Error, it is NO_CONNECTION and is handled by the WATCHDOG
			return
		} //end if
		//--
		defer close(done)
		//--
		var msgHash string = ""
		var firstMessageCompleted bool = false
		for {
			//--
			messageType, message, err := connReadFromSocket(conn, intervalMsgSeconds)
			if(err != nil) {
				log.Println("[ERROR] Message Receive Failed (interval", intervalMsgSeconds, "sec.):", err)
				errHandlerReceive++
				return
			} //end if
			//--
			if(DEBUG == true) {
				log.Println("[DEBUG] Client # Got New Message from Server:{", theServerAddr + "} # Type:", messageType)
			} //end if
			//--
			if(messageType == websocket.TextMessage) {
				//--
				msgHash = msgPakGenerateMessageHash(message) // {{{SYNC-MSGPAK-MSGHASH}}}
				//--
				log.Println("[NOTICE] Message Received from Server{" + theServerAddr + "} # Message-Hash: " + msgHash + " ; Package Size:", len(message), "bytes")
				//--
				srvShardIntf, srvShardExst := dhkxCliKeysServers.Load(theServerAddr)
				var srvShardStr string = ""
				if(srvShardExst) {
					srvShardStr = string(fmt.Sprint(srvShardIntf)) // convert from type interface to string
				} //end if
				if(firstMessageCompleted == true) {
					if(smart.StrTrimWhitespaces(srvShardStr) == "") {
						log.Println("[WARNING] Server{" + theServerAddr + "} Shared Key is Empty ...")
						errHandlerReceive++
						return
					} //end if
				} //end if
				//--
				mRecvOk, mRepl, errMsg, cliShared := msgPakHandleMessage(conn, false, clientID, theServerAddr, msgHash, intervalMsgSeconds, string(message), sharedEncPrivKey, srvShardStr, authUsername, authPassword, handleMessagesFunc)
				if(firstMessageCompleted != true) {
					if(cliShared != "") {
						dhkxCliKeysServers.Store(theServerAddr, cliShared)
						log.Println("[OK] <-> <-> <-> DhKx Exchange Completed:", clientID, "<->", theServerAddr, "/ Key-Length:", len(cliShared), "bytes")
					} //end if
				} //end if
				message = nil
				if(mRecvOk != true) {
					log.Println("[ERROR] Invalid Message received from Server{" + theServerAddr + "} # Message-Hash: " + msgHash + " ; Details: " + errMsg)
				} else { // recv ok
					log.Println("[OK] Valid Message received from Server{" + theServerAddr + "} # Message-Hash: " + msgHash)
					if(errMsg != "") {
						log.Println("[ERROR] Failed to Reply back to Message from Server{" + theServerAddr + "} # Message-Hash: " + msgHash + " ; Details: " + errMsg)
					} else {
						if(mRepl == true) {
							log.Println("[OK] Reply back to Message from Server{" + theServerAddr + "} # Message-Hash: " + msgHash)
						} //end if else
					} //end if else
				} //end if else
				//--
				msgHash = ""
				//--
			} else {
				//--
				log.Println("[ERROR]: TextMessage is expected from Server{" + theServerAddr + "}")
				//--
			} //end if
			//--
			if(firstMessageCompleted != true) {
				firstMessageCompleted = true
			} //end if
			//--
		} //end for
		//--
	} //end function

	connectToServer := func(addr string) {
		//--
		defer smart.PanicHandler()
		//--
		dhkxCliKeysServers.Delete(addr)
		log.Println("[NOTICE] Connecting to Server:", addr, "MODE:", tlsMode)
		//--
		addr = smart.StrTrimWhitespaces(addr)
		if(addr == "") {
			log.Println("[ERROR] Empty Server Address:", addr)
			return
		} //end if
		arrAddr := smart.Explode(":", addr)
		if(len(arrAddr) != 2) {
			log.Println("[ERROR] Invalid Server Address:", addr)
			return
		} //end if
		var httpAddr string = smart.StrTrimWhitespaces(arrAddr[0])
		var httpPort int64 = smart.ParseStrAsInt64(smart.StrTrimWhitespaces(arrAddr[1]))
		if((!smart.IsNetValidIpAddr(httpAddr)) && (!smart.IsNetValidHostName(httpAddr))) {
			log.Println("[ERROR] Invalid Server Address (Host):", addr)
			return
		} //end if
		if(!smart.IsNetValidPortNum(httpPort)) {
			log.Println("[ERROR] Invalid Server Address (Port):", addr)
			return
		} //end if
		//--
		if((tlsMode == "tls") || (tlsMode == "tls:noverify")) {
			log.Println("[NOTICE] Certificates Path:", certifPath)
		} //end if
		//--
		socketPrefix := "ws://"
		socketSuffix := "/msgpak"
		tlsCfgCli := smarthttputils.TlsConfigClient(false, "")
		var theWebSocket websocket.Dialer
		if(tlsMode == "tls:server") {
			socketPrefix = "wss://"
			crt, errCrt := smart.SafePathFileRead(certifPath + CERTIFICATE_PEM_CRT, true)
			if(errCrt != nil) {
				log.Fatal("[ERROR] Failed to read root certificate CRT: " + errCrt.Error())
			} //end if
			key, errKey := smart.SafePathFileRead(certifPath + CERTIFICATE_PEM_KEY, true)
			if(errKey != nil) {
				log.Fatal("[ERROR] Failed to read root certificate KEY: " + errKey.Error())
			} //end if
			log.Println("Initializing Client:", socketPrefix + addr + socketSuffix, "@", "HTTPS/WsMux/TLS:WithServerCertificate")
			log.Println("[NOTICE] Server Certificates Path:", certifPath)
			tlsCfgCli = smarthttputils.TlsConfigClient(false, smart.StrTrimWhitespaces(string(crt)) + "\n" + smart.StrTrimWhitespaces(string(key)))
			theWebSocket = websocket.Dialer{
				HandshakeTimeout: time.Duration(HANDSHAKE_TIMEOUT_SECONDS) * time.Second,
				TLSClientConfig: &tlsCfgCli,
			}
		} else if(tlsMode == "tls:noverify") {
			socketPrefix = "wss://"
			log.Println("Initializing Client:", socketPrefix + addr + socketSuffix, "@", "HTTPS/WsMux/TLS:InsecureSkipVerify")
			tlsCfgCli = smarthttputils.TlsConfigClient(true, "")
			theWebSocket = websocket.Dialer{
				HandshakeTimeout: time.Duration(HANDSHAKE_TIMEOUT_SECONDS) * time.Second,
				TLSClientConfig: &tlsCfgCli,
			}
		} else if(tlsMode == "tls") {
			socketPrefix = "wss://"
			log.Println("Initializing Client:", socketPrefix + addr + socketSuffix, "@", "HTTPS/WsMux/TLS")
			tlsCfgCli = smarthttputils.TlsConfigClient(false, "")
			theWebSocket = websocket.Dialer{
				HandshakeTimeout: time.Duration(HANDSHAKE_TIMEOUT_SECONDS) * time.Second,
				TLSClientConfig: &tlsCfgCli,
			}
		} else { // insecure
			log.Println("Initializing Client:", socketPrefix + addr + socketSuffix, "@", "HTTP/WsMux/Insecure")
			theWebSocket = websocket.Dialer{
				HandshakeTimeout: time.Duration(HANDSHAKE_TIMEOUT_SECONDS) * time.Second,
			}
		} //end if else
		h := smarthttputils.HttpClientAuthBasicHeader(authUsername, authPassword)
	//	h = nil
		//--
		conn, response, err := theWebSocket.Dial(socketPrefix + addr + socketSuffix, h)
	//	conn, response, err := websocket.DefaultDialer.Dial(socketPrefix + addr + socketSuffix, h)
		//--
		connectedServers.Store(addr, conn)
		defer func() {
			dhkxCliKeysServers.Delete(addr)
			connectedServers.Delete(addr)
			connCloseSocket(conn)
		}()
		//--
		if(err != nil) {
			var rStatusCode int = 0
			if(response != nil) {
				rStatusCode = response.StatusCode
			} //end if
			log.Println("[ERROR] Cannot connect to Websocket Server: HTTP Response StatusCode:", rStatusCode, "; Dial Errors:", err)
			return
		} //end if
		//--
		go receiveHandler(conn, addr)
		//-- the main loop for the client
		var firstMessageCompleted bool = false
		const defCliCmd  string = "<PONG>"
		var defCliData string = "PONG, from Client: `" + clientID + "`"
		var crrCliCmd  string = ""
		var crrCliData string = ""
		for {
			//--
			if(errHandlerReceive >= MAX_NUM_ERR_MSG_RECV) {
				log.Println("[INFO] Reset Connection to Server, Too many Message RECV Errors:", errHandlerReceive, "of Max Limit:", MAX_NUM_ERR_MSG_RECV)
				errHandlerReceive = 0 // reset !
				return // stop after any error from receive handler in order to force re-connect
			} //end if
			//--
			srvShardIntf, srvShardExst := dhkxCliKeysServers.Load(addr)
			var srvShardStr string = ""
			if(srvShardExst) {
				srvShardStr = string(fmt.Sprint(srvShardIntf)) // convert from type interface to string
			} //end if
			//--
			select {
				case <-time.After(time.Duration(intervalMsgSeconds) * time.Second):
					//--
					if(smart.StrTrimWhitespaces(srvShardStr) == "") {
						//--
						if(firstMessageCompleted == true) {
							log.Println("[WARNING] SKIP: Sending Message to Server{" + addr + "}, Server Shared Key is Empty ...")
						} //end if
						//--
					} else {
						//--
						mtxCliCustomMsgs.Lock()
						//--
						log.Println("[DEBUG] ≡≡≡≡≡≡≡ Task Commands Queue Length:", cliCustomMsgs.Len(), "≡≡≡≡≡≡≡")
						if(cliCustomMsgs.Len() > 0) {
							tmpMsg := cliCustomMsgs.Front() // get 1st element
							tmpValMsg := string(fmt.Sprint(tmpMsg.Value)) // convert from type interface to string
							tmpArrMsg := smart.ExplodeWithLimit("|", smart.StrTrimWhitespaces(tmpValMsg), 3) // cmd | data | dtime
							if(len(tmpArrMsg) == 3) {
								crrCliCmd = smart.Base64Decode(tmpArrMsg[0])
								crrCliData = smart.Base64Decode(tmpArrMsg[1])
							} else {
								log.Println("[ERROR] Malformed Custom Registered Task Command")
								crrCliCmd = defCliCmd
								crrCliData = defCliData
							} //end if else
							cliCustomMsgs.Remove(tmpMsg)
						} else {
							crrCliCmd = defCliCmd
							crrCliData = defCliData
						} //end if else
						//--
						mtxCliCustomMsgs.Unlock()
						//--
						log.Println("[NOTICE] @@@ Sending `" + crrCliCmd + "` Message to Server {" + addr + "}")
						msg, errMsg := msgPakComposeMessage(crrCliCmd, crrCliData, sharedEncPrivKey, srvShardStr)
						if(errMsg != "") {
							log.Println("[ERROR]:", errMsg)
							return
						} else {
							err := connWriteTxtMsgToSocket(conn, []byte(msg), intervalMsgSeconds)
							if(err != nil) {
								log.Println("[ERROR] Writing to websocket Failed:", err)
								return
							} //end if
						} //end if else
						//--
						msg = ""
						errMsg = ""
						//--
					} //end if else
					//--
					if(firstMessageCompleted != true) {
						firstMessageCompleted = true
					} //end if
					//--
				case <-interrupt: // received a SIGINT (Ctrl + C). Terminate gracefully...
					//--
					log.Println("[NOTICE] Received SIGINT interrupt signal. Closing all pending connections")
					err := connWriteCloseMsgToSocket(conn, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")) // close websocket connection
					if(err != nil) {
						log.Println("[ERROR] Writing the Close Message to websocket Failed:", err)
					} //end if
					//-- possible fix
				//	return
					// fix: if crashes comment below and uncomment the return above
					select {
						case <-done:
							log.Println("[NOTICE] Receiver Channel Closed...")
						case <-time.After(time.Duration(1) * time.Second):
							log.Println("[WARNING] Timeout in closing receiving channel...")
					} //end select
					//--
					return
					//-- #end fix
			} //end select
			//--
		} //end for
		//--
	} //end function

	connectWatchdog := func() {
		//--
		log.Println("Starting WS Client", "#", VERSION)
		//--
		var initConn bool = false
		//--
		for {
			//--
			log.Println("======= Connection WATCHDOG ======= is up and running for Client{" + clientID + "} ...")
			if(DEBUG == true) {
				log.Println("[DEBUG] Connected Servers:", connectedServers)
			} //end if
			//--
			for _, p := range serverPool {
				if _, exist := connectedServers.Load(p); exist {
					log.Println("[INFO] Client Connection appears REGISTERED with Server:", p)
				} else {
					if(initConn == true) {
						log.Println("[WARNING] Client is NOT Connected to Server:", p)
					} //end if
					go connectToServer(p)
				} //end if else
			} //end for
			//--
			initConn = true
			//--
			time.Sleep(time.Duration(int(intervalMsgSeconds + WAIT_CLOSE_LIMIT_SECONDS + WAIT_CLOSE_LIMIT_SECONDS)) * time.Second)
			//--
		} //end for
		//--
	} //end function

	done = make(chan interface{}) // Channel to indicate that the receiveHandler is done
	interrupt = make(chan os.Signal) // Channel to listen for interrupt signal to terminate gracefully
	signal.Notify(interrupt, os.Interrupt) // Notify the interrupt channel for SIGINT

	connectWatchdog()

	return 0

} //END FUNCTION


// #END
