
// GO Lang :: SmartGo / WebSocket Message Pack - Server :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250208.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websocketsrvclimsgpak

import (
	"sync"

	"log"
	"fmt"
	"time"

	"net/http"

	smart 			"github.com/unix-world/smartgo"
	assets 			"github.com/unix-world/smartgo/web/assets/web-assets"
	srvassets 		"github.com/unix-world/smartgo/web/assets/srv-assets"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
	smartcache 		"github.com/unix-world/smartgo/data-structs/simplecache"

	dhkx 			"github.com/unix-world/smartgo/crypto/dhkx"
	websocket 		"github.com/unix-world/smartgo/web-socket/websocket"
	crontab 		"github.com/unix-world/smartgo/utils/crontab"
)

const (
	HTTP_AUTH_REALM string = "Smart.MsgPak Server"
	HTTP_GO_LANG_USER_AGENT string = "Go-http-client/1.1"

	WAIT_DHKX_LIMIT_SECONDS  uint32 = 60 // default is 60

	DEBUG_CACHE bool = false
)


type CronMsgTask struct {
	Timing string
	Cmd string
	Data string
}


func MsgPakSetServerTaskCmd(cmd string, data string, timeoutSec uint32, tlsMode string, certifPath string, httpAddr string, httpPort uint16, authUsername string, authPassword string) string {

	//--
	defer smart.PanicHandler()
	//--

	//--
	certifPath = smart.StrTrimWhitespaces(certifPath)
	if((certifPath == "") || (smart.PathIsBackwardUnsafe(certifPath) == true)) {
		certifPath = CERTIFICATES_DEFAULT_PATH
	} //end if
	certifPath = smart.PathGetAbsoluteFromRelative(certifPath)
	certifPath = smart.PathAddDirLastSlash(certifPath)
	//--

	//--
	var uri string = "http"
	var tlsInsecureSkipVerify bool = false
	var tlsServerCerts string = ""
	if(tlsMode == "tls:server") {
		uri += "s"
		uri += "://"
		crt, errCrt := smart.SafePathFileRead(certifPath + CERTIFICATE_PEM_CRT, true)
		if(errCrt != nil) {
			return "Failed to read root certificate CRT: " + errCrt.Error()
		} //end if
		key, errKey := smart.SafePathFileRead(certifPath + CERTIFICATE_PEM_KEY, true)
		if(errKey != nil) {
			return "Failed to read root certificate KEY: " + errKey.Error()
		} //end if
		tlsServerCerts = smart.StrTrimWhitespaces(string(crt)) + "\n" + smart.StrTrimWhitespaces(string(key))
	} else if(tlsMode == "tls:noverify") {
		uri += "s"
		uri += "://"
		tlsInsecureSkipVerify = true
	} else if(tlsMode == "tls") {
		uri += "s"
		uri += "://"
	} else { // insecure
		uri += "://"
	} //end if else
	//--
	uri += httpAddr
	uri += ":" + smart.ConvertUInt16ToStr(httpPort)
	uri += "/msgsend"
	//--
	var reqArr map[string][]string = map[string][]string{
		"cmd": { cmd },
		"data": { data },
	}
	//--

	//--
	httpResult := smarthttputils.HttpClientDoRequestPOST(uri, tlsServerCerts, tlsInsecureSkipVerify, nil, reqArr, timeoutSec, smarthttputils.HTTP_CLI_DEF_BODY_READ_SIZE, 0, authUsername, authPassword)
	//--
	if(httpResult.Errors != "") {
		return "SET Error # " + httpResult.Errors
	} else if(httpResult.HttpStatus != 202) {
		return "SET Failed # " + smart.ConvertIntToStr(httpResult.HttpStatus)
	} //end if
	//--

	//--
	return ""
	//--

} //END FUNCTION


func MsgPakServerRun(serverID string, useTLS bool, certifPath string, httpAddr string, httpPort uint16, allowedIPs string, authUsername string, authPassword string, sharedEncPrivKey string, intervalMsgSeconds uint32, handleMessagesFunc HandleMessagesFunc, allowedHttpCustomCmds map[string]bool, cronMsgTasks []CronMsgTask) int16 {

	//--
	defer smart.PanicHandler()
	//--

	//-- checks

	serverID = smart.StrTrimWhitespaces(serverID)
	if(serverID == "") {
		serverID = MsgPakGenerateUUID()
		log.Println("[NOTICE] MsgPak Server: No Server ID provided, assigning an UUID as ID:", serverID)
	} //end if
	if(serverID == "") {
		log.Println("[ERROR] MsgPak Server: Empty Server ID")
		return 1001
	} //end if
	if(len(serverID) > 64) {
		log.Println("[ERROR] MsgPak Server: Server ID is too long")
		return 1002
	} //end if

	certifPath = smart.StrTrimWhitespaces(certifPath)
	certifPath = smart.SafePathFixSeparator(certifPath)
	if((certifPath == "") || (smart.PathIsBackwardUnsafe(certifPath) == true)) {
		certifPath = CERTIFICATES_DEFAULT_PATH
	} //end if
	certifPath = smart.PathGetAbsoluteFromRelative(certifPath)
	certifPath = smart.PathAddDirLastSlash(certifPath)

	httpAddr = smart.StrTrimWhitespaces(httpAddr)
	if((!smart.IsNetValidIpAddr(httpAddr)) && (!smart.IsNetValidHostName(httpAddr))) {
		log.Println("[ERROR] MsgPak Server: Empty or Invalid Bind Address")
		return 1003
	} //end if
	if(smart.StrContains(httpAddr, ":")) {
		httpAddr = "[" + httpAddr + "]" // {{{SYNC-SMART-SERVER-DOMAIN-IPV6-BRACKETS}}}
	} //end if

	if(!smart.IsNetValidPortNum(int64(httpPort))) {
		log.Println("[ERROR] MsgPak Server: Empty or Invalid Bind Port")
		return 1004
	} //end if

	authUsername = smart.StrTrimWhitespaces(authUsername)
	if(authUsername == "") {
		log.Println("[ERROR] MsgPak Server: Empty Auth UserName")
		return 1005
	} //end if
	if(smart.AuthIsValidUserName(authUsername) != true) {
		log.Println("[ERROR] MsgPak Server: Invalid Auth UserName Length: must be between 5 and 25 characters")
		return 1006
	} //end if

	// do not trim authPassword !
	if(smart.StrTrimWhitespaces(authPassword) == "") {
		log.Println("[ERROR] MsgPak Server: Empty Auth Password")
		return 1007
	} //end if
	if(smart.AuthIsValidPassword(authPassword) != true) {
		log.Println("[ERROR] MsgPak Server: Invalid Auth Password Length: must be between 7 and 57 characters")
		return 1008
	} //end if

	sharedEncPrivKey = smart.StrTrimWhitespaces(sharedEncPrivKey)
	if(sharedEncPrivKey == "") {
		log.Println("[ERROR] MsgPak Server: Empty Auth Shared PrivKey")
		return 1009
	} //end if
	if(smart.AuthIsValidSecurityKey(sharedEncPrivKey) != true) {
		log.Println("[ERROR] MsgPak Server: Invalid Auth Shared PrivKey Length: must be between 16 and 256 characters")
		return 1010
	} //end if

	if(intervalMsgSeconds < LIMIT_INTERVAL_SECONDS_MIN) { // {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
		log.Println("[ERROR] MsgPak Server: Min allowed Message Interval Seconds is", LIMIT_INTERVAL_SECONDS_MIN, "seconds but is set to:", intervalMsgSeconds)
		return 1011
	} else if(intervalMsgSeconds > LIMIT_INTERVAL_SECONDS_MAX) { // {{{SYNC-MSGPAK-INTERVAL-LIMITS}}}
		log.Println("[ERROR] MsgPak Server: Max allowed Message Interval Seconds is", LIMIT_INTERVAL_SECONDS_MAX, "seconds but is set to:", intervalMsgSeconds)
		return 1012
	} //end if

	var allowedHttpCmds sync.Map
	if(allowedHttpCustomCmds != nil) {
		for ks, vs := range allowedHttpCustomCmds {
			if(vs == true) { // if true can be schedduled also via HTTP(S) tasks manager, else only by cron tasks manager ; commands containing ":" cannot be schedduled {{{SYNC-MSGPAK-SPECIAL-COMMANDS}}}
				allowedHttpCmds.Store(ks, vs)
			} //end if
		} //end for
	} //end if

	//-- #

	var srvWebSockUpgrader = websocket.Upgrader{
		ReadBufferSize:    16384,
		WriteBufferSize:   16384,
		EnableCompression: false, // this is still experimental
	} // use default options

	var dhkxSrvKeysClients sync.Map
	var connectedClients sync.Map

	var memSrvMsgCache *smartcache.InMemCache = smartcache.NewCache("smartgo.websocketsrvclimsgpak.server.messages.inMemCache", time.Duration(int(intervalMsgSeconds + 1)) * time.Second, DEBUG_CACHE)

	var srvCustomMsgs map[string][]string = map[string][]string{}
	var mtxSrvCustomMsgs sync.RWMutex // use a RWMutex instead of Mutex ... currently uses no RLock/RUnlock but ... just in case ...

	const defaultMessageCmd = "<PING>"
	var defaultMessageDat = "PING, from the Server: [" + serverID + "]"

	//--

	setNewTask := func(theMsgCmd string, theMsgData string, theArea string) (err string) { // commands containing ":" cannot be schedduled {{{SYNC-MSGPAK-SPECIAL-COMMANDS}}}
		//--
		defer smart.PanicHandler()
		//--
		err = "" // initialize
		//--
		theMsgCmd = smart.StrTrimWhitespaces(smart.StrTrim(smart.StrTrimWhitespaces(theMsgCmd), "<>")) // min 1 char ; max 255 chars ; must contain only a-z A-Z 0-9 - . :
		theMsgData = smart.StrTrimWhitespaces(theMsgData)
		//--
		if((len(theMsgCmd) < 1) || (len(theMsgCmd) > 255) || (theMsgCmd == "") || (!smart.StrRegexMatch(`^[a-zA-Z0-9\-\.\:]+$`, theMsgCmd))) { // {{{SYNC-MSGPAK-CMD-CHECKS-FORMAT}}}
			err = "Failed to Register new Task Command # Format is Invalid `" + theMsgCmd + "`"
			log.Println("[WARNING] !!!!!!! " + err)
			return
		} //end if
		if(smart.StrContains(theMsgCmd, ":")) { // indirect commands are dissalowed ... (must not contain `:`) // {{{SYNC-MSGPAK-CMD-CHECKS-SPECIALS}}}
			err = "Failed to Register new Task Command # Disallowed `" + theMsgCmd + "`"
			log.Println("[WARNING] !!!!!!! " + err)
			return
		} //end if
		//--
		var lenMsgData int = len(theMsgData)
		if(lenMsgData > int(MAX_MSG_SIZE)) {
			err = "Failed to Register new Task Command # Data is Oversized: " + smart.ConvertIntToStr(lenMsgData) + " bytes"
			log.Println("[WARNING] !!!!!!! " + err)
			return
		} //end if
		//--
		theMsgCmd = smart.StrToUpper(theMsgCmd)
		//--
		_, cmdExst := allowedHttpCmds.Load(theMsgCmd)
		if(!cmdExst) {
			err = "Failed to Register new Task Command # Disallowed `" + theMsgCmd + "`"
			log.Println("[WARNING] !!!!!!! " + err)
			return
		} //end if
		//--
		theMsgCmd = "<" + theMsgCmd + ">"
		//--
		var numConnCli int = 0
		//--
		var errConnCli int = 0
		connectedClients.Range(func(kk, vv interface{}) bool {
			//--
			numConnCli++
			//--
			k := string(fmt.Sprint(kk)) // convert from type interface to string
			if(DEBUG == true) {
				log.Println("[DEBUG] Task Command: Connected Client found # UUID:", k)
			} //end if
			//--
			mtxSrvCustomMsgs.Lock()
			//--
			if(len(srvCustomMsgs[k]) <= int(MAX_QUEUE_MESSAGES)) { // hardcoded
				srvCustomMsgs[k] = append(srvCustomMsgs[k], smart.Base64Encode(theMsgCmd) + "|" + smart.Base64Encode(theMsgData) + "|" + smart.Base64Encode(smart.DateNowIsoUtc()))
				if(DEBUG == true) {
					log.Println("[DEBUG] +++++++ Register Task Command for Client: `" + k + "` in Queue: `" + theMsgCmd + "`")
				} //end if
			} else {
				errConnCli++
				log.Println("[WARNING] !!!!!!! Failed to Register new Task Command for Client: `" + k + "` # Queue is full: `" + theMsgCmd + "`")
			} //end if else
			//--
			mtxSrvCustomMsgs.Unlock()
			//--
			return true
			//--
		})
		if(errConnCli > 0) {
			err = "Failed to Register new Task Command for " + smart.ConvertIntToStr(errConnCli) + " Clients # `" + theMsgCmd + "`"
			return
		} //end if
		//--
		log.Println("[OK] New Task Command was Set by {" + theArea + "} for", numConnCli, "connected client(s): `" + theMsgCmd + "` ; Data-Length:", lenMsgData, "bytes")
		return ""
		//--
	} //END FUNCTION

	//--

	if((cronMsgTasks != nil) && (len(cronMsgTasks) > 0)) { // commands containing ":" cannot be schedduled {{{SYNC-MSGPAK-SPECIAL-COMMANDS}}}
		ctab := crontab.New()
		for t:=0; t<len(cronMsgTasks); t++ {
			log.Println("[INFO] MsgPak Server :: Registering Self-Cron Job Tasks: `" + cronMsgTasks[t].Timing + "` # <" + cronMsgTasks[t].Cmd + "> @ [", len(cronMsgTasks[t].Data), "bytes ]")
			cronJoberr := ctab.AddJob(cronMsgTasks[t].Timing, func(idx int){
				log.Println("[NOTICE] ······· ······· MsgPak Server :: A New Client Task will be set via Self-Cron Job #" + smart.ConvertIntToStr(idx) + " (" + cronMsgTasks[idx].Timing + ") ······· <" + cronMsgTasks[idx].Cmd + ">")
				setNewTask(cronMsgTasks[idx].Cmd, cronMsgTasks[idx].Data, "Self-Cron Job #" + smart.ConvertIntToStr(idx))
			}, t)
			if(cronJoberr != nil) {
				log.Println("[ERROR] MsgPak Server :: Failed to Register a Task as Self-Cron Job #" + smart.ConvertIntToStr(t) + " :", cronJoberr)
				return 2001
			} //end if
		} //end for
	} //end if

	//--

	srvBroadcastMsg := func(conn *websocket.Conn, rAddr string) {
		//--
		defer smart.PanicHandler()
		//--
		var oneCustomMsg []string = []string{}
		var sendCustomMsgToThisClient bool = false
		var theCacheMsgHash string = ""
		//--
		var crrMessageCmd string = ""
		var crrMessageDat string = ""
		//--
		for {
			//--
			if(conn == nil) {
				break
			} //end if
			//--
			oneCustomMsg = []string{} // init
			theCacheMsgHash = "" // init
			sendCustomMsgToThisClient = false // init
			//--
			//===
			//--
			mtxSrvCustomMsgs.Lock() // use just one lock for read and writes
			//--
			log.Println("[DEBUG] ≡≡≡≡≡≡≡ Task Commands Queue Length # Client(s):", len(srvCustomMsgs), "≡≡≡≡≡≡≡")
			if(DEBUG == true) {
				log.Println("[DATA] Message Queue:", srvCustomMsgs)
			} //end if
			//--
			if((srvCustomMsgs[rAddr] != nil) && (len(srvCustomMsgs[rAddr]) > 0)) { // if there are custom (task) messages in the queue, get first
				theCacheMsgHash = smart.Sha512B64(smart.StrTrimWhitespaces(srvCustomMsgs[rAddr][0]))
				oneCustomMsg = smart.ExplodeWithLimit("|", smart.StrTrimWhitespaces(srvCustomMsgs[rAddr][0]), 3) // cmd | data | dtime
				if(len(srvCustomMsgs[rAddr]) > 1) {
					var tmpList []string = srvCustomMsgs[rAddr][1:] // remove 1st element from list after read (key:0)
					srvCustomMsgs[rAddr] = tmpList
					tmpList = nil
				} else {
					srvCustomMsgs[rAddr] = []string{} // there was only one element, reset !
				} //end if else
				if(DEBUG == true) {
					log.Println("[DEBUG] srvBroadcastMsg: Found a Queued Task Command for Client `" + rAddr + "` ; Hash: `" + theCacheMsgHash + "`")
				} //end if
				if(len(oneCustomMsg) == 3) {
					sendCustomMsgToThisClient = true
				} //end if
			} //end if
			//--
			if(srvCustomMsgs[rAddr] != nil) {
				if(len(srvCustomMsgs[rAddr]) <= 0) {
					delete(srvCustomMsgs, rAddr)
					if(DEBUG == true) {
						log.Println("[DEBUG] srvBroadcastMsg: ------- Unregister Client: `" + rAddr + "` from Queue (cleanup, empty list) ...")
					} //end if
				} //end if
			} //end if
			//--
			mtxSrvCustomMsgs.Unlock()
			//--
			//===
			//--
			if(sendCustomMsgToThisClient == true) {
				//--
				if(DEBUG == true) {
					log.Println("[DEBUG] srvBroadcastMsg: Check in Cache for the specific Task Command for Client `" + rAddr + "` ; Hash: `" + theCacheMsgHash + "`")
				} //end if
				cacheExists, cachedObj, _ := memSrvMsgCache.Get(rAddr + "|" + theCacheMsgHash) // {{{SYNC-MSGPAK-CACHE-KEY}}}
				if(DEBUG_CACHE == true) {
					log.Println("[DATA] srvBroadcastMsg: Cached Info for the specific Task Command for Client `" + rAddr + "` ; Hash: `" + theCacheMsgHash + "` ; In-Cache:", cacheExists, "; Object:", cachedObj)
				} //end if
				//--
				if(cacheExists != true) { // send
					cachedObj.Id = rAddr + "|" + theCacheMsgHash // {{{SYNC-MSGPAK-CACHE-KEY}}}
					cachedObj.Data = smart.DateNowIsoUtc()
					memSrvMsgCache.Set(cachedObj, int64(intervalMsgSeconds * 10)) // support up to 7 ( + 3 free loops) queued messages {{{SYNC-MAX-QUEUED-MSGPAK}}}
					if(DEBUG == true) {
						log.Println("[DEBUG] srvBroadcastMsg: Task Command Cached now (send) for Client `" + rAddr + "` ; Hash: `" + theCacheMsgHash + "`")
					} //end if
				} else { // skip
					sendCustomMsgToThisClient = false
					if(DEBUG == true) {
						log.Println("[DEBUG] srvBroadcastMsg: Task Command already Cached (skip) for Client `" + rAddr + "` ; Hash: `" + theCacheMsgHash + "`")
					} //end if
				} //end if
				//--
			} else {
				//--
				if(theCacheMsgHash != "") {
					log.Println("[ERROR] srvBroadcastMsg: Invalid Task Command for Client `" + rAddr + "` ; Hash: `" + theCacheMsgHash + "`")
				} //end if
				//--
			} //end if
			//--
			if(sendCustomMsgToThisClient == true) {
				crrMessageCmd = smart.Base64Decode(oneCustomMsg[0])
				crrMessageDat = smart.Base64Decode(oneCustomMsg[1])
			} else {
				crrMessageCmd = defaultMessageCmd
				crrMessageDat = defaultMessageDat
			} //end if else
			//--
			sendCustomMsgToThisClient = false // reset
			theCacheMsgHash = "" // reset
			oneCustomMsg = []string{} // reset
			//--
			log.Println("[NOTICE] @@@ Broadcasting " + crrMessageCmd + " Message to Client{" + rAddr + "}, Data-Size:", len(crrMessageDat), "bytes")
			//--
			cliShardIntf, cliShardExst := dhkxSrvKeysClients.Load(rAddr)
			var cliShardStr string = ""
			if(cliShardExst) {
				cliShardStr = string(fmt.Sprint(cliShardIntf)) // convert from type interface to string
			} //end if
			if(smart.StrTrimWhitespaces(cliShardStr) == "") {
				log.Println("[WARNING] @@@ Broadcasting # Client{" + rAddr + "} Shared Key is Empty")
				break
			} //end if
			//--
			msg, errMsg := msgPakComposeMessage(crrMessageCmd, crrMessageDat, sharedEncPrivKey, cliShardStr)
			//--
			if(errMsg != "") {
				//--
				log.Println("[ERROR] @@@ Broadcasting # Send Message to Client{" + rAddr + "}:", errMsg)
				break
				//--
			} else {
				//--
				errWrs := connWriteTxtMsgToSocket(conn, []byte(msg), intervalMsgSeconds)
				//--
				if(errWrs != nil) {
					//--
					log.Println("[ERROR] @@@ Broadcasting # Send Message to Client{" + rAddr + "} / Writing to websocket Failed:", errWrs)
					break
					//--
				} else {
					//--
					log.Println("[OK] @@@ Broadcasting # Send Message completed to Client{" + rAddr + "}")
					//--
				} //end if else
				//--
			} //end if else
			//--
			time.Sleep(time.Duration(intervalMsgSeconds) * time.Second)
			//--
		} //end for
		//--
		return
		//--
	} //end function

	//--

	srvHandlerMsgPack := func(w http.ResponseWriter, r *http.Request) {
		//-- safety
		defer smart.PanicHandler() // for: socket upgrade
		//-- check auth
		authErr, authData := smarthttputils.HttpAuthCheck(w, r, HTTP_AUTH_REALM, authUsername, authPassword, "", allowedIPs, nil, false) // outputs: TEXT
		if(authErr != nil) {
			log.Println("[WARNING] MessagePak Server / MsgPak Channel Area :: Authentication Failed:", authErr)
			return
		} //end if
		if((authData.OK != true) || (authData.UserName == "")) {
			log.Println("[WARNING] MessagePak Server / MsgPak Channel Area :: Authentication is Invalid")
			if(DEBUG == true) {
				log.Println("[DEBUG] AuthData:", authData, r.UserAgent())
			} //end if
			return
		} //end if
		if(authData.Method != 1) { // Basic Auth Only
			log.Println("[WARNING] MessagePak Server / Task Commands Area :: Authentication should be Basic [ 1 ] and it is: [", authData.Method, "]")
			return
		} //end if
		//-- upgrade the raw HTTP connection to a websocket based one ; below method must check credentials
		srvWebSockUpgrader.CheckOrigin = func(r *http.Request) bool {
		//	if(authData.Realm != HTTP_AUTH_REALM) {
			var ua string = smart.StrToLower(smart.StrTrimWhitespaces(r.UserAgent()))
			if((ua == "") || (ua != smart.StrToLower(HTTP_GO_LANG_USER_AGENT))) {
				return false
			} //end if
			return true
		} // this is for ths js client connected from another origin ...
		//--
		conn, err := srvWebSockUpgrader.Upgrade(w, r, nil)
		//--
		connectedClients.Store(r.RemoteAddr, conn)
		defer func() {
			defer smart.PanicHandler() // for: connection close
			connectedClients.Delete(r.RemoteAddr)
			connCloseSocket(conn)
		}()
		//--
		if(err != nil) {
			log.Println("[ERROR] Connection Upgrade Failed:", err)
			return
		} //end if
		//--
		log.Println("New Pre-Connection (DhKx Exchange) <-> <-> <-> to:", conn.LocalAddr(), "From:", r.RemoteAddr)
		time.Sleep(time.Duration(2) * time.Second)
		//--
		var serverSendDhKxToClient dhkx.HandleDhkxSrvSendFunc = func(srvPubKey []byte, grpID int) string {
			//--
			defer smart.PanicHandler()
			//--
			msg, errCompose := msgPakComposeMessage("<DHKX:CLI>", smart.ConvertIntToStr(grpID) + ":" + smart.BaseEncode(srvPubKey, "b62"), sharedEncPrivKey, "")
			if(errCompose != "") {
				return "Send (to Client) ERR (1): " + errCompose
			} //end if
			err := connWriteTxtMsgToSocket(conn, []byte(msg), WAIT_DHKX_LIMIT_SECONDS)
			if(err != nil) {
				return "Send (to Client) ERR (2): " + err.Error()
			} //end if
			return ""
			//--
		} //end function
		var groupID int = dhkx.DhKxGetRandomGroup(true) // high only
		errSrvStep1, grpSrv, privSrv, _ := dhkx.DhKxServerInitExchange(groupID, serverSendDhKxToClient)
		if(errSrvStep1 != "") {
			log.Println("[ERROR]: DhKx #1 " + errSrvStep1)
			return
		} //end if
		var serverRecvDhKxFromClient dhkx.HandleDhkxSrvRecvFunc = func(srvPubKey []byte) (string, []byte, []byte) {
			//--
			defer smart.PanicHandler()
			//--
			msgType, message, err := connReadFromSocket(conn, WAIT_DHKX_LIMIT_SECONDS)
			if(err != nil) {
				return "Recv (from Client) ERR: " + err.Error(), nil, nil
			} //end if
			if(msgType != websocket.TextMessage) {
				return "Recv (from Client) ERR: Not a Text Message", nil, nil
			} //end if
			//--
			msg, errMsg := msgPakParseMessage(string(message), sharedEncPrivKey, "")
			if(errMsg != "") {
				return "Recv (from Client) ERR: Invalid Message: " + errMsg, nil, nil
			} //end if
			if(smart.StrStartsWith(msg.Cmd, "<ERR:DHKX:")) {
				return "Recv (from Client) ERR: Message Cmd Failed: `" + msg.Cmd + "` # " + msg.Data, nil, nil
			} //end if
			if(msg.Cmd != "<DHKX:SRV>") {
				return "Recv (from Client) ERR: Invalid Message Cmd: `" + msg.Cmd + "`", nil, nil
			} //end if
			decdata := smart.StrTrimWhitespaces(smart.BlowfishDecryptCBC(msg.Data, smart.BaseEncode(srvPubKey, "b92")))
			if(decdata == "") {
				return "Recv (from Client) ERR: Invalid Message Data Encryption", nil, nil
			} //end if
			data := smart.Explode(":", decdata)
			if(len(data) != 2) {
				return "Recv (from Client) ERR: Invalid Message Data Structure", nil, nil
			} //end if
			var cliPubKey []byte = smart.BaseDecode(data[0], "b58")
			var cliExch []byte = smart.BaseDecode(data[1], "b62")
			//--
			return "", cliPubKey, cliExch
			//--
		} //END FUNCTION
		errSrvRecv1GenShardStep2, recvPubCli, shardSrv := dhkx.DhKxServerFinalizeExchange(grpSrv, privSrv, serverRecvDhKxFromClient)
		if(errSrvRecv1GenShardStep2 != "") {
			log.Println("[ERROR]: DhKx #2 " + errSrvRecv1GenShardStep2)
			return
		} //end if
		if(recvPubCli == nil) {
			log.Println("[ERROR]: DhKx #2 CliPubKey is NULL")
			return
		} //end if
		shardSrv = smart.StrTrimWhitespaces(shardSrv)
		if(shardSrv == "") {
			log.Println("[ERROR]: DhKx #2 SharedSecret is EMPTY")
			return
		} //end if
		if(smart.StrTrimWhitespaces(smart.Base64Decode(shardSrv)) == "") {
			log.Println("[ERROR]: DhKx #2 SharedSecret is INVALID")
			return
		} //end if
		if(DEBUG == true) {
			log.Println("[DEBUG] DhKx SharedSecret:", shardSrv)
		} //end if
		dhkxSrvKeysClients.Store(r.RemoteAddr, shardSrv)
		defer func() {
			dhkxSrvKeysClients.Delete(r.RemoteAddr)
		}()
		log.Println("[OK] <-> <-> <-> DhKx Exchange Completed:", conn.LocalAddr(), "<->", r.RemoteAddr, "/ Key-Length:", len(shardSrv), "bytes")
		time.Sleep(time.Duration(2) * time.Second)
		//--
		log.Println("New Connection to:", conn.LocalAddr(), "From:", r.RemoteAddr)
		//-- The event loop
		go srvBroadcastMsg(conn, r.RemoteAddr)
		var msgHash string = ""
		for {
			//--
			messageType, message, err := connReadFromSocket(conn, intervalMsgSeconds)
			if(err != nil) {
				log.Println("[ERROR] Message Reading Failed (interval", intervalMsgSeconds, "sec.):", err)
				break
			} //end if
			//--
			if(DEBUG == true) {
				log.Println("[DEBUG] Server: [", conn.LocalAddr(), "] # Got New Message from Client: {" + r.RemoteAddr + "} # Type:", messageType)
			} //end if
			//--
			if(messageType == websocket.TextMessage) {
				//--
				msgHash = msgPakGenerateMessageHash(message) // {{{SYNC-MSGPAK-MSGHASH}}}
				//--
				log.Println("[NOTICE] Message Received from Client{" + r.RemoteAddr + "} # Message-Hash: " + msgHash + " ; Package Size:", len(message), "bytes")
				//--
				cliShardIntf, cliShardExst := dhkxSrvKeysClients.Load(r.RemoteAddr)
				var cliShardStr string = ""
				if(cliShardExst) {
					cliShardStr = string(fmt.Sprint(cliShardIntf)) // convert from type interface to string
				} //end if
				if(smart.StrTrimWhitespaces(cliShardStr) == "") {
					log.Println("[WARNING] Client Shared Key is Empty")
					break
				} //end if
				mRecvOk, mRepl, errMsg, _ := msgPakHandleMessage(conn, true, serverID, r.RemoteAddr, msgHash, intervalMsgSeconds, string(message), sharedEncPrivKey, cliShardStr, authUsername, authPassword, handleMessagesFunc)
				message = nil
				if(mRecvOk != true) {
					log.Println("[ERROR] Invalid Message received from Client{" + r.RemoteAddr + "} # Message-Hash: " + msgHash + " ; Details: " + errMsg)
				} else { // recv ok
					log.Println("[OK] Valid Message received from Client{" + r.RemoteAddr + "} # Message-Hash: " + msgHash)
					if(errMsg != "") {
						log.Println("[ERROR] Failed to Reply back to Message from Client{" + r.RemoteAddr + "} # Message-Hash: " + msgHash + " ; Details: " + errMsg)
					} else {
						if(mRepl == true) {
							log.Println("[OK] Reply back to Message from Client{" + r.RemoteAddr + "} # Message-Hash: " + msgHash)
						} //end if else
					} //end if else
				} //end if else
				//--
				msgHash = ""
				//--
			} else {
				//--
				log.Println("[ERROR]: TextMessage is expected from Client{" + r.RemoteAddr + "}")
				//--
			} //end if else
			//--
		} //end for
		//--
		return
		//--
	} //end function

	srvHandlerCustomMsg := func(w http.ResponseWriter, r *http.Request) {
		//--
		if(allowedHttpCustomCmds == nil) {
			smarthttputils.HttpStatus503(w, r, "This service area is NOT Active", true)
			return
		} //end if
		//--
		authErr, authData := smarthttputils.HttpAuthCheck(w, r, HTTP_AUTH_REALM, authUsername, authPassword, "", allowedIPs, nil, true) // outputs: HTML
		if(authErr != nil) {
			log.Println("[WARNING] MessagePak Server / Task Commands Area :: Authentication Failed:", authErr)
			return
		} //end if
		if((authData.OK != true) || (authData.UserName == "")) {
			log.Println("[WARNING] MessagePak Server / Task Commands Area :: Authentication is Invalid")
			if(DEBUG == true) {
				log.Println("[DEBUG] AuthData:", authData)
			} //end if
			return
		} //end if
		if(authData.Method != 1) { // Basic Auth Only
			log.Println("[WARNING] MessagePak Server / Task Commands Area :: Authentication should be Basic [ 1 ] and it is: [", authData.Method, "]")
			return
		} //end if
		//--
		var isRequestOk bool = true
		//--
		if(r.Method == http.MethodGet) { // GET
			var paramMode string = smart.StrTrimWhitespaces(r.URL.Query().Get("mode"))
			var paramCmd  string = smart.StrTrimWhitespaces(r.URL.Query().Get("cmd"))
			var paramData string = smart.StrTrimWhitespaces(r.URL.Query().Get("data"))
			if((paramMode == "display") && (paramCmd != "")) { // display form
				smarthttputils.HttpStatus200(w, r, srvassets.HtmlServerTemplate("Server: Task Command Status: Set", "", `<h1>Server: Task Command Status: Set &nbsp; <i class="sfi sfi-tab sfi-3x"></i></h1>` + `<div class="operation_success" title="Command">` + smart.EscapeHtml("<" + paramCmd + ">") + `</div>` + "\n" + `<div class="operation_display icon" title="Data">` + "\n" + `<textarea class="ux-field" style="width:700px; height:250px;" readonly>` + smart.EscapeHtml(paramData) + `</textarea>` + "\n" + `</div>` + "\n" + `<a href="msgsend" class="ux-button ux-button-primary">New Task Command</a>`, false), "index.html", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, nil) // skip js
				return
			} else if(paramCmd == "") { // new form
				smarthttputils.HttpStatus200(w, r, srvassets.HtmlServerTemplate("Server: New Task Command", "", `<h1>Server: New Task Command &nbsp; <i class="sfi sfi-command sfi-3x"></i></h1>` + `<form id="new-task-form" name="new-task-form" method="post" action="#" class="ux-form" onSubmit="return false;"><input type="hidden" name="mode" value="json">` + "\n" + `<div class="operation_result">` + `<input type="text" name="cmd" class="ux-field" placeholder="Cmd" title="Cmd" maxlength="255" style="width:700px;">` + `</div>` + "\n" + `<div class="operation_important">` + `<textarea name="data" class="ux-field" placeholder="Data" title="Data" maxlength="16000000" style="width:700px; height:250px;"></textarea>` + `</div>` + "\n" + `<button type="submit" disabled style="display:none;" aria-hidden="true" data-hint="Prevent Form Submit on Enter"></button>` + "\n" + `<button type="button" class="ux-button ux-button-special" onClick="smartJ$Browser.SubmitFormByAjax('new-task-form', 'msgsend', 'yes'); return false;"><i class="sfi sfi-new-tab"></i>&nbsp;&nbsp; Submit Task Command</button>` + "\n" + `</form>`, true), "index.html", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, nil) // load js
				return
			} //end if
		} else if(r.Method == http.MethodPost) { // POST
			r.ParseForm()
			r.ParseMultipartForm(int64(smarthttputils.HTTP_CLI_MAX_POST_DATA_SIZE))
		} else {
			isRequestOk = false
		} //end if else
		//--
		var customcmd string  = ""
		var customdata string = ""
		var askJson bool      = false
		if(isRequestOk == true) {
			customcmd  = r.FormValue("cmd")
			customdata = r.FormValue("data")
			askJson    = (r.FormValue("mode") == "json")
		} //end if
		if(DEBUG == true) {
			log.Println("[DEBUG] RequestVars:", "cmd", customcmd, ";", "data", customdata, "askJson", askJson)
		} //end if
		//--
		if(isRequestOk == true) {
			customcmd = smart.StrToUpper(smart.StrTrimWhitespaces(smart.StrTrim(smart.StrTrimWhitespaces(customcmd), "<>")))
			if(customcmd == "") {
				isRequestOk = false
			} //end if
		} //end if
		//--
		var errSetTask string = ""
		//--
		if(isRequestOk == true) {
			errSetTask = setNewTask(customcmd, customdata, "HTTP(S) Task Command (" + r.RemoteAddr + ")")
			if(errSetTask != "") {
				isRequestOk = false
			} //end if
		} //end if
		//--
		if(isRequestOk != true) {
			if(errSetTask == "") {
				errSetTask = "Command is Empty, Invalid Or Disallowed"
			} //end if
			if(askJson) {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(200) // status code must be after content type
				w.Write([]byte(srvassets.JsonAjaxFormReply("ERROR", "", "Server: Task Command was NOT Set", "Invalid Request # Required Variables:\n[ `cmd` : string, `data` : string ]" + "\n\n" + "ERR: " + errSetTask, false, "", "", "", "", false)))
			} else {
				smarthttputils.HttpStatus400(w, r, "Invalid Request # Required Variables: [ `cmd` : string, `data` : string ]" + "\n" + "ERR: " + errSetTask, true)
			} //end if else
			return
		} //end if
		//--
		log.Println("[NOTICE] °°°°°°° °°°°°°° A New Task was set via HTTP(S) Task Command °°°°°°° by `" + authUsername + "` from IP Address [`" + r.RemoteAddr + "`] :: `<" + customcmd + ">`")
		//--
		if(askJson) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(200) // status code must be after content type
			w.Write([]byte(srvassets.JsonAjaxFormReply("OK", "", "Server: Task Command was Set", "Command: " + "<" + customcmd + ">" + "\n" + "Data Length: " + smart.ConvertIntToStr(len(customdata)) + " bytes", false, "", "msgsend?mode=display&cmd=" + smart.EscapeUrl(customcmd) + "&data=" + smart.EscapeUrl(smart.TextCutByLimit(customdata, 255)), "", "", false)))
		} else {
			smarthttputils.HttpStatus202(w, r, srvassets.HtmlServerTemplate("Server: Task Command was Set", "", `<h1>Server: Task Command was Set &nbsp; <i class="sfi sfi-loop sfi-3x"></i></h1>` + `<div class="operation_success" title="Command">` + smart.EscapeHtml("<" + customcmd + ">") + `</div>` + "\n" + `<div class="operation_display icon" title="Data">` + "\n" + `<textarea class="ux-field" style="width:700px; height:250px;" readonly>` + smart.EscapeHtml(customdata) + `</textarea>` + "\n" + `</div>` + "\n" + `<a href="msgsend" class="ux-button ux-button-info">New Task Command</a>`, false), "index.html", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, nil) // skip js
		} //end if else
		//--
	} //end function

	srvHandlerHome := func(w http.ResponseWriter, r *http.Request) {
		//--
		if(r.URL.Path != "/") {
			smarthttputils.HttpStatus404(w, r, "MsgPack Server: Resource Not Found: `" + r.URL.Path + "`", true)
			return
		} //end if
		//--
		headers := map[string]string{"refresh":"10"}
		smarthttputils.HttpStatus200(w, r, assets.HtmlStandaloneTemplate("MsgPak Server: HTTP(S)/WsMux", "", `<div class="operation_display">MsgPak Server: HTTP(S)/WsMux # ` + smart.EscapeHtml(VERSION) + `</div>` + `<div class="operation_info"><img width="48" height="48" src="/lib/framework/img/loading-spin.svg"></div>` + `<hr>` + `<small>` + smart.EscapeHtml(smart.COPYRIGHT) + `</small>`, false), "index.html", "", -1, "", smarthttputils.CACHE_CONTROL_NOCACHE, headers) // skip js
		//--
	} //end function

	webAssetsHttpHandler := func(w http.ResponseWriter, r *http.Request) {
		//--
		srvassets.WebAssetsHttpHandler(w, r, "cache:private") // private cache mode
		//--
	} //end function

	var srvAddr string = httpAddr + fmt.Sprintf(":%d", httpPort)
	mux, srv := smarthttputils.HttpMuxServer(srvAddr, intervalMsgSeconds, true, true, "[MsgPak Server]") // force HTTP/1 ; allow large headers, the purpose of this service is different than public web ...

	mux.HandleFunc("/msgpak", srvHandlerMsgPack)
	mux.HandleFunc("/msgsend", srvHandlerCustomMsg)
	mux.HandleFunc("/lib/", webAssetsHttpHandler)
	mux.HandleFunc("/", srvHandlerHome)

	//--

	if(useTLS == true) {
		log.Println("Starting MsgPak Server:", "wss://" + srvAddr + "/msgpak", "@", "HTTPS/WsMux/TLS", "#", VERSION)
		log.Println("[NOTICE] MsgPak Server Certificates Path:", certifPath)
	//	errServeTls := http.ListenAndServeTLS(srvAddr, certifPath + CERTIFICATE_PEM_CRT, certifPath + CERTIFICATE_PEM_KEY, nil)
		errServeTls := srv.ListenAndServeTLS(certifPath + CERTIFICATE_PEM_CRT, certifPath + CERTIFICATE_PEM_KEY)
		if(errServeTls != nil) {
			log.Println("[ERROR]", "MsgPak Server HTTPS/TLS: Fatal Service Init Error:", errServeTls)
			return 3001
		} //end if
	} else {
		log.Println("Starting MsgPak Server:", "ws://" + srvAddr + "/msgpak", "@", "HTTP/WsMux/Insecure", "#", VERSION)
	//	errServe := http.ListenAndServe(srvAddr, nil)
		errServe := srv.ListenAndServe()
		if(errServe != nil) {
			log.Println("[ERROR]", "MsgPak Server: Fatal Service Init Error:", errServe)
			return 3002
		} //end if
	} //end if else

	//--

	return 0

} //END FUNCTION


// #END
