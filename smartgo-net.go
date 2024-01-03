
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240103.1301 :: STABLE
// [ NET ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"strings"

	"net"
	"net/http"
)

const (
	REGEX_SMART_SAFE_NET_HOSTNAME  string 	= `^[_a-z0-9\-\.]+$` 				// SAFETY: SUPPORT ONLY THESE CHARACTERS IN NET HOST NAMES AS RFC ; if a hostname have upper characters must be converted to all lower characters ; if a hostname have unicode characters must be converted using punnycode ...
	REGEX_SMART_SAFE_HTTP_HEADER_KEY string = `^[A-Za-z0-9\-]+$` 				// SAFETY: SUPPORT ONLY THESE CHARACTERS IN HEADER KEY VALUES

	DEFAULT_FAKE_IP_CLIENT string = "0.0.0.0"
)

var (
	ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP string = "" 							// CASE SENSITIVE, CAMEL CASE (in golang !) ; by default is empty (no proxy) ; if a proxy is used it can be set as: "X-Forwarded-Client-Ip" or "X-Real-Ip" or "X-Forwarded-For" or ... but only once before using any methods that is referencing this ; changing more than once would not be safe and can lead to many security flaws
)

//-----


func SetSafeRealClientIpHeaderKey(hdrKey string) bool {
	//--
//	hdrKey = StrToUpper(StrTrimWhitespaces(hdrKey))
	hdrKey = StrTrimWhitespaces(hdrKey) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}} ; fix: any request header key goes into go http server will be converted into case-sensitive keys. The canonicalization converts the first letter and any letter following a hyphen to upper case; the rest are converted to lowercase. For example, the canonical key for "accept-encoding" is "Accept-Encoding"
	//--
	if(hdrKey == "") {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Set Real Client IP Proxy Header Key Failed, empty")
		return false
	} //end if
	if(!StrRegexMatchString(REGEX_SMART_SAFE_HTTP_HEADER_KEY, hdrKey)) {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Set Real Client IP Proxy Header Key Failed, invalid:", hdrKey)
		return false
	} //end if
	if(ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP != "") {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Set Real Client IP Proxy Header Key Failed, already set as:", ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP)
		return false
	} //end if
	//--
	ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP = http.CanonicalHeaderKey(hdrKey) // fix camelcase
	//--
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo Http Real Client IP Proxy Header Key Set to `" + ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP + "`: Success")
	//--
	return true
	//--
} //END FUNCTION


func GetSafeRealClientIpHeaderKey() string {
	//--
	return StrTrimWhitespaces(ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
	//--
} //END FUNCTION


func GetHttpRealClientIpFromRequestHeaders(r *http.Request) (isOk bool, clientRealIp string, rawVal string, headerKey string) {
	//--
	// This is intended to look at the Request Proxy Headers such as: X-FORWARDED-CLIENT-IP, X-REAL-IP, X-FORWARDED-FOR
	//--
	var ip string = ""
	var ipList string = ""
	//--
	var hdrKey string = StrTrimWhitespaces(ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
	if(hdrKey == "") {
		//--
		ip, _ = GetHttpRemoteAddrIpAndPortFromRequest(r)
		ipList = ip
		hdrKey = "[REMOTE_ADDR]" // this is a special value, not in the headers, with underscore
		//--
	} else {
		//--
		if(DEBUG == true) {
			log.Println("[DEBUG]", "Request Header Keys", r.Header)
		} //end if
		//--
		ipList = StrTrimWhitespaces(r.Header.Get(hdrKey))
		if(ipList == "") {
			log.Println("[WARNING]", CurrentFunctionName(), "Failed to get a valid IP Address from custom Header Key: `" + ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP + "`")
			return false, DEFAULT_FAKE_IP_CLIENT, "", hdrKey
		} //end if
		//--
		splitIps := strings.Split(ipList, ",")
		for _, tmpIp := range splitIps { // get last from list, as this is considered to be last added by trusted proxy
			tmpIp = StrToLower(StrTrimWhitespaces(tmpIp))
			if((tmpIp != "") && IsNetValidIpAddr(tmpIp)) {
				ip = tmpIp
			} //end if
		} //end for
		//--
	} //end if
	//--
	if((StrTrimWhitespaces(ip) == "") || (!IsNetValidIpAddr(ip))) {
		log.Println("[WARNING]", CurrentFunctionName(), "Failed to get a valid IP Address ; custom Header Key: `" + ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP + "`")
		return false, DEFAULT_FAKE_IP_CLIENT, ipList, hdrKey
	} //end if
	//--
	return true, ip, ipList, hdrKey
	//--
} //END FUNCTION


func GetHttpRemoteAddrIpAndPortFromRequest(r *http.Request) (ipAddr string, portNum string) {
	//--
	var remoteAddr string = StrTrimWhitespaces(r.RemoteAddr)
	if(remoteAddr == "") {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Get Safe IP and Port from RemoteAddress Failed, empty")
		return "", "0"
	} //end if
	ip, port, err := net.SplitHostPort(remoteAddr) // expects: remoteAddr = 127.0.0.1:1234
	if(err != nil) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Get Safe IP and Port from RemoteAddress Failed, invalid format")
		return "", "0"
	} //end if
	//--
	ip = StrToLower(StrTrimWhitespaces(ip))
	if(!IsNetValidIpAddr(ip)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Get Safe IP and Port from RemoteAddress Failed, invalid IP:", ip)
		ip = ""
	} //end if
	if(!IsNetValidPortStr(port)) {
		log.Println("[WARNING] " + CurrentFunctionName() + ": Get Safe IP and Port from RemoteAddress Failed, invalid Port", port)
		port = "0"
	} //end if
	return ip, port // returns strtolower + trim of IP
	//--
} //END FUNCTION


//-----


func IsNetValidPortNum(p int64) bool { // can be a valid NUMERIC port between 1 and 65535
	//--
	if((p < 1) || (p > 65535)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func IsNetValidPortStr(s string) bool { // can be a valid STRING(as NUMERIC) port between 1 and 65535
	//--
	if(StrTrimWhitespaces(s) == "") {
		return false
	} //end if
	//--
	var p int64 = ParseStrAsInt64(s)
	//--
	return IsNetValidPortNum(p)
	//--
} //END FUNCTION


func IsNetValidHostName(s string) bool { // can contains only
	//--
	if(StrTrimWhitespaces(s) == "") {
		return false
	} //end if
	//--
	if(!StrRegexMatchString(REGEX_SMART_SAFE_NET_HOSTNAME, s)) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func IsNetValidIpAddr(s string) bool { // can be IPV4 or IPV6 but non-empty or zero
	//--
	if((StrTrimWhitespaces(s) == "") || (StrTrimWhitespaces(s) == "0.0.0.0") || (StrTrimWhitespaces(s) == "0:0:0:0:0:0:0:0") || (StrTrimWhitespaces(s) == "::0") || (StrTrimWhitespaces(s) == "::")) { // dissalow empty or zero IP v4 / v6 addresses
		return false
	} //end if
	//--
	if(net.ParseIP(s) == nil) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


//-----


// #END
