
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250214.2358 :: STABLE
// [ NET ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"strings"

	"net"
	"net/url"
	"net/http"
)

const (
	REGEX_SAFE_VAR_NAME string 				= `^[_a-zA-Z0-9]+$` 				// Safe VarName Regex

	REGEX_SMART_SAFE_BASE_PATH string 		= `^[_a-z0-9\-\/]+$` 				// CONFORMANCE: SUPPORT ONLY THESE CHARACTERS IN HTML BASE PATHS

	REGEX_SMART_SAFE_NET_HOSTNAME string 	= `^[_a-z0-9\-\.]+$` 				// SAFETY: SUPPORT ONLY THESE CHARACTERS IN NET HOST NAMES AS RFC ; if a hostname have upper characters must be converted to all lower characters ; if a hostname have unicode characters must be converted using punnycode ...
	REGEX_SMART_SAFE_HTTP_HEADER_KEY string = `^[A-Za-z0-9\-]+$` 				// SAFETY: SUPPORT ONLY THESE CHARACTERS IN HEADER KEY VALUES

	REGEX_SMART_SAFE_EMAIL_ADDRESS string 	= `^[_a-zA-Z0-9\-\.\+~]{1,63}@[a-z0-9\-\.]{3,63}$` 	// internet email@(subdomain.)domain.name
	REGEX_SMART_SAFE_NET_USERNAME  string 	= `^[_a-zA-Z0-9\-\.\+~@]{3,127}$` 					// general characters accepted in a username

	MAX_HOSTNAME_FULL_LENGTH int    = 253 // The entire hostname, including the delimiting dots, has a maximum of 253 ASCII characters
	MAX_HOSTNAME_SEGMENT_LENGTH int =  63 // For example, "en.wikipedia.org" is a hostname. Each label must be 1 to 63 octets long

	HTTP_PROTO_PREFIX_HTTP  string = "http://"
	HTTP_PROTO_PREFIX_HTTPS string = "https://"

	DATA_URL_EMPTY_PREFIX string = "data:,"
	DATA_URL_CSS_PREFIX string = "data:text/css,"
	DATA_URL_JS_PREFIX string = "data:application/javascript,"
	DATA_URL_SVG_IMAGE_PREFIX string = "data:image/svg+xml,"

	DEFAULT_FAKE_IP_CLIENT string = "0.0.0.0"
	DEFAULT_FAKE_HOSTPORT_SERVER string = "256.256.256.256:65535"

	DEFAULT_BROWSER_UA string = "NetSurf/3.11 (Sf.Go/" + VERSION + ")"
)

var (
	httpProxyBasePath string = "/" 												// for Proxy Mode only ; Serving HTML Document BasePath (used also in 301/302 redirects) ; when Golang is behind Haproxy, ex: under `/api/` path, this have to be changed accordingly as `/api/` instead of default `/` ; to work with assets this path must be rewritten back from ex: `/api/` to `/` by haproxy request rewrites
	ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP string = "" 							// CASE SENSITIVE, CAMEL CASE (in golang !) ; by default is empty (no proxy) ; if a proxy is used it can be set as: "X-Forwarded-Client-Ip" or "X-Real-Ip" or "X-Forwarded-For" or ... ; can be set only once before using any methods that is referencing this ; changing more than once would not be safe and can lead to many security flaws
	ini_SMART_FRAMEWORK_SRVPROXY_SERVER_PROTO string = "" 						// CASE SENSITIVE, CAMEL CASE (in golang !) ; by default is empty (no proxy) ; if a proxy is used it can be set as: "X-Forwarded-Proto" ; expects: `http` | `https` 										; can be set only once before using any methods that is referencing this ; changing more than once would not be safe and can lead to many security flaws
	ini_SMART_FRAMEWORK_SRVPROXY_SERVER_HOSTPORT  string = "" 					// CASE SENSITIVE, CAMEL CASE (in golang !) ; by default is empty (no proxy) ; if a proxy is used it can be set as: "X-Forwarded-Host"  ; expects: `dom.ext:443` | Ipv4 `127.0.0.1:80` | [Ipv6] [::1]:80 	; can be set only once before using any methods that is referencing this ; changing more than once would not be safe and can lead to many security flaws

	sessionUUIDCookieName string = "" 											// [2..16 characters ; valid REGEX_SAFE_VAR_NAME] ; default is EMPTY, to enable anonymous UUID tracking cookie set to ~ "Sf_UUID" ; this is intended to provide a unique session anonymous tracking UUID
	ini_SMART_FRAMEWORK_COOKIES_DEFAULT_SAMESITE string = "Lax" 				// default cookies policy ; can be: Lax / Strict / None / Empty
	ini_SMART_FRAMEWORK_COOKIES_DEFAULT_DOMAIN string = "" 						// default cookies domain ; (empty) `` for the current subdomain as `sdom.domain.tld` ; set it as `*` or explicit `domain.tld` for all sub-domains of domain.tld
)

//-----


func SetHttpProxyBasePath(pfx string) bool {
	//--
	// IMPORTANT: This should be safe, it is used also in 301/302 redirects (Header Values) !!
	// must be slash ex: `/` or start+end with slash, ex: `/path/`
	//--
	pfx = StrTrimWhitespaces(pfx)
	if(pfx == "") {
		pfx = "/"
	} //end if
	if(pfx == "/") {
		log.Println("[INFO]", CurrentFunctionName(), "SmartGo HTML BasePath was Set to (Default) `" + httpProxyBasePath + "`: Success")
		return true
	} //end if
	//--
	pfx = StrTrimWhitespaces(StrTrim(pfx, "/ ")) // trim on both sides
	if((pfx == "") || (StrTrimWhitespaces(StrTrim(pfx, ".-/ ")) == "")) {
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo HTML BasePath Core is Empty: `" + pfx + "`")
		return false
	} //end if
	//--
	pfx = "/" + pfx + "/" // re-add prefix+suffix slashes
	if(!StrRegexMatch(REGEX_SMART_SAFE_BASE_PATH, pfx)) {
		log.Println("[ERROR]", CurrentFunctionName(), "SmartGo HTML BasePath is Invalid: `" + pfx + "`")
		return false
	} //end if
	//--
	httpProxyBasePath = pfx
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo HTML BasePath was Set to `" + httpProxyBasePath + "`: Success")
	//--
	return true
	//--
} //END FUNCTION


func GetHttpProxyBasePath() string {
	//--
	return httpProxyBasePath
	//--
} //END FUNCTION


//-----


func SetCookieDefaultDomain(domain string) bool {
	//--
	var ok bool = true
	//--
	domain = StrTrimWhitespaces(domain)
	if((domain != "") && (domain != "*") && (domain != "@")) { // special cases
		if(!IsNetValidHostName(domain)) {
			log.Println("[ERROR]", CurrentFunctionName(), "SmartGo Cookie Default Domain is Invalid: `" + domain + "`")
			domain = ""
			ok = false
		} //end if
	} //end if
	//--
	if(ok) {
		ini_SMART_FRAMEWORK_COOKIES_DEFAULT_DOMAIN = StrToLower(domain)
		log.Println("[INFO]", CurrentFunctionName(), "SmartGo Cookie Default Domain was Set to `" + ini_SMART_FRAMEWORK_COOKIES_DEFAULT_DOMAIN + "`: Success")
	} //end if
	//--
	return ok
	//--
} //END FUNCTION


func GetCookieDefaultDomain() string {
	//--
	return ini_SMART_FRAMEWORK_COOKIES_DEFAULT_DOMAIN
	//--
} //END FUNCTION


func SetCookieDefaultSameSitePolicy(policy string) bool {
	//--
	var ok bool = true
	//--
	policy = StrUcFirst(StrToLower(StrTrimWhitespaces(policy)))
	//--
	switch(policy) {
		case "None":
		case "Lax":
		case "Strict":
		case "Empty":
			break
		default:
			log.Println("[ERROR]", CurrentFunctionName(), "SmartGo Cookie Default SameSite Policy is Invalid: `" + policy + "`")
			policy = ""
			ok = false
	} //end switch
	//--
	if(ok) {
		ini_SMART_FRAMEWORK_COOKIES_DEFAULT_SAMESITE = policy
		log.Println("[INFO]", CurrentFunctionName(), "SmartGo Cookie Default SameSite Policy was Set to `" + ini_SMART_FRAMEWORK_COOKIES_DEFAULT_SAMESITE + "`: Success")
	} //end if
	//--
	return ok
	//--
} //END FUNCTION


func GetCookieDefaultSameSitePolicy() string {
	//--
	return ini_SMART_FRAMEWORK_COOKIES_DEFAULT_SAMESITE
	//--
} //END FUNCTION


//-----


func HttpSessionUUIDCookieIsEnabled() bool {
	//--
	if(HttpSessionUUIDCookieNameGet() != "") {
		return true
	} //end if
	//--
	return false
	//--
} //END FUNCTION


func HttpSessionUUIDCookieNameGet() string {
	//--
	var cookieName string = StrTrimWhitespaces(sessionUUIDCookieName)
	if(!ValidateCookieName(cookieName)) {
		cookieName = "" // invalid, clear
	} //end if
	//--
	if(cookieName != "") {
		if((cookieName == auth2FACookieName) || (cookieName == authCookieName)) { // avoid collision with auth2FACookieName or authCookieName
			cookieName = "" // invalid, clear
		} //end if
	} //end if
	//--
	return cookieName
	//--
} //END FUNCTION


func HttpSessionUUIDCookieNameSet(cookieName string) bool {
	//--
	var ok bool = true
	//--
	cookieName = StrTrimWhitespaces(cookieName)
	if(cookieName == "") { // do not check below for empty cookie name, must be a way to be unset by passing empty string to this method
		if(sessionUUIDCookieName == "") {
			return true // disallow unset
		} else {
			ok = false // invalid, empty ; unset is not allowed
		} //end if else
	} else if(HttpSessionUUIDCookieNameGet() == "") { // allow set just once
		if(ValidateCookieName(cookieName)) {
			if((cookieName != auth2FACookieName) && (cookieName != authCookieName)) { // avoid collision with auth2FACookieName or authCookieName
				sessionUUIDCookieName = cookieName // set
			} else {
				ok = false // was non-empty, colission
			} //end if else
		} else {
			ok = false // was non-empty, but invalid
		} //end if
	} else {
		ok = false // don't allow set it again, if already was set
	} //end if
	//--
	if(ok) {
		log.Println("[INFO]", CurrentFunctionName(), "Session UUID Cookie Name was Set to `" + sessionUUIDCookieName + "`: Success")
	} else {
		log.Println("[ERROR]", CurrentFunctionName(), "Failed to Set Session UUID Cookie Name to: `" + cookieName + "`")
	} //end if else
	//--
	return ok
	//--
} //END FUNCTION


//-----


func ValidateCookieName(cookieName string) bool {
	//--
	if(StrTrimWhitespaces(cookieName) == "") {
		return false // invalid, empty
	} //end if
	if(!StrRegexMatch(REGEX_SAFE_VAR_NAME, cookieName)) {
		return false // invalid, regex does not match
	} //end if
	if(len(cookieName) < 2) { // reasonable, min 2 characters
		return false // invalid, too short
	} //end if
	if(len(cookieName) > 128) { // reasonable, max 128 characters, but anyway this is far too long ... recommended is having ~ max 16 characters ; this is allowed to be longer, by ex for Smart Captcha style cookies with hash suffixes
		return false // invalid, too long
	} //end if else
	//--
	return true // valid
	//--
} //END FUNCTION


//-----


func IsValidHttpHeaderKey(hdrKey string) bool {
	//--
	if(StrTrimWhitespaces(hdrKey) == "") {
		return false
	} //end if
	if(!StrRegexMatch(REGEX_SMART_SAFE_HTTP_HEADER_KEY, hdrKey)) {
		return false
	} //end if
	if(len(hdrKey) < 1) { // reasonable, min 1 characters
		return false // invalid, too short
	} //end if
	if(len(hdrKey) > 255) { // reasonable, max 255 characters, but anyway this is far too long ... recommended is having ~ max 64 characters ; this is allowed to be longer for exceptional situations only
		return false // invalid, too long
	} //end if else
	//--
	return true
	//--
} //END FUNCTION


//-----


func SetHttpProxyRealServerProtoHeaderKey(hdrKey string) bool {
	//--
//	hdrKey = StrToUpper(StrTrimWhitespaces(hdrKey))
	hdrKey = StrTrimWhitespaces(hdrKey) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}} ; fix: any request header key goes into go http server will be converted into case-sensitive keys. The canonicalization converts the first letter and any letter following a hyphen to upper case; the rest are converted to lowercase. For example, the canonical key for "accept-encoding" is "Accept-Encoding"
	//--
	if(!IsValidHttpHeaderKey(hdrKey)) {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Set Real Server Proto Proxy Header Key Failed, invalid:", hdrKey)
		return false
	} //end if
	//--
	if(ini_SMART_FRAMEWORK_SRVPROXY_SERVER_PROTO != "") {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Set Real Server Proto Proxy Header Key Failed, already set as:", ini_SMART_FRAMEWORK_SRVPROXY_SERVER_PROTO)
		return false
	} //end if
	//--
	ini_SMART_FRAMEWORK_SRVPROXY_SERVER_PROTO = http.CanonicalHeaderKey(hdrKey) // fix camelcase
	//--
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo Http Real Server Proto Proxy Header Key Set to `" + ini_SMART_FRAMEWORK_SRVPROXY_SERVER_PROTO + "`: Success")
	//--
	return true
	//--
} //END FUNCTION


func GetHttpProxyRealServerProtoHeaderKey() string {
	//--
	return StrTrimWhitespaces(ini_SMART_FRAMEWORK_SRVPROXY_SERVER_PROTO) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
	//--
} //END FUNCTION


//-----


func SetHttpProxyRealServerHostPortHeaderKey(hdrKey string) bool {
	//--
//	hdrKey = StrToUpper(StrTrimWhitespaces(hdrKey))
	hdrKey = StrTrimWhitespaces(hdrKey) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}} ; fix: any request header key goes into go http server will be converted into case-sensitive keys. The canonicalization converts the first letter and any letter following a hyphen to upper case; the rest are converted to lowercase. For example, the canonical key for "accept-encoding" is "Accept-Encoding"
	//--
	if(!IsValidHttpHeaderKey(hdrKey)) {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Set Real Server HostPort Proxy Header Key Failed, invalid:", hdrKey)
		return false
	} //end if
	//--
	if(ini_SMART_FRAMEWORK_SRVPROXY_SERVER_HOSTPORT != "") {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Set Real Server HostPort Proxy Header Key Failed, already set as:", ini_SMART_FRAMEWORK_SRVPROXY_SERVER_HOSTPORT)
		return false
	} //end if
	//--
	ini_SMART_FRAMEWORK_SRVPROXY_SERVER_HOSTPORT = http.CanonicalHeaderKey(hdrKey) // fix camelcase
	//--
	log.Println("[INFO]", CurrentFunctionName(), "SmartGo Http Real Server HostPort Proxy Header Key Set to `" + ini_SMART_FRAMEWORK_SRVPROXY_SERVER_HOSTPORT + "`: Success")
	//--
	return true
	//--
} //END FUNCTION


func GetHttpProxyRealServerHostPortHeaderKey() string {
	//--
	return StrTrimWhitespaces(ini_SMART_FRAMEWORK_SRVPROXY_SERVER_HOSTPORT) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
	//--
} //END FUNCTION


//-----


func SetHttpProxyRealClientIpHeaderKey(hdrKey string) bool {
	//--
//	hdrKey = StrToUpper(StrTrimWhitespaces(hdrKey))
	hdrKey = StrTrimWhitespaces(hdrKey) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}} ; fix: any request header key goes into go http server will be converted into case-sensitive keys. The canonicalization converts the first letter and any letter following a hyphen to upper case; the rest are converted to lowercase. For example, the canonical key for "accept-encoding" is "Accept-Encoding"
	//--
	if(!IsValidHttpHeaderKey(hdrKey)) {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Set Real Client IP Proxy Header Key Failed, invalid:", hdrKey)
		return false
	} //end if
	//--
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


func GetHttpProxyRealClientIpHeaderKey() string {
	//--
	return StrTrimWhitespaces(ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
	//--
} //END FUNCTION


//-----


func GetHttpRealClientIpFromRequestHeaders(r *http.Request) (isOk bool, clientRealIp string, rawVal string, headerKey string) {
	//--
	defer PanicHandler()
	//--
	// This may differ from RemoteAddr IP ; if ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP is set will get IP from the Request Proxy Headers such as: X-FORWARDED-CLIENT-IP, X-REAL-IP, X-FORWARDED-FOR
	//--
	var ip string = ""
	var ipList string = ""
	//--
	var hdrKey string = StrTrimWhitespaces(ini_SMART_FRAMEWORK_SRVPROXY_CLIENT_IP) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
	if(hdrKey == "") {
		//--
		ip, _ = GetHttpRemoteAddrIpAndPortFromRequest(r)
		ipList = ip
		hdrKey = "[REMOTE_ADDR]" // this is a special value, not in the headers, with underscore, keep in square brackets, to identify particular from the rest
		//--
	} else {
		//--
		if(DEBUG == true) {
			log.Println("[DEBUG]", "Request Header Keys", r.Header)
		} //end if
		//--
		if((r.Header != nil) && (len(r.Header) > 0)) {
			ipList = StrTrimWhitespaces(r.Header.Get(hdrKey))
		} //end if
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
	defer PanicHandler()
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


// returns: `http://` or `https://`
func GetHttpProtocolFromRequest(r *http.Request) (proto string) {
	//--
	defer PanicHandler()
	//--
	proto = "" // in case of error display as this, is non-usable, at least to know ...
	//--
	var hdrKey string = StrTrimWhitespaces(ini_SMART_FRAMEWORK_SRVPROXY_SERVER_PROTO) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
	if(hdrKey != "") { // behind proxy
		var hdrVal string = ""
		if((r.Header != nil) && (len(r.Header) > 0)) {
			hdrVal = StrToLower(StrTrimWhitespaces(r.Header.Get(hdrKey)))
		} //end if
		if(hdrVal == "https") {
			proto = HTTP_PROTO_PREFIX_HTTPS
		} else {
			proto = HTTP_PROTO_PREFIX_HTTP
		} //end if else
	} else {
		if(r.TLS != nil) {
			proto = HTTP_PROTO_PREFIX_HTTPS
		} else {
			proto = HTTP_PROTO_PREFIX_HTTP
		} //end if
	} //end if
	//--
	return
	//--
} //END FUNCTION


// domain can be: domain or IPv4 / IPv6
func GetHttpDomainAndPortFromRequest(r *http.Request) (domain string, portNum string, err error) {
	//--
	defer PanicHandler()
	//--
	domain = ""
	portNum = ""
	err = nil
	//--
	var host string = ""
	//--
	var hdrKey string = StrTrimWhitespaces(ini_SMART_FRAMEWORK_SRVPROXY_SERVER_HOSTPORT) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
	if(hdrKey != "") {
		var proxyHostPort string = ""
		if((r.Header != nil) && (len(r.Header) > 0)) {
			proxyHostPort = StrTrimWhitespaces(r.Header.Get(hdrKey)) // {{{SYNC-HEADER-KEY-GO-CASE-SENSITIVE}}}
		} //end if
		if(proxyHostPort == "") {
			log.Println("[WARNING]", CurrentFunctionName(), "Failed to get a valid HostPort from custom Header Key: `" + ini_SMART_FRAMEWORK_SRVPROXY_SERVER_HOSTPORT + "`")
			proxyHostPort = DEFAULT_FAKE_HOSTPORT_SERVER // use an impossible value to avoid spoofing
		} //end if
		host = proxyHostPort
	} else {
		host = StrTrimWhitespaces(r.Host)
	} //end if else
	//--
	var missingPort bool = false
	if(StrStartsWith(host, "[")) { // ex: ipv6 [::1]:13788 | [::1] ; {{{SYNC-SMART-SERVER-DOMAIN-IPV6-BRACKETS}}}
		if(!StrContains(host, "]:")) { // port is missing ; if no explicit port is used, defaults 80 and 443 may be missing
			missingPort = true
		} //end if
	} else { // dom.ext:13788 | dom.ext | 127.0.0.1:13788 | 127.0.0.1
		if(!StrContains(host, ":")) { // port is missing ; if no explicit port is used, defaults 80 and 443 may be missing
			missingPort = true
		} //end if
	} //end if
	if(missingPort) {
		var proto string = GetHttpProtocolFromRequest(r)
		if(proto == HTTP_PROTO_PREFIX_HTTPS) {
			host += ":443" // if port is missing and proto is https, include default https port: 443
		} else {
			host += ":80" // if port is missing and proto is http, include default https port: 80
		} //end if else
	} //end if
	//--
	domain, portNum, errSplit := net.SplitHostPort(host)
	if(errSplit != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Failed to get a valid HostName and Port from: `" + host + "` ; Error:", errSplit)
		domain = ""
		portNum = ""
		err = errSplit
	} //end if
	//--
	if((!IsNetValidHostName(domain)) && (!IsNetValidIpAddr(domain))) {
		domain = ""
		err = NewError("Invalid Hostname Domain/IP")
	} //end if
	//--
	if(!IsNetValidPortStr(portNum)) {
		portNum = ""
		err = NewError("Invalid Hostname Port")
	} //end if
	//--
	if(StrContains(domain, ":")) { // Ipv6
		domain = "[" + domain + "]" // {{{SYNC-SMART-SERVER-DOMAIN-IPV6-BRACKETS}}}
	} //end if
	//--
	return
	//--
} //END FUNCTION


func GetBaseDomainFromDomain(domain string) (string, error) {
	//--
	defer PanicHandler()
	//--
	domain = StrTrimWhitespaces(domain)
	if(domain == "") {
		return "", NewError("Domain is Empty")
	} //end if
	//--
	domain = StrTrimWhitespaces(StrTrim(domain, "[] ")) // for IPv6 trim [] ; {{{SYNC-SMART-SERVER-DOMAIN-IPV6-BRACKETS}}}
	if(domain == "") {
		return "", NewError("Domain is Empty")
	} //end if
	//--
	if(IsNetValidIpAddr(domain)) { // if is an IPv4 or IPv6 that is considered a base domain
		if(StrContains(domain, ":")) { // Ipv6
			domain = "[" + domain + "]" // {{{SYNC-SMART-SERVER-DOMAIN-IPV6-BRACKETS}}}
			return domain, nil
		} //end if
		return domain, nil
	} //end if
	if(!IsNetValidHostName(domain)) {
		return "", NewError("Domain is Invalid")
	} //end if
	//--
	if(!StrContains(domain, ".")) { // if it does not contain any dot, it is already a base domain
		return domain, nil
	} //end if
	//--
	arr := Explode(".", domain)
	l := len(arr)
	if(l < 2) { // if have less than 2 segments, stop here
		return domain, nil
	} //end if
	var baseName string = StrTrimWhitespaces(arr[l-2])
	var baseExt string  = StrTrimWhitespaces(arr[l-1])
	if((baseName == "") || (baseExt == "")) {
		return "", NewError("Base Domain contains Empty Segments") // ex a..b
	} //end if
	domain = baseName + "." + baseExt
	//--
	return domain, nil
	//--
} //END FUNCTION


func GetHttpBrowserPathFromRequest(r *http.Request) (path string) { // FRONTEND Request Path
	//--
	// This is the real path as seen in browser
	// it should be used in constructs of HTML documents and/or 3xx redirects only
	//--
	return StrTrimRight(httpProxyBasePath, "/") + GetHttpPathFromRequest(r)
	//--
} //END FUNCTION


// returns: `/` or `/path/extra` or `/path/extra/`
func GetHttpPathFromRequest(r *http.Request) (path string) { // BACKEND Request Path
	//--
	// This is the internal GO request path ! By ex: if `/api/` is used as httpProxyBasePath, Haproxy will rewrite it to `/` and send to Go, and Go should use `/` as is when running behind ; but HTML document reference and 3xx redirects must still use httpProxyBasePath as prefix because they operate in frontend ...
	// This path is for backend (translated from proxy or direct real as go runs)
	// This must not include the httpProxyBasePath
	// It must be the real request path because will be processed internally by router
	// The httpProxyBasePath should be used only in constructs of HTMl Documents and Redirects !
	//--
	defer PanicHandler()
	//--
	path = StrTrimWhitespaces(r.URL.Path)
	if(path == "") {
		path = "/" // !!! do not add trailing slash except if empty, like this case ! in go ... this can be a dir, a file or a virtual route !!!
	} //end if
	//--
	return
	//--
} //END FUNCTION


func GetHttpBaseUrlFromRequest(r *http.Request) string { // FRONTEND Base URL ; this includes the proxy prefix/domain/port, it is the browser external url as seen in browser
	//--
	dom, port, _ := GetHttpDomainAndPortFromRequest(r)
	//--
	return GetHttpProtocolFromRequest(r) + dom + ":" + port + GetHttpProxyBasePath()
	//--
} //END FUNCTION


func GetHttpUrlFromRequest(r *http.Request, withUrlQuery bool) string { // FRONTEND URL w/o query string ; this includes the proxy prefix/domain/port, it is the browser external url as seen in browser
	//--
	var urlQuery = ""
	if(withUrlQuery) {
		urlQuery = GetHttpQueryStringFromRequest(r)
	} //end if
	//--
	dom, port, _ := GetHttpDomainAndPortFromRequest(r)
	//--
	return GetHttpProtocolFromRequest(r) + dom + ":" + port + GetHttpBrowserPathFromRequest(r) + urlQuery
	//--
} //END FUNCTION


// returns: `` or `?` or `?a` or `?a=` or `?a=b` or `?a=b&` or `?a=b&c` or `?a=b&c=` or `?a=b&c=d`
func GetHttpQueryStringFromRequest(r *http.Request) (query string) {
	//--
	defer PanicHandler()
	//--
	query = StrTrimWhitespaces(r.URL.RawQuery)
	if(query != "") {
		query = "?" + query // fix, otherwise omits the ?
	} //end if
	//--
	return
	//--
} //END FUNCTION


func GetHttpUserAgentFromRequest(r *http.Request) (ua string) {
	//--
	defer PanicHandler()
	//--
	ua = StrTrimWhitespaces(r.UserAgent())
	if(ua == "") {
		ua = "[Unknown]"
	} //end if
	//--
	return
	//--
} //END FUNCTION


func GetUserAgentBrowserClassOs(signature string) (bw string, cls string, os string, mb bool) {
	//-- r.20241031
	signature = StrToLower(StrTrimWhitespaces(signature))
	//--
	bw = ""
	cls = ""
	os = ""
	mb = false
	//-- SF::{{{SYNC-CLI-BW-ID}}} ; identify browser ; real supported browser classes: gk, ie, wk ; other classes as: xy are not trusted ... ;  tx / rb are text/robots browsers
	if(StrContains(signature, "firefox") || StrContains(signature, "iceweasel") || StrContains(signature, " fxios/")) {
		bw = "fox" 	// firefox
		cls = "gk" 	// gecko
	} else if(StrContains(signature, "seamonkey")) {
		bw = "smk" 	// mozilla seamonkey
		cls = "gk" 	// gecko
	} else if(StrContains(signature, " edg/") || StrContains(signature, " edge/")) {
		bw = "iee" 	// microsoft edge
		cls = "bk" 	// blink class
	} else if(StrContains(signature, "opera") || StrContains(signature, " opr/") || StrContains(signature, " oupeng/") || StrContains(signature, " opios/")) {
		bw = "opr" 	// opera
		cls = "bk" 	// blink class
	} else if(StrContains(signature, "iridium") || StrContains(signature, "chromium") || StrContains(signature, "chrome") || StrContains(signature, " crios/")) {
		bw = "crm" 	// chromium
		cls = "bk" 	// blink class
	} else if(StrContains(signature, "konqueror")) { // must be detected before safari because includes safari signature
		bw = "knq" 	// konqueror (kde)
		cls = "bk" 	// blink class ; since recently all konqueror releases are using qt webengine (blink)
	} else if(StrContains(signature, "epiphany")) { // must be detected before safari because includes safari signature
		bw = "eph" 	// epiphany (gnome)
		cls = "wk" 	// webkit class
	} else if(StrContains(signature, "safari") || StrContains(signature, "applewebkit")) {
		bw = "sfr" 	// safari
		cls = "wk" 	// webkit class
	} else if(StrContains(signature, "webkit")) { // general webkit signature, untrusted
		bw = "wkt" 	// webkit (component)
		cls = "wk" 	// webkit class
	} else if(StrContains(signature, "mozilla") || StrContains(signature, "gecko")) { // general mozilla signature, untrusted
		bw = "moz" 	// mozilla derivates, but not firefox or seamonkey which are detected above
		cls = "xy" 	// various class
	} else if(StrContains(signature, "netsurf/")) { // netsurf have just a simple signature, but avoid detect robots which are faking this signature ...
		bw = "nsf" 	// netsurf
		cls = "xy" 	// various class
	} else if(StrContains(signature, "lynx") || StrContains(signature, "links")) { // console text browsers and derivates
		bw = "lyx" 	// lynx / links (text browser)
		cls = "tx" 	// text class
	} //end if else
	//-- SF::{{{SYNC-CLI-OS-ID}}} ; identify os
	if(StrContains(signature, "windows") || StrContains(signature, "winnt")) {
		os = "win" // ms windows
	} else if(StrContains(signature, "macos") || StrContains(signature, " mac ") || StrContains(signature, "os x") || StrContains(signature, "osx") || StrContains(signature, "darwin") || StrContains(signature, "macintosh")) {
		os = "mac" // apple mac / osx / darwin
	} else if(StrContains(signature, "linux")) {
		os = "lnx" // *linux
	} else if(StrContains(signature, "openbsd") || StrContains(signature, "netbsd") || StrContains(signature, "freebsd") || StrContains(signature, "dragonfly") || StrContains(signature, " bsd ")) {
		os = "bsd" // *bsd
	} else if(StrContains(signature, "openindiana") || StrContains(signature, "illumos") || StrContains(signature, "opensolaris") || StrContains(signature, "solaris") || StrContains(signature, "sunos")) {
		os = "sun" // sun solaris incl clones
	} //end if else
	//--  identify mobile os
	if(StrContains(signature, "iphone") || StrContains(signature, "ipad") || StrContains(signature, "ipod") || StrContains(signature, "iwatch") || StrContains(signature, " opios/") || StrContains(signature, " crios/")) {
		os = "ios" // apple mobile ios: iphone / ipad / ipod / iwatch (and derivatives)
		mb = true
	} else if(StrContains(signature, "android") || StrContains(signature, "saphi") || StrContains(signature, " opr/") || StrContains(signature, " oupeng/")) {
		os = "and" // google android (and derivatives)
		mb = true
	} else if(StrContains(signature, "windows ce") || StrContains(signature, "windows phone") || StrContains(signature, "windows mobile") || StrContains(signature, "windows rt")) {
		os = "wmo" // ms windows mobile
		mb = true
	} else if((StrContains(signature, "mobile") && (StrContains(signature, "linux") || StrContains(signature, "ubuntu"))) || StrContains(signature, "tizen") || StrContains(signature, "webos") || StrContains(signature, "raspberry") || StrContains(signature, "blackberry")) {
		os = "lxm" // linux mobile
		mb = true
	} //end if
	//-- later fix
	if(bw == "sfr") {
		if((os != "mac") && (os != "ios")) { // safari can run just on Mac and iOS ; Webkit fakes also the signature as Safari
			bw = "wkt" // webkit
			cls = "xy" 	// various class
		} //end if
	} //end if
	//-- app support
	if(StrContains(signature, "(app.nwjs)") || StrContains(signature, "(app.electron)") || StrContains(signature, "(app.webkit)")) {
		bw = "app" // app: NwJS, Electron, WebKit based
		cls = "xy" 	// various class
	} //end if
	//-- robots (simplified detection ; actually robots can fake real signatures, so do just a basic detection)
	if(StrContains(signature, "curl") || StrContains(signature, "wget") || StrContains(signature, "bot") || StrContains(signature, "ftp") || StrContains(signature, "go-") || StrContains(signature, "php") || StrContains(signature, "python") || StrContains(signature, "perl") || StrContains(signature, "htmldoc") || StrContains(signature, "wkhtml") || StrContains(signature, "lighthouse")) {
		bw = "bot" // robot
		cls = "rb" 	// bot class
	} //end if
	//-- self-robot (simplified, go microservices version ; in go microservices can be split, using a hash does not apply, like in php ...)
	if(signature == StrToLower(StrTrimWhitespaces(DEFAULT_BROWSER_UA))) {
		bw = "@s#" // self-robot
		cls = "rb" 	// bot class
	} //end if
	//--
	return bw, cls, os, mb
	//--
} //END FUNCTION


//-----


func ParseUrl(u string) (*url.URL, error) {
	//--
	u = StrTrimWhitespaces(u)
	if(u == "") {
		return nil, NewError("URL is Empty")
	} //end if
	//--
	pUrl, err := url.Parse(u)
	if(err != nil) {
		return nil, NewError("URL Parse Error: " + err.Error())
	} //end if
	if(pUrl == nil) {
		return nil, NewError("URL Parse Error, Null")
	} //end if
	//--
	if((pUrl.Scheme != "https") && (pUrl.Scheme != "http")) {
		return nil, NewError("URL Scheme must be one of: `http://` or `https://`")
	} //end if
	//--
	return pUrl, nil
	//--
} //END FUNCTION


//-----


func IsNetValidHttpUrl(u string) bool {
	//--
	u = StrTrimWhitespaces(u)
	if(u == "") {
		return false
	} //end if
	//--
	pUrl, err := url.Parse(u)
	if((err != nil) || (pUrl == nil)) {
		return false
	} //end if
	//--
	if((pUrl.Scheme != "https") && (pUrl.Scheme != "http")) {
		return false
	} //end if
	//--
	return true
	//--
} //END FUNCTION


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
	if(len(s) > MAX_HOSTNAME_FULL_LENGTH) {
		return false
	} //end if
	//--
	if(!StrRegexMatch(REGEX_SMART_SAFE_NET_HOSTNAME, s)) {
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


func ValidateIPAddrList(ipList string) error {
	//--
	ipList = StrTrimWhitespaces(ipList)
	if(ipList == "") {
		return nil
	} //end if
	//--
	arrIpList := Explode(",", ipList)
	if((arrIpList == nil) || (len(arrIpList) <= 0)) {
		return NewError("The IP List have a wrong format")
	} //end if
	//--
	for i:=0; i<len(arrIpList); i++ {
		//--
		arrIpList[i] = StrTrimWhitespaces(arrIpList[i])
		//--
		if(!StrStartsWith(arrIpList[i], "<")) {
			return NewError("The IP List have a wrong value, must start with `<`, at entry #" + ConvertIntToStr(i))
		} //end if
		if(!StrEndsWith(arrIpList[i], ">")) {
			return NewError("The IP List have a wrong value, must end with `>`, at entry #" + ConvertIntToStr(i))
		} //end if
		//--
		arrIpList[i] = StrTrim(arrIpList[i], "<>") // do not trim ; must not have spaces inside brackets because matching is made by if StrContains <ip> to be fast and avoid re-parsing address list for each request
		if(StrTrimWhitespaces(arrIpList[i]) == "") {
			return NewError("The IP List have an empty IP Address value at entry #" + ConvertIntToStr(i))
		} //end if
		if(StrTrimWhitespaces(arrIpList[i]) != arrIpList[i]) { // must not contain any trailing spaces between brackets
			return NewError("The IP List have an wrong IP Address value at entry #" + ConvertIntToStr(i))
		} //end if
		//--
		if(IsNetValidIpAddr(arrIpList[i]) != true) {
			return NewError("The IP List have an invalid IP Address value at entry #" + ConvertIntToStr(i))
		} //end if
		//--
	} //end for
	//--
	return nil
	//--
} //END FUNCTION


//-----


// #END
