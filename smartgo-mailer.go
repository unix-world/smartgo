
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20250214.2358 :: STABLE
// [ MAILER ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"time"
	"strings"

	"net/smtp"

	uid    "github.com/unix-world/smartgo/crypto/uuid"
	mailer "github.com/unix-world/smartgo/utils/mail"
)

const (
	SMTP_TLS_STARTTLS string 			= "STARTTLS"
	SMTP_TLS_OPTIONAL_STARTTLS string 	= "STARTTLS/OPTIONAL"
	SMTP_SSL_TLS string 				= "SSL"
	SMTP_NO_TLS_NO_SSL string 			= "NOTLS/NOSSL"

	MAIL_ENCODING_B64  string 			= "B64"
	MAIL_ENCODING_QP   string 			= "QP"
	MAIL_ENCODING_8BIT string 			= "8BIT"
)


//-----


type SmtpConfig struct {
	MxDomain string
	Host     string
	Port     uint16
	TlsMode  string
	AuthType string
	AuthUser string
	AuthPass string
}

type MailMessageStruct struct {
	FromAddress  string
	FromName     string
	ToAddresses  []string
	CcAddresses  []string
	BccAddresses []string
	Subject      string
	Body         string
	AltBody      string
	IsHtml       bool
	Embedds      map[string]string
	Attachments  map[string]string
	Encoding     string
}


//-----


var smtpDefaultConfig *SmtpConfig = nil


//-----


func SmtpSetDefaultConfig(mxDomain string, host string, port uint16, tlsMode string, authType string, authUser string, authPass string) error {
	//--
	if(smtpDefaultConfig != nil) {
		return NewError("SMTP Default Config is already set") // allow to be set just once
	} //end if
	//--
	if(mxDomain == "") {
		return NewError("SMTP Default Config: MxDomain is empty")
	} //end if
	if(host == "") {
		return NewError("SMTP Default Config: Host is empty")
	} //end if
	if(port <= 0) {
		return NewError("SMTP Default Config: Port is zero")
	} //end if
	//--
	smtpDefaultConfig = &SmtpConfig{
		MxDomain: mxDomain,
		Host: host,
		Port: port,
		TlsMode: tlsMode,
		AuthType: authType,
		AuthUser: authUser,
		AuthPass: authPass,
	}
	//--
	return nil
	//--
} //END FUNCTION


func SmtpGetDefaultConfig() *SmtpConfig {
	//--
	return smtpDefaultConfig
	//--
} //END FUNCTION


//-----


func SendSmtpEmail(smtpConf SmtpConfig, mailMsgStruct MailMessageStruct) error {
	//-- message settings
	const maxSizePerAttachOrEmbedd    uint64 = SIZE_BYTES_16M * 2 //  32MB (ex: gmail only have 25MB)
	const maxSizeTotalAttachAndEmbedd uint64 = SIZE_BYTES_16M * 8 // 128MB (safety)
	//-- smtp mx domain
	smtpConf.MxDomain = StrTrimWhitespaces(smtpConf.MxDomain)
	if(smtpConf.MxDomain == "") {
		return NewError("SMTP MxDomain is Empty, it should be set to the advertised host name of the SMTP server")
	} //end if
	if(len(smtpConf.MxDomain) > MAX_HOSTNAME_SEGMENT_LENGTH) { // allow just 63 characters here, for safety ...
		return NewError("SMTP MxDomain is Too Long")
	} //end if
	if(!IsNetValidHostName(smtpConf.MxDomain)) {
		return NewError("SMTP MxDomain is Invalid as a HostName")
	} //end if
	//-- smtp host
	smtpConf.Host = StrTrimWhitespaces(smtpConf.Host)
	if(smtpConf.Host == "") {
		return NewError("SMTP Host is Empty")
	} //end if
	if((!IsNetValidHostName(smtpConf.Host)) && (!IsNetValidIpAddr(smtpConf.Host))) { // can be hostname or ip
		return NewError("SMTP Host should be either a valid HostName or an IPv4/IPv6 Address")
	} //end if
	//-- smtp port
	switch(smtpConf.Port) { // the allowed SMTP ports are: 25, 465, 587, and 2525
		case   25: fallthrough
		case  465: fallthrough
		case  587: fallthrough
		case 2525:
			break
		default:
			return NewError("SMTP Port is Invalid: [" + ConvertUInt16ToStr(smtpConf.Port) + "] ; the allowed SMTP ports are: 25, 465, 587, and 2525")
	} //end switch
	//-- smtp tls mode
	smtpConf.TlsMode = StrToUpper(StrTrimWhitespaces(smtpConf.TlsMode))
	switch(smtpConf.TlsMode) {
		case SMTP_SSL_TLS: fallthrough
		case SMTP_TLS_STARTTLS: fallthrough
		case SMTP_TLS_OPTIONAL_STARTTLS: fallthrough
		case SMTP_NO_TLS_NO_SSL:
			break
		default:
			return NewError("SMTP TLS Policy is Invalid: `" + smtpConf.TlsMode + "` ; accepted values are: `NONE`, `SSL`, `STARTTLS` and `STARTTLS/OPTIONAL`")
	} //end switch
	//-- smtp auth type
	smtpConf.AuthType = StrToUpper(StrTrimWhitespaces(smtpConf.AuthType))
	smtpConf.AuthUser = StrTrimWhitespaces(smtpConf.AuthUser)
	smtpConf.AuthPass = StrTrimWhitespaces(smtpConf.AuthPass)
	switch(smtpConf.AuthType) {
		case "XOAUTH2": fallthrough
		case "CRAM-MD5": fallthrough
		case "PLAIN": fallthrough
		case "LOGIN":
			if(smtpConf.AuthUser == "") {
				NewError("SMTP Auth User is Empty, but Authentication Type has been set to `" + smtpConf.AuthType + "`")
			} //end if
			if(len(smtpConf.AuthUser) > 127) { // allow: 63 + 1 + 63 as in the REGEX_SMART_SAFE_EMAIL_ADDRESS regex limits
				NewError("SMTP Auth User is too long")
			} //end if
			if(!StrRegexMatch(REGEX_SMART_SAFE_NET_USERNAME, smtpConf.AuthUser)) {
				NewError("SMTP Auth User contains invalid characters")
			} //end if
			if(smtpConf.AuthPass == "") {
				NewError("SMTP Auth Pass is Empty, but Authentication Type has been set to `" + smtpConf.AuthType + "`")
			} //end if
			if(len(smtpConf.AuthPass) > 512) { // allow 512 because can be a long XOAUTH2 token, otherwise passwords are much shorter
				NewError("SMTP Auth Pass is too long")
			} //end if
			break
		case "NONE":
			if((smtpConf.AuthUser != "") || (smtpConf.AuthPass != "")) {
				NewError("SMTP Auth User is Not Empty or Auth Pass is Not Empty, but Authentication Type has been set to `NONE`")
			} //end if
			break
		default:
			return NewError("SMTP Auth Type is Invalid: `" + smtpConf.AuthType + "` ; accepted values are: `NONE`, `LOGIN`, `PLAIN`, `CRAM-MD5` and `XOAUTH2`")
	} //end switch
	//-- From Addr
	mailMsgStruct.FromAddress = StrTrimWhitespaces(mailMsgStruct.FromAddress)
	if(mailMsgStruct.FromAddress == "") {
		return NewError("From Address is Empty")
	} //end if
	if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, mailMsgStruct.FromAddress)) {
		return NewError("From Address is Invalid")
	} //end if
	//-- From Name
	mailMsgStruct.FromName = StrNormalizeSpaces(StrTrimWhitespaces(mailMsgStruct.FromName))
	if(StrUnicodeLen(mailMsgStruct.FromName) > 128) { // can be empty
		return NewError("From Name is Too Long")
	} //end if
	if(StrContains(mailMsgStruct.FromName, "@")) {
		return NewError("From Name cannot contain `@` character")
	} //end if
	//-- To
	if(len(mailMsgStruct.ToAddresses) <= 0) {
		return NewError("To addresses list is Empty")
	} //end if
	for i:=0; i<len(mailMsgStruct.ToAddresses); i++ {
		mailMsgStruct.ToAddresses[i] = StrTrimWhitespaces(mailMsgStruct.ToAddresses[i])
		if(mailMsgStruct.ToAddresses[i] == "") {
			return NewError("Empty Email Address, To #" + ConvertIntToStr(i))
		} //end if
		if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, mailMsgStruct.ToAddresses[i])) {
			return NewError("Invalid Email Address, To #" + ConvertIntToStr(i))
		} //end if
	} //end for
	//-- Cc
	if(len(mailMsgStruct.CcAddresses) > 0) {
		for i:=0; i<len(mailMsgStruct.CcAddresses); i++ {
			mailMsgStruct.CcAddresses[i] = StrTrimWhitespaces(mailMsgStruct.CcAddresses[i])
			if(mailMsgStruct.CcAddresses[i] == "") {
				return NewError("Empty Email Address, Cc #" + ConvertIntToStr(i))
			} //end if
			if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, mailMsgStruct.CcAddresses[i])) {
				return NewError("Invalid Email Address, Cc #" + ConvertIntToStr(i))
			} //end if
		} //end for
	} //end if
	//-- Bcc
	if(len(mailMsgStruct.BccAddresses) > 0) {
		for i:=0; i<len(mailMsgStruct.BccAddresses); i++ {
			mailMsgStruct.BccAddresses[i] = StrTrimWhitespaces(mailMsgStruct.BccAddresses[i])
			if(mailMsgStruct.BccAddresses[i] == "") {
				return NewError("Empty Email Address, Cc #" + ConvertIntToStr(i))
			} //end if
			if(!StrRegexMatch(REGEX_SMART_SAFE_EMAIL_ADDRESS, mailMsgStruct.BccAddresses[i])) {
				return NewError("Invalid Email Address, Cc #" + ConvertIntToStr(i))
			} //end if
		} //end for
	} //end if
	//-- Subject
	mailMsgStruct.Subject = StrNormalizeSpaces(StrTrimWhitespaces(mailMsgStruct.Subject))
	if(mailMsgStruct.Subject == "") {
		return NewError("Subject is Empty")
	} //end if
	if(StrUnicodeLen(mailMsgStruct.Subject) > 255) {
		return NewError("Subject is Too Long")
	} //end if
	//-- Body
	mailMsgStruct.Body = StrTrimWhitespaces(mailMsgStruct.Body)
	if(mailMsgStruct.Body == "") {
		return NewError("Body is Empty")
	} //end if
	if(len(mailMsgStruct.Body) > 65535) {
		return NewError("Body is Too Long")
	} //end if
	//-- Alt Body (allowed just if body is html)
	mailMsgStruct.AltBody = StrTrimWhitespaces(mailMsgStruct.AltBody)
	if(mailMsgStruct.IsHtml == true) {
		if(len(mailMsgStruct.AltBody) > 65535) {
			return NewError("Alternate Body is Too Long")
		} //end if
	} else {
		if(mailMsgStruct.AltBody != "") {
			return NewError("Alternate Body is allowed just with HTML Body")
		} //end if
	} //end if else
	//-- Size Calculator
	var maxAttachAndEmbeddSize int = 0
	//-- Embedds
	var numEmbedds int = len(mailMsgStruct.Embedds)
	if(numEmbedds > 10) {
		return NewError("Embedds list can contain max 10")
	} //end if
	if(numEmbedds > 0) {
		for key, val := range mailMsgStruct.Embedds {
			//--
			if(StrTrimWhitespaces(key) == "") {
				return NewError("Embedds list contain an empty key")
			} //end if
			if(len(key) > 64) {
				return NewError("Embedds list contain an key which is too long: `" + key + "`")
			} //end if
			if(!PathIsSafeValidFileName(key)) {
				return NewError("Embedds list contain an key which contain unsafe characters: `" + key + "`")
			} //end if
			//--
			if(len(val) <= 0) {
				return NewError("Embedds list contain an empty value at key: `" + key + "`")
			} //end if
			if(uint64(len(val)) > maxSizePerAttachOrEmbedd) {
				return NewError("Embedds list contain an oversized value (more than 32MB) at key: `" + key + "`")
			} //end if
			//--
			maxAttachAndEmbeddSize += len(val)
			//--
		} //end for
	} //end if
	//-- Attachments
	var numAttachments int = len(mailMsgStruct.Attachments)
	if(numAttachments > 10) {
		return NewError("Attachments list can contain max 10")
	} //end if
	if(numAttachments > 0) {
		for key, val := range mailMsgStruct.Attachments {
			//--
			if(StrTrimWhitespaces(key) == "") {
				return NewError("Attachments list contain an empty key")
			} //end if
			if(len(key) > 64) {
				return NewError("Attachments list contain an key which is too long: `" + key + "`")
			} //end if
			if(!PathIsSafeValidFileName(key)) {
				return NewError("Attachments list contain an key which contain unsafe characters: `" + key + "`")
			} //end if
			//--
			if(len(val) <= 0) {
				return NewError("Attachments list contain an empty value at key: `" + key + "`")
			} //end if
			if(uint64(len(val)) > maxSizePerAttachOrEmbedd) {
				return NewError("Attachments list contain an oversized value (more than 32MB) at key: `" + key + "`")
			} //end if
			//--
			maxAttachAndEmbeddSize += len(val)
			//--
		} //end for
	} //end if
	//--
	if((maxAttachAndEmbeddSize < 0) || (uint64(maxAttachAndEmbeddSize) > maxSizeTotalAttachAndEmbedd)) {
		return NewError("The total size of all Embedds and Attachments cannot be more than 128MB")
	} //end if
	//--
	mailMsgStruct.Encoding = StrToUpper(StrTrimWhitespaces(mailMsgStruct.Encoding))
	switch(mailMsgStruct.Encoding) {
		case MAIL_ENCODING_B64: fallthrough
		case MAIL_ENCODING_QP: fallthrough
		case MAIL_ENCODING_8BIT:
			break
		case "":
			mailMsgStruct.Encoding = MAIL_ENCODING_8BIT
			break
		default:
			return NewError("Invalid Encoding: `" + mailMsgStruct.Encoding + "`")
	} //end switch
	//--
	msg := mailer.NewMessage()
	//--
	msg.SetCharset(CHARSET)
	msg.SetDateHeader("Date", time.Now())
	//--
	msgID := "<ID-" + uid.UuidUrn() + ">"
	//println(msgID)
	msg.SetHeader("Message-Id", msgID)
	//--
	uuidBound := uid.Uuid10Num() + uid.Uuid10Seq() + Crc32b("@MimePart---#Boundary@" + DateNowUtc())
	boundary :=  "_===-Mime.Part___.0000" + uuidBound + "__P_.-===_" // 60 characters
	msg.SetBoundary(boundary)
	aboundary := "_=-=-Mime.Alt___.00000" + uuidBound + "__A_.=-=-_" // 60 characters
	msg.SetABoundary(aboundary)
	rboundary := "_-==-Mime.Related___.0" + uuidBound + "__R_.-==-_" // 60 characters
	msg.SetRBoundary(rboundary)
	//--
	mailMsgStruct.Encoding = StrToUpper(StrTrimWhitespaces(mailMsgStruct.Encoding))
	switch(mailMsgStruct.Encoding) {
		case MAIL_ENCODING_B64:
			msg.SetEncoding(mailer.Base64)
			break
		case MAIL_ENCODING_QP:
			msg.SetEncoding(mailer.QuotedPrintable)
			break
		case MAIL_ENCODING_8BIT: fallthrough
		default:
			msg.SetEncoding(mailer.Unencoded) // 8-bit
	} //end switch
	//--
	msg.SetAddressHeader("From", mailMsgStruct.FromAddress, mailMsgStruct.FromName)
	msg.SetHeader("To",  mailMsgStruct.ToAddresses...)
	if(len(mailMsgStruct.CcAddresses) > 0) {
		msg.SetHeader("Cc",  mailMsgStruct.CcAddresses...)
	} //end if
	if(len(mailMsgStruct.BccAddresses) > 0) {
		msg.SetHeader("Bcc", mailMsgStruct.BccAddresses...)
	} //end if
	//--
	msg.SetHeader("Subject", mailMsgStruct.Subject)
	//--
	if(mailMsgStruct.IsHtml == true) {
		if(mailMsgStruct.AltBody == "") {
			mailMsgStruct.AltBody = "This is a MIME Message in HTML Format." // anti-spam rules needs an alternate plain text for html messages for better score
		} //end if
		msg.SetBody("text/plain", mailMsgStruct.AltBody)
		msg.AddAlternative("text/html", mailMsgStruct.Body)
	} else {
		msg.SetBody("text/plain", mailMsgStruct.Body)
	} //end if
	//--
	if(numEmbedds > 0) {
		for key, val := range mailMsgStruct.Embedds {
			msg.EmbedReader(key, strings.NewReader(val))
		} //end for
	} //end if
	mailMsgStruct.Embedds = nil // free mem
	//--
	if(numAttachments > 0) {
		for key, val := range mailMsgStruct.Attachments {
			msg.AttachReader(key, strings.NewReader(val))
		} //end for
	} //end if
	mailMsgStruct.Attachments = nil // free mem
	//--
	var auth smtp.Auth
	switch(smtpConf.AuthType) {
		case "XOAUTH2":
			auth = mailer.LoginXOauth2(smtpConf.AuthUser, smtpConf.AuthPass, smtpConf.MxDomain)
			break
		case "CRAM-MD5":
			auth = smtp.CRAMMD5Auth(smtpConf.AuthUser, smtpConf.AuthPass)
			break
		case "PLAIN":
			auth = smtp.PlainAuth("", smtpConf.AuthUser, smtpConf.AuthPass, smtpConf.MxDomain)
			break
		case "LOGIN":
			auth = mailer.LoginAuth(smtpConf.AuthUser, smtpConf.AuthPass, smtpConf.MxDomain)
			break
		default:
			auth = nil // use none as default
	} //end switch
	//--
	var tlsPolicy mailer.StartTLSPolicy = mailer.NoStartTLS
	var isSslPolicy bool = false
	// mailer.MandatoryStartTLS
	switch(smtpConf.TlsMode) {
		case SMTP_SSL_TLS:
			isSslPolicy = true
			break;
		case SMTP_TLS_STARTTLS:
			tlsPolicy = mailer.MandatoryStartTLS
			break
		case SMTP_TLS_OPTIONAL_STARTTLS:
			tlsPolicy = mailer.OpportunisticStartTLS
			break
		case SMTP_NO_TLS_NO_SSL: fallthrough
		default:
			// use no TLS, no SSL
	} //end switch
	//--
	d, errD := mailer.NewCustomAuthDialer(smtpConf.Host, smtpConf.Port, auth)
	if(errD != nil) {
		return errD
	} //end if
	if(d == nil) {
		return NewError("SMTP Dialer is Null")
	} //end if
	//--
	if(isSslPolicy == true) {
		d.SSL = true
	} else {
		d.StartTLSPolicy = tlsPolicy
	} //end if else
	//--
	return d.DialAndSend(msg)
	//--
} //END FUNCTION


//-----


// #END
