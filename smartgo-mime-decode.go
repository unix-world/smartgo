
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE
// [ MIME (EMAIL MESSAGE) / DECODE ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"fmt"
	"log"

	"bytes"
	"io"

	"mime"
	"mime/multipart"
	"mime/quotedprintable"

	"net/mail"

	dkim "github.com/unix-world/smartgo/mx/dkim"
)

const (
	// {{{SYNC-MIME-MESSAGE-TOTAL-SIZE}}} ; must be higher wih something, epilogue will be on compose which is extra added ; limit to max attachments and embedds zsize + 2 * Body Size (which is ~max~ 130 MB) to preserve memory ; most of mail clients will not decode messages over 100 MB so this is a reasonable limit
	MIME_MESSAGE_MAX_SIZE_PARSE uint64 = MIME_SIZE_TOTAL_ATTACH_AND_EMBEDD + MIME_BODY_MAX_LEN + MIME_BODY_MAX_LEN
)

const ( // DO NOT CHANGE any of these ; they are synced with the mailer.Message (smart) composer and intended to be supported just for the smart composer composed messages
	epilogueReservedPrefix 	string = "X-MimeMessage-Epilogue-"
	epilogueStart 			string = "X-MimeMessage-Epilogue-Start: #"
	epilogueEnd 			string = "X-MimeMessage-Epilogue-End: #"
	epilogueKeyCrc64e 		string = "X-MimeMessage-Crc64e"
	epilogueKeySh3a512B64 	string = "X-MimeMessage-CheckSum-Sha3-512"
	epilogueKeySha384B64 	string = "X-MimeMessage-Chained-CheckSum-Sha-384"
)

var (
	MIME_DEBUG bool = DEBUG
)

//-----

type MimeAddress struct {
	Email 				string 	`json:"email"`
	Name 				string 	`json:"name"`
}

type MimePartMetaInfo struct {
	MimeType 			string
	Charset 			string
	PartId 				string
	PartName 			string
	FileName 			string
	Disposition 		string
	IsInlineText 		bool
	IsInlineHtml 		bool
	IsInlineEmbedd 		bool
	IsAttachment 		bool
}

type MimeParseWarning struct {
	Index 				int
	PartNum 			int
	Warning 			string
}

type MimeDecodedPart struct {
	Error 				error
	Warnings 			[]string
	Encoding 			string
	Index 				int
	PartNum 			int
	MetaInfo 			MimePartMetaInfo
	Headers 			map[string][]string
	Content 			[]byte
	Decoded 			bool
}

type MimeHeader struct {
	DKIMSigned 			bool
	DKIMCustomVerifier 	bool
	DKIMVerifyOK 		bool
	DKIMVerifications 	[]*dkim.Verification
	DKIMSignature 		string
	DKIMPubKey 			string
	MimeVersion 		string
	IsMultiPartMixed 	bool
	IsMultiPartAlt 		bool
	ContentType 		string
	MessageId 			string
	DateTime 			string
	ReturnPath 			[]MimeAddress
	From 				[]MimeAddress
	To 					[]MimeAddress
	Cc 					[]MimeAddress
	Bcc 				[]MimeAddress
	Subject 			string
	NumParts 			uint64
	NumAttachments 		uint64
	NumEmbedds 			uint64
	NumEmbeddTextParts 	uint64
	NumEmbeddHtmlParts 	uint64
	NumWarnings 		uint64
	NumErrors 			uint64
	Epilogue 			MimeEpilogue
	EpilogueVfyOK   	bool
	EpilogueXtraVfyOK 	bool
	EpilogueXtraVfyJson string
	EpilogueXtraVfyErr 	error
}

type MimeEpilogue struct {
	Crc64e 				string
	Sh3a512B64 			string
	Sha384B64 			string
	Values 				map[string][]string
	IntegrityValues 	map[string][]string
}

type MessageXtraEpilogueVerifyFn func(bytMsg []byte, hdr MimeHeader, senderEmail string) (string, error)


//-----


func ParseMimeMessage(data []byte, msgXtraEpilogueVerifyFn MessageXtraEpilogueVerifyFn) (MimeHeader, []MimeDecodedPart, []MimeParseWarning, error) {
	//--
	defer PanicHandler()
	//--
	var decodedHdr 		MimeHeader
	var decodedParts 	[]MimeDecodedPart
	var warnings 		[]MimeParseWarning
	//--
	if(uint64(len(data)) > MIME_MESSAGE_MAX_SIZE_PARSE) { // check this before check if empty to avoid trim on very large string
		return decodedHdr, decodedParts, warnings, NewError("Message is OverSized, limit is 128MB")
	} //end if
	//--
	if(data == nil) {
		return decodedHdr, decodedParts, warnings, NewError("Message is Null")
	} //end if
	if((len(data) <= 0) || (len(BytTrimWhitespaces(data)) <= 0)) {
		return decodedHdr, decodedParts, warnings, NewError("Message is Empty")
	} //end if
	//--
	var eplgWarns []MimeParseWarning
	decodedHdr.EpilogueVfyOK, decodedHdr.Epilogue, eplgWarns = VerifyMimeMessageEpilogue(data)
	if(len(eplgWarns) > 0) {
		warnings = append(warnings, eplgWarns...)
	} //end if
	//-- Parse the message to separate the Header and the Body with mail.ReadMessage()
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if(err != nil) {
		return decodedHdr, decodedParts, warnings, NewError("Message Parsing Failed: " + err.Error())
	} //end if
	if(msg == nil) {
		return decodedHdr, decodedParts, warnings, NewError("Message Parsing Failed, Null")
	} //end if
	if((msg.Header == nil) || (len(msg.Header) <= 0)) {
		return decodedHdr, decodedParts, warnings, NewError("Message Parsing Failed, Header is Empty or Null")
	} //end if
	if(msg.Body == nil) { // body can't be checked for len, is interface to io.Reader
		return decodedHdr, decodedParts, warnings, NewError("Message Parsing Failed, Body is Empty or Null")
	} //end if
	//--
	decodedHdr.MimeVersion = StrToLower(conformMimeHeaderValue(msg.Header.Get(MIME_HEADER_KEY_MIME_VERSION)))
	//--
	decodedHdr.ContentType = StrToLower(conformMimeHeaderValue(msg.Header.Get(MIME_HEADER_KEY_CONTENT_TYPE))) // pre-parse, in case of error to display something
	if(MIME_DEBUG) {
		log.Println("[DEBUG]", CurrentFunctionName(), "Raw Content-Type:", decodedHdr.ContentType)
	} //end if
	//--
	decodedHdr.MessageId = conformMimeHeaderSpecialValue(msg.Header.Get(MIME_HEADER_KEY_MESSAGE_ID)) // do not make it lowercase, it is case-sensitive
	if(decodedHdr.MessageId != "") {
		decodedHdr.MessageId = StrTrimWhitespaces(StrTrim(StrTrimWhitespaces(decodedHdr.MessageId), MIME_ID_ENCLOSURE_START + MIME_ID_ENCLOSURE_END))
	} //end if
	//--
	decodedHdr.DKIMSignature = conformMimeHeaderValue(msg.Header.Get(MIME_HEADER_KEY_DKIM_SIGNATURE))
	if(decodedHdr.DKIMSignature != "") {
		decodedHdr.DKIMSigned = true
		dkimVfyOpts, errVfyOpts := DkimGetDefaultVerifyOptions(0, nil)
		if(errVfyOpts != nil) {
			warnings = append(warnings, MimeParseWarning{
				Index: 0,
				PartNum: 0,
				Warning: "DKIM Signature Verification Options Failed: " + errVfyOpts.Error(),
			})
		} else {
			if(dkimVfyOpts.LookupTXT != nil) {
				decodedHdr.DKIMCustomVerifier = true
			} //end if
			okDkim, dkimVerifications, errDkimVfy := dkim.VerifySignedMimeMessage(dkimVfyOpts, data)
			decodedHdr.DKIMVerifications = dkimVerifications
			if(len(dkimVerifications) > 0) {
				for _, dkV := range dkimVerifications {
					if(dkV.Err != nil) {
						warnings = append(warnings, MimeParseWarning{
							Index: 0,
							PartNum: 0,
							Warning: "FAIL: DKIM Signature is Invalid for domain: `" + dkV.Domain + "` # ERR: " + dkV.Err.Error(),
						})
					} else {
						decodedHdr.DKIMVerifyOK = true
						if(MIME_DEBUG) {
							log.Println("[DEBUG]", "OK: DKIM Signature is Valid for domain: `" + dkV.Domain + "`")
						} //end if
					} //end if else
				} //end for
			} //end if
			if(errDkimVfy != nil) {
				warnings = append(warnings, MimeParseWarning{
					Index: 0,
					PartNum: 0,
					Warning: "DKIM Signature Verification Error: " + errDkimVfy.Error(),
				})
			} else if(!okDkim) {
				warnings = append(warnings, MimeParseWarning{
					Index: 0,
					PartNum: 0,
					Warning: "DKIM Signature Verification is NOT OK",
				})
			} //end if
		} //end if else
	} //end if
	//--
	decodedHdr.DKIMPubKey 		= conformMimeHeaderSpecialValue(msg.Header.Get(MIME_HEADER_KEY_DKIM_PUBKEY))
	//--
	decodedHdr.DateTime 		= conformMimeHeaderValue(msg.Header.Get(MIME_HEADER_KEY_DATE))
	//--
	decodedHdr.ReturnPath 		= getMimeAddressesList(msg.Header.Get(MIME_HEADER_KEY_RETURN_PATH))
	decodedHdr.From 			= getMimeAddressesList(msg.Header.Get(MIME_HEADER_KEY_FROM))
	decodedHdr.To 				= getMimeAddressesList(msg.Header.Get(MIME_HEADER_KEY_TO))
	decodedHdr.Cc 				= getMimeAddressesList(msg.Header.Get(MIME_HEADER_KEY_CC))
	decodedHdr.Bcc 				= getMimeAddressesList(msg.Header.Get(MIME_HEADER_KEY_BCC))
	decodedHdr.Subject 			= getMimeDecodedHeaderVal(msg.Header.Get(MIME_HEADER_KEY_SUBJECT))
	//--
	arrCType := ParseContentTypeHeaderVal(msg.Header.Get(MIME_HEADER_KEY_CONTENT_TYPE))
	if(len(arrCType) <= 0) {
		arrCType = map[string]string{} // be sure is not nil !
	} //end if
	mediaType, okMediaType := arrCType[MIME_PARSER_CONTENT_TYPE_KEY]
	if(!okMediaType) {
		return decodedHdr, decodedParts, warnings, NewError("MIME Message Content-Type Header could not be parsed or was not found or is empty")
	} //end if
	mediaType = StrToLower(StrTrimWhitespaces(mediaType))
	if(mediaType != "") {
		decodedHdr.ContentType = mediaType // rewrite (if not empty) after parsing with the parsed value
	} //end if
	if((mediaType == "") || (StrStartsWith(mediaType, MIME_MESSAGE_MULTIPART_TYPE_PREFIX) != true)) {
		return decodedHdr, decodedParts, warnings, NewError("Message is Not a Multipart MIME Type")
	} //end if
	if(StrToLower(StrTrimWhitespaces(mediaType)) == (MIME_MESSAGE_MULTIPART_TYPE_PREFIX + "mixed")) {
		decodedHdr.IsMultiPartMixed = true
	} //end if
	boundary, okBoundary := arrCType[MIME_PARSER_CONTENT_BOUNDARY_KEY]
	if(!okBoundary) {
		return decodedHdr, decodedParts, warnings, NewError("MIME Message Boundary was not detected or is missing")
	} //end if
	boundary = StrTrimWhitespaces(boundary) // do not make lowercase, is case sensitive
	if(boundary == "") {
		return decodedHdr, decodedParts, warnings, NewError("MIME Message Boundary is empty")
	} //end if
	//-- Recursivey parsed the MIME parts of the Body, starting with the first level where the MIME parts are separated by boundary
	var decErr error = nil
	var decWarnings []MimeParseWarning
	decodedHdr.IsMultiPartAlt, decodedParts, decWarnings, decErr = parseMimePart(msg.Body, boundary, 1, nil, nil) // will do a recursive parsing
	if(len(decWarnings) > 0) {
		warnings = append(warnings, decWarnings...)
	} //end if
	//--
	var numWarnings int = len(warnings)
	if(numWarnings < 0) {
		numWarnings = 0
	} //end if
	decodedHdr.NumWarnings = uint64(numWarnings)
	for _, p := range decodedParts {
		decodedHdr.NumParts++
		if(p.Error != nil) {
			decodedHdr.NumErrors++
		} else if(p.Decoded != true) {
			decodedHdr.NumErrors++
		} //end if else
		if(p.MetaInfo.IsAttachment == true) {
			decodedHdr.NumAttachments++
		} else {
			decodedHdr.NumEmbedds++
			if(p.MetaInfo.IsInlineText == true) {
				decodedHdr.NumEmbeddTextParts++
			} else if(p.MetaInfo.IsInlineHtml == true) {
				decodedHdr.NumEmbeddHtmlParts++
			} //end if else
		} //end if else
	} //end for
	//--
	if(msgXtraEpilogueVerifyFn != nil) {
		var senderEmail string = ""
		for _, from := range decodedHdr.From {
			senderEmail = from.Email // get the 1st
			break
		} //end for
		decodedHdr.EpilogueXtraVfyJson, decodedHdr.EpilogueXtraVfyErr = msgXtraEpilogueVerifyFn(data, decodedHdr, senderEmail)
		if(decodedHdr.EpilogueXtraVfyErr != nil) {
			decodedHdr.NumWarnings++
			warnings = append(warnings, MimeParseWarning{
				Index: 0,
				PartNum: 0,
				Warning: "Xtra Epilogue Verify Failed: " + decodedHdr.EpilogueXtraVfyErr.Error(),
			})
		} else {
			decodedHdr.EpilogueXtraVfyOK = true
		} //end if else
	} //end if
	//--
	return decodedHdr, decodedParts, warnings, decErr
	//--
} //END FUNCTION


//-----


func GetMimeMessageCleanContent(data []byte) []byte {
	//--
	defer PanicHandler()
	//--
	if(len(data) <= 0) {
		return nil
	} //end if
	//--
	if(BytContains(data, []byte(MIME_HEADER_VAL_VERSION_ONE + "\r\n"))) {
		//--
		if(MIME_DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage Contains Head Value Version One:", MIME_HEADER_VAL_VERSION_ONE)
		} //end if
		//--
		var arrDat [][]byte
		arrDat = BExplodeWithLimit([]byte(MIME_HEADER_VAL_VERSION_ONE + "\r\n"), data, 2)
		if((len(arrDat) == 2) && (len(arrDat[0]) > 0) && (len(arrDat[1]) > 0)) {
			return append([]byte(MIME_HEADER_VAL_VERSION_ONE + "\r\n"), arrDat[1]...)
		} //end if
		//--
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


//-----


func VerifyMimeMessageEpilogue(data []byte) (bool, MimeEpilogue, []MimeParseWarning) {
	//--
	defer PanicHandler()
	//--
	var isEplgOk bool
	var eplg MimeEpilogue
	var warnings []MimeParseWarning
	//--
	if(len(data) <= 0) {
		return false, eplg, warnings
	} //end if
	//--
	if(BytContains(data, []byte(epilogueStart + "\r\n"))) {
		if(MIME_DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage Contains Epilogue Head Value Start:", epilogueStart)
		} //end if
		if(BytContains(data, []byte(epilogueEnd + "\r\n"))) {
			if(MIME_DEBUG) {
				log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage Contains Epilogue Head Value End:", epilogueStart)
			} //end if
			data = GetMimeMessageCleanContent(data)
			if(len(data) > 0) {
				var arrDat [][]byte
				arrDat = BExplodeWithLimit([]byte(epilogueStart + "\r\n"), data, 2)
				if((len(arrDat) == 2) && (len(arrDat[0]) > 0) && (len(arrDat[1]) > 0)) {
					if(MIME_DEBUG) {
						log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage Epilogue is computing the Integrity Hashes ...")
					} //end if
					var theCrc64e  string = string(CrcByt64e(arrDat[0]))
					var theSh3a512 string = string(Sh3aByt512B64(arrDat[0]))
					var theSha384  string = string(ShaByt384B64(append([]byte(theSh3a512 + FORM_FEED + theCrc64e + VERTICAL_TAB), arrDat[0]...))) // {{{SYNC-MIME-MESSAGE-SHA384-CHAINING}}}
					arrDat[0] = nil // free mem
					var errEplg error
					eplg, errEplg = parseMimeMessageEpilogue(arrDat[1])
					arrDat[1] = nil // free mem
					if(errEplg != nil) {
						warnings = append(warnings, MimeParseWarning{
							Index: 0,
							PartNum: 0,
							Warning: "MimeMessage Epilogue parsing Failed: " + errEplg.Error(),
						})
					} else {
						//--
						const reqEplgNumVfy uint8 = 3
						var passEplgNumVfy uint8 = 0
						if(MIME_DEBUG) {
							log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage Epilogue parsing Success")
						} //end if
						//--
						if(eplg.Crc64e != "") {
							if(eplg.Crc64e != theCrc64e) {
								warnings = append(warnings, MimeParseWarning{
									Index: 0,
									PartNum: 0,
									Warning: "MimeMessage Epilogue CRC64e is Invalid, expecting: " + eplg.Crc64e + ", but having: " + theCrc64e,
								})
							} else {
								passEplgNumVfy++
								if(MIME_DEBUG) {
									log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage Epilogue CRC64e Verification Passed")
								} //end if
							} //end if else
						} //end if
						//--
						if(eplg.Sh3a512B64 != "") {
							if(eplg.Sh3a512B64 != theSh3a512) {
								warnings = append(warnings, MimeParseWarning{
									Index: 0,
									PartNum: 0,
									Warning: "MimeMessage Epilogue SHA3-512 is Invalid, expecting: " + eplg.Sh3a512B64 + ", but having: " + theSh3a512,
								})
							} else {
								passEplgNumVfy++
								if(MIME_DEBUG) {
									log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage Epilogue SHA3-512 Verification Passed")
								} //end if
							} //end if else
						} //end if
						//--
						if(eplg.Sha384B64 != "") {
							if(eplg.Sha384B64 != theSha384) {
								warnings = append(warnings, MimeParseWarning{
									Index: 0,
									PartNum: 0,
									Warning: "MimeMessage Epilogue Chained SHA-384 is Invalid, expecting: " + eplg.Sha384B64 + ", but having: " + theSha384,
								})
							} else {
								passEplgNumVfy++
								if(MIME_DEBUG) {
									log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage Epilogue Chained SHA-384 Verification Passed")
								} //end if
							} //end if else
						} //end if
						//--
						if(passEplgNumVfy >= reqEplgNumVfy) {
							isEplgOk= true
						} //end if
						//--
					} //end if else
				} //end if
			} else {
				warnings = append(warnings, MimeParseWarning{
					Index: 0,
					PartNum: 0,
					Warning: "Failed to get Mime Clean Cpntent Part, Empty",
				})
			} //end if else
		} else {
			warnings = append(warnings, MimeParseWarning{
				Index: 0,
				PartNum: 0,
				Warning: "MimeMessage Epilogue is Invalid, missing the End Part",
			})
		} //end if else
	} else { // this should be no warning, 3rd party mime messages does not have
		if(MIME_DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "MimeMessage does not Contain the Epilogue Head Value Start")
		} //end if
	} //end if else
	//--
	return isEplgOk, eplg, warnings
	//--
} //END FUNCTION


func parseMimeMessageEpilogue(data []byte) (MimeEpilogue, error) {
	//--
	defer PanicHandler()
	//--
	data = BytTrimWhitespaces(data)
	if(data == nil) {
		data = []byte{}
	} //end if
	data = append(data, []byte("\r\n" + "\r\n" + "This is a pseudo MIME Message to parse the Epilogue" + "\r\n")...)
	//--
	eplg := MimeEpilogue{
		Values: map[string][]string{},
		IntegrityValues: map[string][]string{},
	}
	pseudoMsg, errPseudo := mail.ReadMessage(bytes.NewReader(data))
	if(errPseudo != nil) {
		return eplg, NewError("Epilogue Parsing Failed: " + errPseudo.Error())
	} //end if
	if(pseudoMsg == nil) {
		return eplg, NewError("PseudoMessage is Null")
	} //end if
	if((pseudoMsg.Header == nil) || (len(pseudoMsg.Header) <= 0)) {
		return eplg, NewError("PseudoMessage Header is Empty or Null")
	} //end if
	if(pseudoMsg.Body == nil) { // body can't be checked for len, is interface to io.Reader
		return eplg, NewError("PseudoMessage Body is Null")
	} //end if
	//--
	eplg.Crc64e     = StrToLower(conformMimeHeaderSpecialValue(pseudoMsg.Header.Get(epilogueKeyCrc64e)))
	eplg.Sh3a512B64 = conformMimeHeaderSpecialValue(pseudoMsg.Header.Get(epilogueKeySh3a512B64)) // B64, case sensitive, do not make lowercase
	eplg.Sha384B64  = conformMimeHeaderSpecialValue(pseudoMsg.Header.Get(epilogueKeySha384B64))  // B64, case sensitive, do not make lowercase
	//--
	for eK, eV := range pseudoMsg.Header {
		eK = StrToLower(StrTrimWhitespaces(eK))
		if(!StrIStartsWith(eK, epilogueReservedPrefix)) {
			if(StrIStartsWith(eK, MIME_COMPOSER_EPILOGUE_HEADER_KEY_PREFIX)) {
				eplg.Values[eK] = []string{}
				for _, eVV := range eV {
					eplg.Values[eK] = append(eplg.Values[eK], conformMimeHeaderValue(eVV))
				} //end for
			} else {
				eplg.IntegrityValues[eK] = []string{}
				for _, eVV := range eV {
					eplg.IntegrityValues[eK] = append(eplg.IntegrityValues[eK], conformMimeHeaderSpecialValue(eVV))
				} //end for
			} //end if
		} //end if
	} //end for
	//--
	return eplg, nil
	//--
} //END FUNCTION


//-----


func conformMimeHeaderValue(val string) string {
	//--
	return StrTrimWhitespaces(StrNormalizeSpaces(val))
	//--
} //END FUNCTION


func conformMimeHeaderSpecialValue(val string) string {
	//--
	return StrReplaceAll(conformMimeHeaderValue(val), " ", "")
	//--
} //END FUNCTION


//-----


func getMimeDecodedHeaderVal(hdrVal string) string {
	//--
	defer PanicHandler()
	//--
	hdrVal = StrTrimWhitespaces(hdrVal)
	if(hdrVal == "") {
		return ""
	} //end if
	//--
	dec := mime.WordDecoder{}
	str, errDec := dec.DecodeHeader(hdrVal)
	if(errDec != nil) {
		return ""
	} //end if
	//--
	return conformMimeHeaderValue(str)
	//--
} //END FUNCTION


func getMimeAddressesList(hdrVal string) []MimeAddress {
	//--
	defer PanicHandler()
	//--
	addrList := []MimeAddress{}
	//--
	hdrVal = StrTrimWhitespaces(hdrVal)
	if(hdrVal == "") {
		return addrList
	} //end if
	//--
	mAddrParser := mail.AddressParser{}
	theList, errParse := mAddrParser.ParseList(hdrVal)
	if(errParse != nil) {
		return addrList
	} //end if
	if(len(theList) > 0) {
		for _, v := range theList {
			entry := StrTrimWhitespaces(ObjectToString(v))
			if(entry != "") {
				mAddr, errAParse := mAddrParser.Parse(entry)
				if(errAParse == nil) {
					addr := MimeAddress{}
					addr.Name = StrTrimWhitespaces(StrNormalizeSpaces(mAddr.Name))
					addr.Email = StrToLower(StrTrimWhitespaces(StrNormalizeSpaces(mAddr.Address)))
					if(addr.Email != "") {
						addrList = append(addrList, addr)
					} //end if
				} //end if
			} //end if
		} //end for
	} //end if
	//--
	return addrList
	//--
} //END FUNCTION


//-----


func getMimePartMetaInfo(part *multipart.Part, radix string, index int) MimePartMetaInfo {
	//--
	// builds a file name for a MIME part, using information extracted from the part itself, as well as a radix and an index given as parameters.
	//--
	defer PanicHandler()
	//--
	mInf := MimePartMetaInfo{}
	//--
	if(part == nil) {
		return mInf
	} //end if
	if(index < 0) {
		index = 0 // disallow negative index
	} //end if
	//-- 1st try to parse the content disposition to get contentType, charset and filename, is more accurate
	var filename string = ""
	cDisp, cParams, errDisp := ParseMediaTypeHeaderVal(part.Header.Get(MIME_HEADER_KEY_CONTENT_DISPOSITION))
	if(errDisp != nil) {
		cDisp = MIME_MAIL_DISPOSITION_ATTACHMENT // if there is an error fallback to ATTACHMENT for safety
	} else {
		cDisp = StrToUpper(StrTrimWhitespaces(cDisp))
		if(cDisp != MIME_MAIL_DISPOSITION_INLINE) {
			cDisp = MIME_MAIL_DISPOSITION_ATTACHMENT
		} //end if
		if(len(cParams) > 0) {
			var okFname bool
			filename, okFname = cParams[MIME_PARSER_CONTENT_FILENAME_KEY]
			if(okFname) {
				filename = StrTrimWhitespaces(filename)
			} else {
				filename = ""
			} //end if else
		} //end if
	} //end if else
	//--
	var charset string = ""
	var partName string = ""
	mType, mParams, errTyp := ParseMediaTypeHeaderVal(part.Header.Get(MIME_HEADER_KEY_CONTENT_TYPE))
	if(errTyp != nil) {
		mType = ""
	} else {
		mType = StrToLower(StrTrimWhitespaces(mType))
		if(len(mParams) > 0) {
			var okCharset bool
			charset, okCharset = mParams[MIME_PARSER_CONTENT_CHARSET_KEY]
			if(okCharset) {
				charset = StrToUpper(StrTrimWhitespaces(charset))
			} else {
				charset = ""
			} //end if
			var okPartName bool
			partName, okPartName = mParams[MIME_PARSER_CONTENT_NAME_KEY]
			if(okPartName) {
				partName = StrTrimWhitespaces(partName)
			} else {
				partName = ""
			} //end if else
		} //end if
	} //end if else
	//-- if parsing above failed try to fallback to get FileName as parsed by go, is not so accurate as above
	if(filename == "") {
		filename = part.FileName() // 1st try to get the true file name if there is one in Content-Disposition
	} //end if
	if(partName != "") {
		if(filename == "") {
			filename = partName
			partName = ""
		} //end if
	} //end if
	//--
	var partId string = conformMimeHeaderSpecialValue(part.Header.Get(MIME_HEADER_KEY_CONTENT_ID))
	if(partId != "") {
		partId = StrTrimWhitespaces(StrTrim(StrTrimWhitespaces(partId), MIME_ID_ENCLOSURE_START + MIME_ID_ENCLOSURE_END))
	} //end if
	if(partId == "") {
		mediaType, _, err := ParseMediaTypeHeaderVal(part.Header.Get(MIME_HEADER_KEY_CONTENT_TYPE))
		if(err == nil) {
			mimeType, erx := mime.ExtensionsByType(mediaType)
			if(erx == nil) {
				if(len(mimeType) > 0) {
					partId = "|" + StrTrimWhitespaces(fmt.Sprintf("%s-%d%s", radix, index, mimeType[0])) + "|" // add | as prefix and suffix to know is emulated
				} //end if
			} //end if
		} //end if
	} //end if
	//--
	partName = StrTrimWhitespaces(StrReplaceAll(StrNormalizeSpaces(partName), " ", ""))
	filename = StrTrimWhitespaces(StrReplaceAll(StrNormalizeSpaces(filename), " ", ""))
	//--
	if(filename == "") {
		cDisp = MIME_MAIL_DISPOSITION_INLINE // if there is no filename, can't be attachment, fallback to INLINE
	} //end if
	//--
	mInf.MimeType = mType
	mInf.Charset = charset
	mInf.PartId = partId
	mInf.PartName = partName
	mInf.FileName = filename
	mInf.Disposition = cDisp

	if(mInf.Disposition == MIME_MAIL_DISPOSITION_INLINE) {
		if(StrToLower(StrTrimWhitespaces(mType)) == "text/plain") {
			mInf.IsInlineText = true
		} else if(StrToLower(StrTrimWhitespaces(mType)) == "text/html") {
			mInf.IsInlineHtml = true
		} else {
			mInf.IsInlineEmbedd = true
		} //end if else
	} else if(mInf.Disposition == MIME_MAIL_DISPOSITION_ATTACHMENT) {
		mInf.IsAttachment = true
	} //end if else
	//--
	return mInf
	//--
} //END FUNCTION


//-----


func decodeMimePart(part *multipart.Part) MimeDecodedPart {
	//--
	defer PanicHandler()
	//--
	// IMPORTANT: if decodedPart.Error != nil, the content decoding had failed and the content is not decoded, and was preserved for debugging purposes
	//--
	decodedPart := MimeDecodedPart{
		Error: nil, 					// reset
		Warnings: []string{}, 			// init
		Index: -1, 						// this will be updated in the parent method
		PartNum: -1, 					// this will be updated in the parent method
		MetaInfo: MimePartMetaInfo{}, 	// this will be updated in the parent method
		Headers: nil, 					// this will be populated later in the parent method
		Encoding: "", 					// reset
		Content: nil, 					// reset
	}
	//--
	if(part == nil) {
		decodedPart.Error = NewError("MIME Part Data is Null")
		return decodedPart
	} //end if
	//--
	partData, err := io.ReadAll(part) // Read the data for this MIME part
	if(err != nil) {
		decodedPart.Error = NewError("Failed to Read MIME Part Data: " + err.Error())
		return decodedPart
	} //end if
	if((partData == nil) || (len(partData) <= 0)) {
		return decodedPart // part is empty, nothing to decode, no error
	} //end if
	//--
	var strContentLen string = conformMimeHeaderSpecialValue(part.Header.Get(MIME_HEADER_KEY_CONTENT_LENGTH))
	var theContentLen int64 = ParseStrAsInt64(strContentLen)
	if(theContentLen > 0) {
		var actualCLen int64 = int64(len(partData))
		if(actualCLen != theContentLen) {
			decodedPart.Warnings = append(decodedPart.Warnings, "Content Length does not match, expecting: `" + strContentLen + "` bytes as " + ConvertInt64ToStr(theContentLen) + ", but having: " + ConvertInt64ToStr(actualCLen))
		} else {
			if(MIME_DEBUG) {
				log.Println("[DEBUG]", CurrentFunctionName(), "Content Length Verification OK")
			} //end if
		} //end if else
	} //end if
	//--
	decodedPart.Encoding = StrToUpper(conformMimeHeaderSpecialValue(part.Header.Get(MIME_HEADER_KEY_CONTENT_TRANSFER_ENCODING)))
	//--
	switch(decodedPart.Encoding) {
		case "BASE64":
			decodedPart.Content = Base64BytDecode(Base64BytNormalizeMultiLineData(partData)) // B64 data is chunked on multi-lines in emails, need normalication
			if(len(decodedPart.Content) > 0) {
				decodedPart.Decoded = true
			} else {
				decodedPart.Content = partData // reset to original, keep it for debug
				decodedPart.Error = NewError("MIME Part B64 Decode Failed, Empty after Decode")
			} //end if
			break
		case "QUOTED-PRINTABLE":
			var errQpDec error = nil
			decodedPart.Content, errQpDec = io.ReadAll(quotedprintable.NewReader(bytes.NewReader(partData)))
			if(errQpDec != nil) {
				decodedPart.Content = partData // reset to original, keep it for debug
				decodedPart.Error = NewError("MIME Part QP Decode Failed: " + errQpDec.Error())
			} else {
				if(len(decodedPart.Content) > 0) {
					decodedPart.Decoded = true
					decodedPart.Content = BytNormalizeOnlySpaces(decodedPart.Content)
					decodedPart.Content = BytNormalizeLineEndings(decodedPart.Content) // {{{SYNC-MIME-ENCODING-NORMALIZE-LINES}}}
				} else {
					decodedPart.Content = partData // reset to original, keep it for debug
					decodedPart.Error = NewError("MIME Part QP Decode Failed, Empty after Decode")
				} //end if
			} //end if
			break
		case "": fallthrough
		default:
			decodedPart.Content = partData
			if(len(decodedPart.Content) > 0) { // do not use StrTr/BytTr, they are unstable in order of replacements and here the order counts
				decodedPart.Decoded = true
				decodedPart.Content = BytNormalizeOnlySpaces(decodedPart.Content)
				decodedPart.Content = BytNormalizeLineEndings(decodedPart.Content) // {{{SYNC-MIME-ENCODING-NORMALIZE-LINES}}}
			} else {
				decodedPart.Content = partData // reset to original, keep it for debug
				decodedPart.Error = NewError("MIME Part NO Decode Failed, Empty")
			} //end if
	} //end switch
	//--
	if(decodedPart.Decoded == true) {
		//-- crc64e (unencoded) support
		var theCrc64eHdrVal string = StrToLower(conformMimeHeaderSpecialValue(part.Header.Get(MIME_HEADER_KEY_CONTENT_CRC64E)))
		if(theCrc64eHdrVal != "") {
			var crc64eByt = string(CrcByt64e(decodedPart.Content))
			if(crc64eByt != theCrc64eHdrVal) {
				decodedPart.Warnings = append(decodedPart.Warnings, "Decoded Content CRC64e Failed, expecting: `" + theCrc64eHdrVal + "`, but having: `" + crc64eByt + "`")
			} else {
				if(MIME_DEBUG) {
					log.Println("[DEBUG]", CurrentFunctionName(), "Content CRC64e Verification OK")
				} //end if
			} //end if else
		} //end if
		//-- checksum (unencoded) digest support, standard, modern
		var theDigestHdrVal string = conformMimeHeaderValue(part.Header.Get(MIME_HEADER_KEY_CONTENT_CHECKSUMS_DIGEST))
		checksumsDigest := ParseContentDigestHeaderVal(theDigestHdrVal)
		digestPassed, digestWarnings := VerifyContentDigestChecksums(decodedPart.Content, checksumsDigest)
		if(MIME_DEBUG) {
			if(len(digestPassed) > 0) {
				for pk, pv := range digestPassed {
					log.Println("[DEBUG]", CurrentFunctionName(), "Digest Verification OK: #" + ConvertIntToStr(pk) + " " + pv)
				} //end for
			} //end if
		} //end if
		if(len(digestWarnings) > 0) {
			for wk, wv := range digestWarnings {
				decodedPart.Warnings = append(decodedPart.Warnings, "#" + ConvertIntToStr(wk) + " " + wv)
			} //end for
		} //end if
		if(len(theDigestHdrVal) > 0) {
			if(len(digestPassed) <= 0) {
				decodedPart.Warnings = append(decodedPart.Warnings, "Digest Check not passed or is unsupported")
			} else if(len(digestPassed) != len(checksumsDigest)) {
				decodedPart.Warnings = append(decodedPart.Warnings, "Digest Check Failed, some checksums did not match")
			} //end if
		} //end if
		//-- legacy support, smart mailer
		checksumSha1 := StrToLower(conformMimeHeaderSpecialValue(part.Header.Get(MIME_HEADER_KEY_CONTENT_CHECKSUM_SHA1))) // make it hex lowercase
		if(len(checksumSha1) == 40) { // be sure is hex and not b64
			var sha1Sum string = string(ShaByt1(decodedPart.Content))
			if(sha1Sum != checksumSha1) {
				decodedPart.Warnings = append(decodedPart.Warnings, "Decoded Content Checksum SHA1 Failed, expecting: `" + checksumSha1 + "`, but having: `" + sha1Sum + "`")
			} else {
				if(MIME_DEBUG) {
					log.Println("[DEBUG]", CurrentFunctionName(), "Content Checksum Verification OK:", "sha1")
				} //end if
			} //end if else
		} //end if
		//-- obsolete support, standard
		checksumMd5  := StrToLower(conformMimeHeaderSpecialValue(part.Header.Get(MIME_HEADER_KEY_CONTENT_CHECKSUM_MD5))) // make it hex lowercase
		if(len(checksumMd5) == 32) { // be sure is hex and not b64
			var md5Sum string = string(MdByt5(decodedPart.Content))
			if(md5Sum != checksumMd5) {
				decodedPart.Warnings = append(decodedPart.Warnings, "Decoded Content Checksum MD5 Failed, expecting: `" + checksumMd5 + "`, but having: `" + md5Sum + "`")
			} else {
				if(MIME_DEBUG) {
					log.Println("[DEBUG]", CurrentFunctionName(), "Content Checksum Verification OK:", "md5")
				} //end if
			} //end if else
		} //end if
		//--
	} //end if
	//--
	return decodedPart
	//--
} //END FUNCTION


//-----


// Parses the MIME part from mimeData, each part being separated by
// boundary. If one of the part read is itself a multipart MIME part, the
// function calls itself to recursively parse all the parts. The parts read
// are decoded and written to separate files, named uppon their Content-Descrption
// (or boundary if no Content-Description available) with the appropriate
// file extension. Index is incremented at each recursive level and is used in
// building the filename where the part is written, as to ensure all filenames
// are distinct.
func parseMimePart(mimeData io.Reader, boundary string, index int, decodedParts []MimeDecodedPart, warnings []MimeParseWarning) (bool, []MimeDecodedPart, []MimeParseWarning, error) {
	//--
	defer PanicHandler()
	//--
	var isMPAlt bool = false
	if(decodedParts == nil) {
		decodedParts = []MimeDecodedPart{}
	} //end if
	if(warnings == nil) {
		warnings = []MimeParseWarning{}
	} //end if
	//--
	if(index < 1) {
		return isMPAlt, decodedParts, warnings, NewError("Part #" + ConvertIntToStr(index) + " " + "MIME internal Index is Zero or Negative: BREAK STOP")
	} else if(index > 255) { // protect against infinite loop ; most email systems disallow more than 100 parts so 255 is a fair limit
		return isMPAlt, decodedParts, warnings, NewError("Part #" + ConvertIntToStr(index) + " " + "MIME Index is > 255, Oversized: BREAK STOP")
	} //end if else
	//--
	if(mimeData == nil) {
		return isMPAlt, decodedParts, warnings, NewError("Part #" + ConvertIntToStr(index) + " " + "MIME Data is Null")
	} //end if
	//-- Instantiate a new io.Reader dedicated to MIME multipart parsing using multipart.NewReader()
	reader := multipart.NewReader(mimeData, boundary)
	if(reader == nil) {
		return isMPAlt, decodedParts, warnings, NewError("Part #" + ConvertIntToStr(index) + " " + "MultiPart Reader is Null")
	} //end if
	//-- Loop through each of the MIME part of the message Body with NextPart(), and read the content of the MIME part with io.ReadAll()
	var partNum int = 0
	for {
		//--
		partNum++
		//--
		newPart, err := reader.NextRawPart() // need this, it does not do auto decoding of QP !
		if(err == io.EOF) {
			break
		} //end if
		if(err != nil) {
			warnings = append(warnings, MimeParseWarning{
				Index: index,
				PartNum: partNum,
				Warning: "Failed to parse the MIME Part, ERR: " + err.Error(),
			})
			continue
		} //end if
		//--
		if(len(newPart.Header) <= 0) {
			warnings = append(warnings, MimeParseWarning{
				Index: index,
				PartNum: partNum,
				Warning: "Failed to parse the MIME Part, Headers are Empty",
			})
			continue
		} //end if
		//--
		conformedPartHeaders := map[string][]string{}
		for key, value := range newPart.Header {
			if(len(value) > 0) {
				for kk, vv := range value {
					value[kk] = StrTrimWhitespaces(StrTrim(StrTrimWhitespaces(vv), ";")) // fix: mime parser does not trim on right the `;` and will have `inline;`, so fix this by trim on right ..., but just in case also trim on left !
				} //end for
			} else {
				value = []string{} // make sure is not nil
			} //end if
			conformedPartHeaders[key] = value // write back with the fixed ones
		} //end for
		//--
		arrCType := ParseContentTypeHeaderVal(newPart.Header.Get(MIME_HEADER_KEY_CONTENT_TYPE))
		if(len(arrCType) <= 0) {
			arrCType = map[string]string{} // be sure is not nil !
		} //end if
		mediaType, okMediaType := arrCType[MIME_PARSER_CONTENT_TYPE_KEY]
		if(!okMediaType) {
			mediaType = "" // safe reset in case of error
		} //end if
		mediaType = StrToLower(StrTrimWhitespaces(mediaType))
		if(mediaType == "") {
			//--
			warnings = append(warnings, MimeParseWarning{
				Index: index,
				PartNum: partNum,
				Warning: "MIME Message Part Content-Type is empty or missing or could not be parsed",
			})
			//--
		} else {
			//--
			if(StrStartsWith(mediaType, MIME_MESSAGE_MULTIPART_TYPE_PREFIX) == true) {
				//--
				if(StrToLower(StrTrimWhitespaces(mediaType)) == (MIME_MESSAGE_MULTIPART_TYPE_PREFIX + "alternative")) {
					isMPAlt = true
				} //end if
				//--
				partBoundary, okPartBoundary := arrCType[MIME_PARSER_CONTENT_BOUNDARY_KEY]
				if(!okPartBoundary) {
					warnings = append(warnings, MimeParseWarning{
						Index: index,
						PartNum: partNum,
						Warning: "MIME Message Part Boundary was not detected or is missing",
					})
				} else {
					partBoundary = StrTrimWhitespaces(partBoundary) // do not make lowercase, is case sensitive
					if(partBoundary == "") {
						warnings = append(warnings, MimeParseWarning{
							Index: index,
							PartNum: partNum,
							Warning: "MIME Message Part Boundary is empty",
						})
					} else {
						var decErr error = nil
						var isMsPAlt bool = false
						isMsPAlt, decodedParts, warnings, decErr = parseMimePart(newPart, partBoundary, index + 1, decodedParts, warnings)
						if(decErr != nil) {
							return isMPAlt, decodedParts, warnings, decErr
						} //end if
						if(isMsPAlt == true) {
							isMPAlt = true
						} //end if
					} //end if else
				} //end if else
				//--
			} else {
				//--
				mInf := getMimePartMetaInfo(newPart, boundary, partNum)
				//--
				mInf.FileName = StrTrimWhitespaces(mInf.FileName)
				mInf.Disposition = StrToUpper(StrTrimWhitespaces(mInf.Disposition))
				mInf.Charset = StrToUpper(StrTrimWhitespaces(mInf.Charset))
				//--
				decPart := decodeMimePart(newPart)
				if(decPart.Error != nil) {
					warnings = append(warnings, MimeParseWarning{
						Index: index,
						PartNum: partNum,
						Warning: "Mime Part Decoding FAILED ; Encoding: `" + decPart.Encoding + "` # Error: " + decPart.Error.Error(),
					})
				} //end if
				if(len(decPart.Warnings) > 0) {
					for _, warn := range decPart.Warnings {
						warn = StrTrimWhitespaces(warn)
						if(warn != "") {
							warnings = append(warnings, MimeParseWarning{
								Index: index,
								PartNum: partNum,
								Warning: "Mime Part Decoding Warning: " + warn,
							})
						} //end if
					} //end for
				} //end if
				//--
				decPart.Index = index
				decPart.PartNum = partNum
				decPart.MetaInfo = mInf
				decPart.Headers = conformedPartHeaders
				//--
				decodedParts = append(decodedParts, decPart)
				//--
			} //end if else
			//--
		} //end if else
		//--
	} //end for
	//--
	return isMPAlt, decodedParts, warnings, nil
	//--
} //END FUNCTION


//-----


// #END
