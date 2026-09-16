
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE
// [ MIME ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"log"

	"mime"
	"net/textproto"
)

const ( // DO NOT CHANGE any of these
	MIME_MESSAGE_MULTIPART_TYPE_PREFIX 			string = "multipart/"

	MIME_MESSAGE_PART_MIMETYPE_TEXT 			string = "text/plain"
	MIME_MESSAGE_PART_MIMETYPE_HTML 			string = "text/html"

	MIME_HEADER_KEY_DKIM_SIGNATURE 				string = "Dkim-Signature" // DO NOT CHANGE, it is synced with DKIM signer and also this is the only standard key allowed for this purpose
	MIME_HEADER_KEY_DKIM_PUBKEY 				string = "X-Dkim-Public-Key" // DO NOT CHANGE, it is a special key used internally by the smart Mime Composer ; will be used to append the DKIM public key to the message if DKIM is used

	MIME_HEADER_KEY_MIME_VERSION 				string = "Mime-Version"
	MIME_HEADER_KEY_MESSAGE_ID 					string = "Message-Id"
	MIME_HEADER_KEY_CONTENT_ID 					string = "Content-Id"
	MIME_HEADER_KEY_CONTENT_TYPE 				string = "Content-Type"
	MIME_HEADER_KEY_CONTENT_DISPOSITION 		string = "Content-Disposition"
	MIME_HEADER_KEY_CONTENT_TRANSFER_ENCODING 	string = "Content-Transfer-Encoding"
	MIME_HEADER_KEY_CONTENT_LENGTH 				string = "Content-Length"
	MIME_HEADER_KEY_CONTENT_CRC64E 				string = "X-Unencoded-Crc64e" // {{{SYNC-CONTENT-CRC64E-UNENCODED}}} ; do not change ; synced with the mailer.Message (smart) composer and intended to be supported just for the smart composer composed messages
	MIME_HEADER_KEY_CONTENT_CHECKSUMS_DIGEST 	string = "Unencoded-Digest"   // {{{SYNC-CONTENT-DIGEST-UNENCODED}}} ; do not change ; synced with the mailer.Message (smart) composer and intended to be supported just for the smart composer composed messages
	MIME_HEADER_KEY_CONTENT_CHECKSUM_SHA1 		string = "Content-Decoded-Checksum-Sha1" // synced with the mailer.Message (smart) composer and intended to be supported just for the smart composer composed messages, legacy support for older versions of mime composer
	MIME_HEADER_KEY_CONTENT_CHECKSUM_MD5 		string = "Content-Decoded-Checksum-Md5"  // synced with the mailer.Message (smart) composer and intended to be supported just for the smart composer composed messages, obsolete support for very old versions of mime composer

	MIME_HEADER_KEY_RETURN_PATH 				string = "Return-Path"
	MIME_HEADER_KEY_FROM 						string = "From"
	MIME_HEADER_KEY_TO 							string = "To"
	MIME_HEADER_KEY_CC 							string = "Cc"
	MIME_HEADER_KEY_BCC 						string = "Bcc"
	MIME_HEADER_KEY_DATE 						string = "Date"
	MIME_HEADER_KEY_SUBJECT 					string = "Subject"

	MIME_HEADER_VAL_VERSION_ONE 				string = "MIME-Version: 1.0" // DO NOT CHANGE, this is STANDARD ; it is also synced with the mailer.Message (smart) composer ; it is also used by the Mime Message Epilogue Parser !

	MIME_PARSER_CONTENT_BOUNDARY_KEY 			string = "boundary"
	MIME_PARSER_CONTENT_CHARSET_KEY 			string = "charset"
	MIME_PARSER_CONTENT_NAME_KEY 				string = "name"
	MIME_PARSER_CONTENT_FILENAME_KEY 			string = "filename"

	MIME_MAIL_DISPOSITION_INLINE 				string = "INLINE"
	MIME_MAIL_DISPOSITION_ATTACHMENT 			string = "ATTACHMENT"

	MIME_ID_ENCLOSURE_START 					string = "<"
	MIME_ID_ENCLOSURE_END 						string = ">"

	MIME_PARSER_CONTENT_TYPE_KEY 				string = "=type=" // do not change, this is a special key for internal parsing, that is crafted to avoid mixture with real valid keys

	MIME_MESSAGE_UXM_SEAL_KEY 					string = "MimeMessage-Seal"
	MIME_MESSAGE_UXM_SEAL_TYPE 					string = "EcDSA/P-521+SHA3-512"
)


//-----

/*
func StrMimeChunkLen(body string, chunklen uint, end string) string {
	//--
	if(len(body) <= chunklen) {
		return body
	} //end if
	//--
	firstLine = StrSubstr(bodym 0, chunklen)
	//--
	StrChunkSplit(body string, chunklen uint, end string)
	//--
} //END FUNCTION
*/

//-----


func ParseEmailAddress(a string) (string, string, error) {
	//--
	a = StrToLower(StrTrimWhitespaces(a))
	if(a == "") {
		return "", "", NewError("Email Address is empty")
	} //end if
	//--
	if(!StrContains(a, "@")) {
		return "", "", NewError("Email Address is missing the @ separator")
	} //end if
	//--
	arr := ExplodeWithLimit("@", a, 2)
	if(len(arr) != 2) {
		return "", "", NewError("Email Address separation failed")
	} //end if
	arr[0] = StrTrimWhitespaces(arr[0])
	arr[1] = StrTrimWhitespaces(arr[1])
	if((arr[0] == "") || (arr[1] == "")) {
		return "", "", NewError("Email Address separation failed, at least one part is empty")
	} //end if
	//--
	return arr[0], arr[1], nil
	//--
} //END FUNCTION


//-----


func ConformHeaderKeyName(hdrKey string) string {
	//--
	hdrKey = StrTrimWhitespaces(hdrKey)
	if(hdrKey == "") {
		return ""
	} //end if
	//--
	return textproto.CanonicalMIMEHeaderKey(hdrKey)
	//--
} //END FUNCTION


//-----


func ParseMediaTypeHeaderVal(hdrVal string) (string, map[string]string, error)  {
	//--
	defer PanicHandler()
	//--
	hdrVal = StrTrimWhitespaces(hdrVal)
	if(hdrVal == "") {
		return "", nil, NewError("Media Content Type Value is Empty")
	} //end if
	//--
	return mime.ParseMediaType(hdrVal)
	//--
} //END FUNCTION


//-----


func ParseContentTypeHeaderVal(hdrVal string) map[string]string {
	//--
	// this is a flexible parser for HTTP or MIME
	// see below, the ex2 will fail by normal parser because boundary contains reserved characters and not being enclosed in double quotes:
	// ex1: `Content-Type: multipart/mixed; boundary="_Smart-Mail=X=00000000000000023565846642565310385WFTZZNMOUQ_"` 	# standard
	// ex2: `Content-Type: multipart/mixed; boundary=_Smart-Mail=X=00000000000000023565846642565310385WFTZZNMOUQ_` 		# non-standard, fixed
	// ex3: `Content-Type: text/plain; charset="UTF-8"`
	// ex4: `Content-Type: text/html; charset=UTF-8`
	// ex5: `Content-Type: image/svg+xml; name="email-embed.svg"`
	//--
	// the content type will be returned as a special key: `=type=` ; the rest of params will be returned as they are (lowercase keys)
	//--
	defer PanicHandler()
	//--
	params := map[string]string{}
	//--
	hdrVal = StrTrimWhitespaces(hdrVal)
	if(hdrVal == "") {
		return params
	} //end if
	//--
	mediaType, mediaParams, errParse := mime.ParseMediaType(hdrVal) // 1st try to parse as standard and if successful return
	if(errParse == nil) {
		//--
		if(len(mediaParams) > 0) {
			for k, v := range mediaParams {
				k = StrToLower(StrTrimWhitespaces(k))
				if(k != "") {
					params[k] = StrTrimWhitespaces(v) // do not make lowercase, values here are case sensitive
				} //end if
			} //end for
		} //end if
		//--
		params[MIME_PARSER_CONTENT_TYPE_KEY] = StrToLower(StrTrimWhitespaces(mediaType)) // add at the end to be sure is not being rewritten by another mediaParams
		//--
		return params
		//--
	} //end if
	//--
	if(DEBUG) {
		log.Println("[DEBUG]", CurrentFunctionName(), "Content Type standard Parser Failed, fall back to custom parser trying to fix this ; Parse Err:", errParse)
	} //end if
	//--
	arr := Explode(";", hdrVal)
	if(len(arr) > 0) {
		mediaType = StrToLower(StrTrimWhitespaces(arr[0]))
		if(mediaType != "") {
			if(len(arr) > 1) {
				for k, v := range arr {
					if(k > 0) {
						v = StrTrimWhitespaces(v)
						if(v != "") {
							if(StrContains(v, "=") == true) {
								arrV := ExplodeWithLimit("=", v, 2)
								if(len(arrV) == 2) {
									arrV[0] = StrToLower(StrTrimWhitespaces(arrV[0]))
									if(arrV[0] != "") {
										arrV[1] = StrTr(arrV[1], map[string]string{ // fix if split on multi lines
											"\r\n ": " ",
											"\r ": " ",
											"\n ": " ",
										})
										arrV[1] = StrNormalizeSpaces(arrV[1]) 											// normalize spaces ; but maybe the value contains a space so can't replace spaces with nothing, above replacements should be fixed already the content
										arrV[1] = StrTrimWhitespaces(StrTrim(StrTrimWhitespaces(arrV[1]), `"`)) // do not make lowercase, values here are case sensitive ; trim double quotes just in case if it is enclosed in
										if(arrV[1] != "") {
											params[arrV[0]] = arrV[1] // do not register unless is a non-empty value
										} //end if
									} //end if
								} //end if
							} //end if
						} //end if
					} //end if
				} //end for
			} //end if
			params[MIME_PARSER_CONTENT_TYPE_KEY] = mediaType
		} //end if
	} //end if
	//--
	return params
	//--
} //END FUNCTION


//-----


func ParseContentDigestHeaderVal(hdrVal string) map[string]string {
	//--
	// this is a flexible parser for HTTP or MIME
	// see below, the `Content-Digest:` values can be as:
	// ex1: `sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:`
	// ex2: `sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:, sha-512=:YMAam51Jz/jOATT6/zvHrLVgOYTGFy1d6GJiOHTohq4yP+pgk4vf2aCsyRZOtw8MjkM7iw7yZ/WkppmM44T3qg==:`
	//--
	defer PanicHandler()
	//--
	params := map[string]string{}
	//--
	hdrVal = StrTrimWhitespaces(hdrVal)
	if(hdrVal == "") {
		return params
	} //end if
	//--
	arr := Explode(",", hdrVal)
	if(len(arr) > 0) {
		for _, part := range arr {
			part = StrTrimWhitespaces(part)
			pArr := ExplodeWithLimit("=", part, 2) // explode with limit, content after is B64 and may contanin =
			if(len(pArr) == 2) {
				pArr[0] = StrToLower(StrTrimWhitespaces(pArr[0])) 							// key such as `sha-256`
				pArr[1] = StrNormalizeSpaces(pArr[1]) 										// normalize spaces, maybe is split on multi lines ; since we expect a B64 string there will be no gap spaces, here is safe to do this
				pArr[1] = StrReplaceAll(pArr[1], " ", "") 									// concatenate parts if was split on multi lines ; since we expect a B64 string there will be no gap spaces, here is safe to do this
				pArr[1] = StrTrimWhitespaces(StrTrim(StrTrimWhitespaces(pArr[1]), ":")) 	// the B64 Part, enclosed between `:` ; do not make lowercase, B64 is case-sensitive
				switch(pArr[0]) {
					case "md5": 		fallthrough // obsolete support
					case "sha1": 		fallthrough // legacy support
					case "sha-224": 	fallthrough
					case "sha-256": 	fallthrough
					case "sha-384": 	fallthrough
					case "sha-512": 	fallthrough
					case "sha3-224": 	fallthrough
					case "sha3-256": 	fallthrough
					case "sha3-384": 	fallthrough
					case "sha3-512":
						if((pArr[1] != "") && (StrRegexMatch(REGEX_SAFE_B64_STR, pArr[1]))) {
							params[pArr[0]] = pArr[1]
						} else {
							if(DEBUG) {
								log.Println("[DEBUG]", CurrentFunctionName(), "Unsupported Format (Not B64) for Algorithm:", pArr[0], "=", pArr[1])
							} //end if
						} //end if else
						break
					default: // unsupported
						if(DEBUG) {
							log.Println("[DEBUG]", CurrentFunctionName(), "Unsupported Algorithm:", pArr[0], "=", pArr[1])
						} //end if
				} //end switch
			} //end if
		} //end for
	} //end if
	//--
	return params
	//--
} //END FUNCTION


func VerifyContentDigestChecksums(decodedBytPart []byte, checksumsDigest map[string]string) ([]string, []string) {
	//--
	// this method will verify the checksums provided by the above method: ParseContentDigestHeaderVal
	//--
	defer PanicHandler()
	//--
	var passed   []string = []string{}
	var warnings []string = []string{}
	//--
	if(decodedBytPart == nil) {
		decodedBytPart = []byte{} // make sure is not null
	} //end if
	//--
	if(len(checksumsDigest) > 0) {
		for kk, vv := range checksumsDigest {
			switch(kk) {
				case "md5": // obsolete support
					var md5B64Sum string = string(MdByt5B64(decodedBytPart))
					if(md5B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + md5B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha1": // legacy support
					var sha1B64Sum string = string(ShaByt1B64(decodedBytPart))
					if(sha1B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sha1B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha-224":
					var sha224B64Sum string = string(ShaByt224B64(decodedBytPart))
					if(sha224B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sha224B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha-256":
					var sha256B64Sum string = string(ShaByt256B64(decodedBytPart))
					if(sha256B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sha256B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha-384":
					var sha384B64Sum string = string(ShaByt384B64(decodedBytPart))
					if(sha384B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sha384B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha-512":
					var sha512B64Sum string = string(ShaByt512B64(decodedBytPart))
					if(sha512B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sha512B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha3-224":
					var sh3a224B64Sum string = string(Sh3aByt224B64(decodedBytPart))
					if(sh3a224B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sh3a224B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha3-256":
					var sh3a256B64Sum string = string(Sh3aByt256B64(decodedBytPart))
					if(sh3a256B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sh3a256B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha3-384":
					var sh3a384B64Sum string = string(Sh3aByt384B64(decodedBytPart))
					if(sh3a384B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sh3a384B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				case "sha3-512":
					var sh3a512B64Sum string = string(Sh3aByt512B64(decodedBytPart))
					if(sh3a512B64Sum != vv) {
						warnings = append(warnings, "Content Digest Checksum `" + kk + "` Failed, expecting: `" + vv + "`, but having: `" + sh3a512B64Sum + "`")
					} else {
						passed = append(passed, "Content Digest Checksum `" + kk + "` Passed: " + vv)
					} //end if else
					break
				default:
					if(DEBUG) {
						log.Println("[DEBUG]", CurrentFunctionName(), "Unsupported Digest Type:", kk, "with Digest:", vv)
					} //end if
			} //end switch
		} //end if
	} else {
		if(DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "No Digest Checksums provided")
		} //end if
	} //end if else
	//--
	return passed, warnings
	//--
} //END FUNCTION


//-----


var (
	mimeTypesRegistered bool = false // DO NOT CHANGE, this is handled by the registerMimeTypes() method
)

func registerMimeTypes() { // register mime types from below
	//--
	defer PanicHandler()
	//--
	if(mimeTypesRegistered == true) {
		log.Println("[FAIL]", CurrentFunctionName(), "MimeTypes already registered !")
		return
	} //end if
	mimeTypesRegistered = true
	//--
	var mimeTypes map[string]string = map[string]string{ // {{{SYNC-SMARTGO-MIME-TYPES}}} ; the list with the well known mime types
		//-- go:mime-types ; below mimes are taken from go 1.24.13, src/mime/type.go
		".avif": 		"image/avif",
		".css": 		"text/css; charset=utf-8",
		".gif": 		"image/gif",
		".htm": 		"text/html; charset=utf-8",
		".html": 		"text/html; charset=utf-8",
		".jpeg": 		"image/jpeg",
		".jpg": 		"image/jpeg",
		".js": 			"text/javascript; charset=utf-8",
		".json": 		"application/json; charset=utf-8",
		".mjs": 		"text/javascript; charset=utf-8",
		".pdf": 		"application/pdf",
		".png": 		"image/png",
		".svg": 		"image/svg+xml",
		".wasm": 		"application/wasm",
		".webp": 		"image/webp",
		".xml": 		"text/xml; charset=utf-8",
		//-- #end:go:mime-types
		// #
		//-- #php:mime-types ; below mimes are taken from Smart.Framework.PHP
		".http": 		"message/http; charset=utf-8", // http message includding header and body
		".httph": 		"message/http; charset=utf-8", // http header ; required by method TRACE
		//--
		".ts": 			"application/x-typescript; charset=utf-8",
		".tsx": 		"application/x-typescript; charset=utf-8",
		//--
		".readme": 		"text/plain; charset=utf-8",
		".txt": 		"text/plain; charset=utf-8",
		".text": 		"text/plain; charset=utf-8",
		".vtt": 		"text/vtt; charset=utf-8",
		//--
		".mtpl": 		"text/html; charset=utf-8",
		".tpl": 		"text/html; charset=utf-8",
		".shtml": 		"text/html; charset=utf-8",
		//--
		".woff2": 		"application/x-font-woff2",
		".woff": 		"application/x-font-woff",
		".ttf": 		"application/x-font-ttf",
		//--
		".rdf": 		"application/rdf+xml; charset=utf-8",
		".rss": 		"application/rss+xml; charset=utf-8",
		".atom": 		"application/atom+xml; charset=utf-8",
		//--
		".eml": 		"message/rfc822",
		".ics": 		"text/calendar; charset=utf-8",
		".vcf": 		"text/vcard; charset=utf-8",
		".vcs": 		"text/x-vcalendar; charset=utf-8",
		".vcard": 		"text/x-vcard; charset=utf-8",
		".ldif": 		"text/ldif",
		//--
		".tar": 		"application/x-tar",
		".zstd": 		"application/zstd",
		".gz": 			"application/gzip",
		".xz": 			"application/x-xz",
		".lz4": 		"application/x-lz4",
		".sz": 			"application/x-snappy-framed",
		".bz2": 		"application/x-bzip2",
		".z": 			"application/x-compress",
		".tgz": 		"application/x-compressed",
		".tbz": 		"application/x-compressed",
		".rar": 		"application/x-rar-compressed",
		".7z": 			"application/x-7z-compressed",
		".zip": 		"application/zip",
		//--
		".csv": 		"text/csv; charset=utf-8",
		".tab": 		"text/csv; charset=utf-8",
		//--
		".ico": 		"image/vnd.microsoft.icon",
		".apng": 		"image/apng",
		".jpe": 		"image/jpeg",
		".pjp": 		"image/jpeg",
		".pjpeg": 		"image/jpeg",
		".jfif": 		"image/jpeg",
		".tif": 		"image/tiff",
		".tiff": 		"image/tiff",
		".bmp": 		"image/bmp",
		".xbm": 		"image/x-xbitmap",
		".psd": 		"image/x-xcf", // gimp, photoshop
		".xcf": 		"image/x-xcf", // gimp
		//--
		".weba": 		"audio/webm",
		".oga": 		"audio/ogg",
		".ogg": 		"audio/ogg",
		".opus": 		"audio/ogg",
		".m4a": 		"audio/mp4",
		".mpga": 		"audio/mpeg",
		".mp3": 		"audio/mpeg",
		".mp2": 		"audio/mpeg",
		".flac": 		"audio/flac",
		".wav": 		"audio/wav",
		//--
		".webm": 		"video/webm",
		".ogv": 		"video/ogg",
		".mp4": 		"video/mp4",
		".mpeg": 		"video/mpeg",
		".mpg": 		"video/mpeg",
		".mpe": 		"video/mpeg",
		".mpv": 		"video/mpeg",
		".mov": 		"video/quicktime",
		".qt": 			"video/quicktime",
		".avi": 		"video/x-msvideo",
		//--
		".xfdf": 		"application/vnd.adobe.xfdf",
		".epub": 		"application/epub+zip",
		//--
		".rtf": 		"application/rtf",
		".abw": 		"application/x-abiword",
		".otc": 		"application/vnd.oasis.opendocument.chart-template",
		".odc": 		"application/vnd.oasis.opendocument.chart",
		".otf": 		"application/vnd.oasis.opendocument.formula-template",
		".odf": 		"application/vnd.oasis.opendocument.formula",
		".sxm": 		"application/vnd.oasis.opendocument.formula",
		".otg": 		"application/vnd.oasis.opendocument.graphics-template",
		".odg": 		"application/vnd.oasis.opendocument.graphics",
		".fodg": 		"application/vnd.oasis.opendocument.graphics",
		".sxd": 		"application/vnd.oasis.opendocument.graphics",
		".oti": 		"application/vnd.oasis.opendocument.image-template",
		".odi": 		"application/vnd.oasis.opendocument.image",
		".otp": 		"application/vnd.oasis.opendocument.presentation-template",
		".sti": 		"application/vnd.oasis.opendocument.presentation-template",
		".odp": 		"application/vnd.oasis.opendocument.presentation",
		".fodp": 		"application/vnd.oasis.opendocument.presentation",
		".sxi": 		"application/vnd.oasis.opendocument.presentation",
		".ots": 		"application/vnd.oasis.opendocument.spreadsheet-template",
		".stc": 		"application/vnd.oasis.opendocument.spreadsheet-template",
		".ods": 		"application/vnd.oasis.opendocument.spreadsheet",
		".fods": 		"application/vnd.oasis.opendocument.spreadsheet",
		".sxc": 		"application/vnd.oasis.opendocument.spreadsheet",
		".ott": 		"application/vnd.oasis.opendocument.text-template",
		".stw": 		"application/vnd.oasis.opendocument.text-template",
		".odt": 		"application/vnd.oasis.opendocument.text",
		".fodt": 		"application/vnd.oasis.opendocument.text",
		".sxw": 		"application/vnd.oasis.opendocument.text",
		".otm": 		"application/vnd.oasis.opendocument.text-master",
		".oth": 		"application/vnd.oasis.opendocument.text-web",
		".odb": 		"application/vnd.oasis.opendocument.database",
		".dot": 		"application/msword",
		".doc": 		"application/msword",
		".docx": 		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xlt": 		"application/vnd.ms-excel",
		".xlw": 		"application/vnd.ms-excel",
		".xls": 		"application/vnd.ms-excel",
		".xlm": 		"application/vnd.ms-excel",
		".xlc": 		"application/vnd.ms-excel",
		".xla": 		"application/vnd.ms-excel",
		".xltx": 		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".xlsx": 		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".pot": 		"application/vnd.ms-powerpoint",
		".pps": 		"application/vnd.ms-powerpoint",
		".ppt": 		"application/vnd.ms-powerpoint",
		".potx": 		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".ppsx": 		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".pptx": 		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".mdb": 		"application/x-msaccess",
		//--
		".ps": 			"application/postscript",
		".eps": 		"application/postscript",
		".ai": 			"application/postscript",
		//--
		".pem": 		"application/x-pem-file",
		".asc": 		"application/pgp-signature",
		".sig": 		"application/pgp-signature",
		".pub": 		"text/plain",
		//--
		".ini": 		"text/plain; charset=utf-8",
		".yml": 		"text/x-yaml; charset=utf-8",
		".yaml": 		"text/x-yaml; charset=utf-8",
		".md": 			"text/markdown; charset=utf-8",
		".markdown":	"text/markdown; charset=utf-8",
		//--
		".cf": 			"text/plain; charset=utf-8",
		".cfg": 		"text/plain; charset=utf-8",
		".conf": 		"text/plain; charset=utf-8",
		".config": 		"text/plain; charset=utf-8",
		".inf": 		"text/plain; charset=utf-8",
		".inc": 		"text/plain; charset=utf-8",
		//--
		".openscad": 	"text/plain",
		".jscad": 		"text/plain",
		".scad": 		"text/plain",
		".stl": 		"text/plain",
		".obj": 		"text/plain",
		//--
		".xbl": 		"text/xml; charset=utf-8",
		".xht": 		"application/xhtml+xml; charset=utf-8",
		".xhtml": 		"application/xhtml+xml; charset=utf-8",
		".xsl": 		"text/xml; charset=utf-8",
		".dtd": 		"application/xml; charset=utf-8",
		".glade": 		"application/xml; charset=utf-8",
		//--
		".diff": 		"text/x-diff; charset=utf-8",
		".patch": 		"text/plain; charset=utf-8",
		//--
		".php": 		"text/x-php; charset=utf-8",
		".phps": 		"text/x-php; charset=utf-8",
		".py": 			"text/x-python; charset=utf-8",
		".pl": 			"text/x-perl; charset=utf-8",
		".pm": 			"text/x-perl; charset=utf-8",
		".tcl": 		"text/plain; charset=utf-8",
		".tk": 			"text/plain; charset=utf-8",
		".m": 			"text/plain; charset=utf-8",
		".c": 			"text/plain; charset=utf-8",
		".h": 			"text/plain; charset=utf-8",
		".y": 			"text/plain; charset=utf-8",
		".f": 			"text/plain; charset=utf-8",
		".fs": 			"text/plain; charset=utf-8",
		".fsharp": 		"text/plain; charset=utf-8",
		".r": 			"text/plain; charset=utf-8",
		".d": 			"text/plain; charset=utf-8",
		".csharp": 		"text/plain; charset=utf-8",
		".cs": 			"text/plain; charset=utf-8",
		".pro": 		"text/plain; charset=utf-8",
		".cpp": 		"text/plain; charset=utf-8",
		".hpp": 		"text/plain; charset=utf-8",
		".ypp": 		"text/plain; charset=utf-8",
		".cxx": 		"text/plain; charset=utf-8",
		".hxx": 		"text/plain; charset=utf-8",
		".yxx": 		"text/plain; charset=utf-8",
		".csh": 		"text/plain; charset=utf-8",
		".lua": 		"text/plain; charset=utf-8",
		".gjs": 		"text/plain; charset=utf-8",
		".toml": 		"text/plain; charset=utf-8",
		".rs": 			"text/plain; charset=utf-8",
		".vala": 		"text/plain; charset=utf-8",
		".vapi": 		"text/plain; charset=utf-8",
		".deps": 		"text/plain; charset=utf-8",
		".swift": 		"text/plain; charset=utf-8",
		".java": 		"text/plain; charset=utf-8",
		".groovy":		"text/plain; charset=utf-8",
		".gvy": 		"text/plain; charset=utf-8",
		".gy": 			"text/plain; charset=utf-8",
		".gsh": 		"text/plain; charset=utf-8",
		".kotlin": 		"text/plain; charset=utf-8",
		".kt": 			"text/plain; charset=utf-8",
		".ktm": 		"text/plain; charset=utf-8",
		".kts": 		"text/plain; charset=utf-8",
		".scala": 		"text/plain; charset=utf-8",
		".sc": 			"text/plain; charset=utf-8",
		".gradle": 		"text/plain; charset=utf-8",
		".hs": 			"text/plain; charset=utf-8",
		".lhs": 		"text/plain; charset=utf-8",
		".ocaml": 		"text/plain; charset=utf-8",
		".ml": 			"text/plain; charset=utf-8",
		".mli": 		"text/plain; charset=utf-8",
		".ss": 			"text/plain; charset=utf-8",
		".scm": 		"text/plain; charset=utf-8",
		".sld": 		"text/plain; charset=utf-8",
		".pas": 		"text/plain; charset=utf-8",
		//--
		".asm": 		"text/plain",
		".aasm": 		"text/plain",
		".masm": 		"text/plain",
		//--
		".log": 		"text/plain; charset=utf-8",
		".sh": 			"text/plain; charset=utf-8",
		".bash": 		"text/plain; charset=utf-8",
		".awk": 		"text/plain; charset=utf-8",
		".cmd": 		"text/plain; charset=utf-8",
		".bat": 		"text/plain; charset=utf-8",
		".ps1": 		"text/plain; charset=utf-8",
		".psm1": 		"text/plain; charset=utf-8",
		".psd1": 		"text/plain; charset=utf-8",
		".sql": 		"text/plain; charset=utf-8",
		//--
		".latex": 		"application/x-latex; charset=utf-8",
		".tex": 		"text/x-tex; charset=utf-8",
		".ltx": 		"text/x-tex; charset=utf-8",
		".sty": 		"text/x-tex; charset=utf-8",
		".cls": 		"text/x-tex; charset=utf-8",
		//--
		".apk": 		"application/vnd.android.package-archive",
		".pkg": 		"application/octet-stream",
		".dmg": 		"application/octet-stream",
		".bin": 		"application/octet-stream",
		".exe": 		"application/octet-stream",
		".com": 		"application/octet-stream",
		//-- #end:php:mime-types
		// #
		//-- #end:mime-types
	}
	//--
	for k, v := range mimeTypes {
		errMimeRegister := mime.AddExtensionType(k, v)
		if(errMimeRegister != nil) {
			log.Fatal("[FATAL:ERROR] " + CurrentFunctionName() + ": Failed to register a mime type: `" + k + "`: `" + v + "` # " + errMimeRegister.Error())
			return
		} else {
			if(DEBUG) {
				log.Println("[DEBUG:INIT]", CurrentFunctionName(), "MimeType registered:", k, v)
			} //end if
		} //end if else
	} //end for
	//--
} //END FUNCTION


//-----


// #END
