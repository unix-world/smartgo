
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260823.2358 :: STABLE
// [ ARCHIVERS ]

// REQUIRE: go 1.22 or later
package smartgo

import (
	"io"
	"bytes"

	"compress/flate"
)


const (
	SEPARATOR_SFZ_CHECKSUM_V1 string 		= "#CHECKSUM-SHA1#" 							// compatibility, v1
	SEPARATOR_SFZ_CHECKSUM_V2 string 		= "#CKSUM256#" 									// compatibility, v2
	SEPARATOR_SFZ_CHECKSUM_V3 string 		= "#CKSUM384V3#" 								// current, v3

	SIGNATURE_SFZ_DATA_ARCH_V1 string 		= "PHP.SF.151129/B64.ZLibRaw.HEX" 				// compatibility, v1, unarchive only
	SIGNATURE_SFZ_DATA_ARCH_V2 string 		= "SFZ.20210818/B64.ZLibRaw.hex" 				// compatibility, v2, unarchive only
	SIGNATURE_SFZ_DATA_ARCH_V3 string 		= "[SFZ.20231031/B64.ZLibRaw.hex]" 				// current, v3 ; archive + unarchive

	SIGNATURE_SNAPPY_PACK_v1   string 		= "sz1!" 										// v1
	SIGNATURE_GZIP_PACK_v1     string 		= "gz1!" 										// v1
)


//-----


// Long-Time Storage Safe Archive Format :: Archive (string) to B64/Zlib-Raw/Hex (v3 only)
func DataArchive(str string, verifyCompressed bool) (string, error) { // compress smart data archive (v3 only) ; file extension: .smart-arch
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by deflate panic handler with malformed data
	//--
	var ulen int = StrLen(str)
	if((str == "") || (ulen <= 0)) {
		return "", nil // should be no error
	} //end if
	if(uint64(ulen) > SIZE_BYTES_16M * 4) { // max 64MB ; sync with PHP
		return "", NewError("Data is too large to be Archived by this method")
	} //end if
	//-- ideas: for v4: use below Sh3a384() as hex, is better compressible ; use "'SHA384V3'" as separator, single quotes are not in B92 ; use B92 instead of B64 for final
	var chksum string = Sh3a384B64(str) // b64
	var data string = StrTrimWhitespaces(Bin2Hex(str)) + SEPARATOR_SFZ_CHECKSUM_V3 + chksum // v3
	//--
	zlCompressed, errZlCompress := ZlibCompress([]byte(data), -1, verifyCompressed)
	if(errZlCompress != nil) {
		return "", NewError("ZLib Deflated Data Failed: " + errZlCompress.Error())
	} //end if
	if(zlCompressed == nil) {
		return "", NewError("ZLib Deflated Data is Null")
	} //end if
	var arch string = string(zlCompressed)
	var alen int = len(arch)
	zlCompressed = nil // free mem
	//--
	if((arch == "") || (alen <= 0)) { // check also division by zero
		return "", NewError("ZLib Deflated Data is Empty")
	} //end if
	//--
	var ratio = float64(ulen) / float64(alen) // division by zero is checked above by (alen <= 0)
	if(ratio <= 0) {
		return "", NewError("ZLib Data Ratio is zero or negative: " + ConvertFloat64ToStr(ratio))
	} //end if
	if(ratio > 32768) { // check for this bug in ZLib {{{SYNC-GZ-ARCHIVE-ERR-CHECK}}}
		return "", NewError("ZLib Data Ratio is higher than 32768: " + ConvertFloat64ToStr(ratio))
	} //end if
	//--
	arch = StrTrimWhitespaces(Base64Encode(arch)) + LINE_FEED + SIGNATURE_SFZ_DATA_ARCH_V3 // v3
	theSgn, errSgn := dataArchCheckSign(arch)
	if(errSgn != nil) {
		return "", NewError("Package Signature Failed: " + errSgn.Error())
	} //end if
	if(StrTrimWhitespaces(theSgn) == "") {
		return "", NewError("Package Signature Failed, Empty")
	} //end if
	arch += LINE_FEED + "(" + theSgn + ")" // v3+ signature
	//--
	return arch, nil
	//--
} //END FUNCTION


func dataArchCheckSign(pak string) (string, error) { // checksum derivation for Data Archive v3 Package
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by hex2bin panic handler with malformed data
	//--
	len := ConvertIntToStr(len(pak))
	//--
	crc32b  := Crc32bB36(pak) // b36
	sh3a512 := Sh3a512B64(pak + VERTICAL_TAB + len) // b64
	sh3a384 := Sh3a384B64(sh3a512 + NULL_BYTE + pak) // b64
	sh3a256 := Sh3a256B64(pak + NULL_BYTE + sh3a384) // b64
	sh3a224 := Sh3a224B64(sh3a512 + NULL_BYTE + pak + NULL_BYTE + crc32b + NULL_BYTE + sh3a256 + NULL_BYTE + sh3a384) // b64
	//--
	hmacSh3a224, err := HashHmac("SHA3-224", len + VERTICAL_TAB + pak, sh3a224, false) // hex
	if(err != nil) {
		return "", NewError("HMAC Hash Failed: " + err.Error())
	} //end if
	hmacSh3a224 = Hex2Bin(hmacSh3a224) // do not trim binary data
	if(hmacSh3a224 == "") {
		return "", NewError("HMAC Hash Un-Hex Failed, Empty")
	} //end if
	//--
	b62Data := StrTrimWhitespaces(BaseEncode([]byte(hmacSh3a224), "b62"))
	if(b62Data == "") {
		return "", NewError("B62 Failed, Empty")
	} //end if
	//--
	return b62Data, nil
	//--
} //END FUNCTION


// Long-Time Storage Safe Archive Format :: Unarchive data (string) from B64/Zlib-Raw/Hex (v3, v2 and v1)
func DataUnarchive(str string) (string, error) { // uncompress smart data archive (v3, v2, v1) ; file extension: .smart-arch
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by gz / hex2bin panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return "", nil // should be no error
	} //end if
	//--
	if(uint64(len(str)) > SIZE_BYTES_16M * 4) { // max 64MB ; sync with PHP
		return "", NewError("Data is too large to be UnArchived by this method")
	} //end if
	//--
	if(!StrRegexMatch(REGEX_ASCII_ANDSPACE_CHARACTERS, str)) { // safety
		return "", NewError("Input Data contains Non-ASCII characters")
	} //end if
	//--
	arr := ExplodeWithLimit(LINE_FEED, str, 4) // let it be 4 not 3 ; if there is some garbage on a new line after signature ; also v3 have an extra checksum ... just let it there ...
	str = "" // free mem
	var alen int = len(arr)
	//--
	arr[0] = StrTrimWhitespaces(arr[0])
	if(arr[0] == "") {
		return "", NewError("Invalid Package Format")
	} //end if
	//--
	var versionDetected uint8 = 0
	if(alen < 2) {
		return "", NewError("Package Signature is Empty")
	} //end if
	//--
	if(alen < 3) {
		arr = append(arr, "") // fix: add missing arr[1] to avoid panic below
	} //end if
	arr[2] = StrTrimWhitespaces(arr[2])
	lenSign := len(arr[2])
	//--
	arr[1] = StrTrimWhitespaces(arr[1])
	if(arr[1] == SIGNATURE_SFZ_DATA_ARCH_V3) {
		versionDetected = 3
	} else if(arr[1] == SIGNATURE_SFZ_DATA_ARCH_V2) {
		versionDetected = 2
	} else if(arr[1] == SIGNATURE_SFZ_DATA_ARCH_V1) {
		versionDetected = 1
	} //end if else
	if(versionDetected <= 0) {
		return "", NewError("Invalid Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` ; Raw: `" + arr[1] + "`")
	} //end if
	//-- verify package checksum (v3+ only)
	if(versionDetected == 3) { // v3
		if(
			(lenSign < 2) ||
			(arr[2] == "") ||
			(StrStartsWith(arr[2], "(") != true) ||
			(StrSubstr(arr[2], lenSign-1, lenSign) != ")")) {
				return "", NewError("Invalid Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` ; Empty or Malformed Package Signature: `" + arr[2] + "`")
		} //end if
		theSgn, errSgn := dataArchCheckSign(arr[0] + LINE_FEED + arr[1])
		if(errSgn != nil) {
			return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Signature Failed: " + errSgn.Error())
		} //end if
		if(StrTrimWhitespaces(theSgn) == "") {
			return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Signature Failed, Empty")
		} //end if
		cksgn := "(" + theSgn + ")"
		if(cksgn != arr[2]) {
			return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Signature does not match, archived data is unsafe or broken")
		} //end if
	} //end if
	//--
	arr[0] = Base64Decode(arr[0])
	if(arr[0] == "") {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Invalid B64 Data")
	} //end if
	//--
	zlUncompressed, errZlUncompress := ZlibUncompress([]byte(arr[0]))
	if(errZlUncompress != nil) {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` ZLib Inflated Data Failed: " + errZlUncompress.Error())
	} //end if
	if(zlUncompressed == nil) {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` ZLib Inflated Data is Null")
	} //end if
	arr[0] = string(zlUncompressed)
	zlUncompressed = nil // free mem
	if(arr[0] == "") {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Invalid Zlib GzInflate Data")
	} //end if
	//--
	const txtErrExpl string = "this can occur if decompression failed or an invalid packet has been assigned"
	//--
	var versionCksumSeparator string = SEPARATOR_SFZ_CHECKSUM_V3
	if(versionDetected == 2) { // v2
		versionCksumSeparator = SEPARATOR_SFZ_CHECKSUM_V2
	} else if(versionDetected == 1) { // v1
		versionCksumSeparator = SEPARATOR_SFZ_CHECKSUM_V1
	} //end if else
	//--
	if((versionCksumSeparator == "") || (!StrContains(arr[0], versionCksumSeparator))) {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Checksum not detected (" + txtErrExpl + ")")
	} //end if
	//--
	darr := Explode(versionCksumSeparator, arr[0])
	arr = nil
	var dlen int = len(darr)
	if(dlen < 2) {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Checksum not found (" + txtErrExpl + ")")
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Checksum is empty (" + txtErrExpl + ")")
	} //end if
	if(darr[0] == "") {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Data not found (" + txtErrExpl + ")")
	} //end if
	//--
	if(versionDetected == 1) { // v1 only
		darr[0] = Hex2Bin(StrToLower(darr[0]))
	} else { // v2, v3
		darr[0] = Hex2Bin(darr[0])
	} //end if else
	if(darr[0] == "") {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Invalid HEX Data")
	} //end if
	//--
	var chkSignature bool = false
	if(versionDetected == 1) {
		if(Sha1(darr[0]) == darr[1]) { // v1
			chkSignature = true
		} //end if
	} else if(versionDetected == 2) { // v2
		if(Sha256(darr[0]) == darr[1]) {
			chkSignature = true
		} //end if
	} else { // v3
		if(Sh3a384B64(darr[0]) == darr[1]) {
			chkSignature = true
		} //end if
	} //end if else
	//--
	if(chkSignature != true) {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` Checksum is Invalid: `" + darr[1] + "`")
	} //end if
	//--
	return darr[0], nil
	//--
} //END FUNCTION


//-----


func ZlibCompress(data []byte, level int, verifyCompressed bool) ([]byte, error) { // compress zlib ; file extension: .zl (zlib/deflate)
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by gz deflate panic handler with malformed data
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	if((level < 1) || (level > 9)) {
		level = -1 // zlib default compression
	} //end if
	//--
	var b bytes.Buffer
	//--
	w, errInit := flate.NewWriter(&b, level) // RFC 1951
	if(errInit != nil) {
		return nil, NewError("Compress Init Failed: " + errInit.Error())
	} //end if
	//--
	_, errWr := w.Write(data)
	if(errWr != nil) {
		return nil, NewError("Compressed Write Failed: " + errWr.Error())
	} //end if
	//--
	errClose := w.Close()
	if(errClose != nil) {
		return nil, NewError("Compressed Close Failed: " + errClose.Error())
	} //end if
	//--
	byts := b.Bytes()
	if(byts == nil) {
		return nil, NewError("Compressed Data is Empty")
	} //end if
	//--
	if(verifyCompressed == true) {
		unarchData, unarchErr := ZlibUncompress(byts)
		if(unarchErr != nil) {
			return nil, NewError("Compressed Data Verification Failed: " + unarchErr.Error())
		} //end if
		if(unarchData == nil) {
			return nil, NewError("Compressed Data Verification Failed, Empty")
		} //end if
		if(len(unarchData) != len(data)) {
			return nil, NewError("Compressed Data Verification Failed, Length")
		} //end if
		if(string(ShaByt512B64(unarchData)) != string(ShaByt512B64(data))) {
			return nil, NewError("Compressed Data Verification Failed, Checksum")
		} //end if
		if(BytesEqual(unarchData, data) != true) {
			return nil, NewError("Compressed Data Verification Failed, Data")
		} //end if
	} //end if
	//--
	return byts, nil
	//--
} //END FUNCTION


func ZlibUncompress(data []byte) ([]byte, error) { // uncompress zlib ; file extension: .zl (zlib/deflate)
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by gz inflate panic handler with malformed data
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	b := bytes.NewReader(data)
	r := flate.NewReader(b) // RFC 1951
	//--
	byts, errRd := io.ReadAll(r)
	if(errRd != nil) {
		return nil, NewError("Uncompress Read Failed: " + errRd.Error())
	} //end if
	//--
	errClose := r.Close()
	if(errClose != nil) {
		return nil, NewError("Uncompress Close Failed: " + errClose.Error())
	} //end if
	//--
	if(byts == nil) {
		return nil, NewError("Uncompressed Data is Empty")
	} //end if
	//--
	return byts, nil
	//--
} //END FUNCTION





//-----





//-----


// #END
