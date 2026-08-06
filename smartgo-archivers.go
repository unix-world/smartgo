
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260806.2358 :: STABLE
// [ ARCHIVERS ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"
	"fmt"

	"io"
	"bytes"
	"time"

	"compress/flate"

	"github.com/unix-world/smartgo/compress/gzip"
	"github.com/unix-world/smartgo/compress/zip"
	"github.com/unix-world/smartgo/compress/snappy"
	"github.com/unix-world/smartgo/utils/iox"
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
	defer PanicHandler() // req. by gz deflate panic handler with malformed data
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
	gzCompressed, errGzCompress := GzDeflate([]byte(data), -1, verifyCompressed)
	if(errGzCompress != nil) {
		return "", NewError("ZLib Deflated Data Failed: " + errGzCompress.Error())
	} //end if
	if(gzCompressed == nil) {
		return "", NewError("ZLib Deflated Data is Null")
	} //end if
	var arch string = string(gzCompressed)
	var alen int = len(arch)
	gzCompressed = nil // free mem
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
	gzUncompressed, errGzUncompress := GzInflate([]byte(arr[0]))
	if(errGzUncompress != nil) {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` ZLib Inflated Data Failed: " + errGzUncompress.Error())
	} //end if
	if(gzUncompressed == nil) {
		return "", NewError("Package Version: `" + ConvertUInt8ToStr(versionDetected) + "` ZLib Inflated Data is Null")
	} //end if
	arr[0] = string(gzUncompressed)
	gzUncompressed = nil // free mem
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


func GzDeflate(data []byte, level int, verifyCompressed bool) ([]byte, error) { // compress zlib ; file extension: .zl (zlib/deflate)
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
		unarchData, unarchErr := GzInflate(byts)
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


func GzInflate(data []byte) ([]byte, error) { // uncompress zlib ; file extension: .zl (zlib/deflate)
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


func GzPak(data string, verifyCompressed bool) (string, error) { // compress gzip style smart archive ; file extension: .smart-gz
	//--
	// compatible PHP
	//--
	defer PanicHandler()
	//--
	if(data == "") {
		return "", nil // should be no error
	} //end if
	//--
	if(uint64(len(data)) > SIZE_BYTES_16M) { // max 16MB ; sync with PHP
		return "", NewError("Data is too large to be Archived by this method")
	} //end if
	//--
	gzData, err := GzEncode([]byte(data), -1, verifyCompressed) // compress
	if(err != nil) {
		return "", err
	} //end if
	if(gzData == nil) {
		return "", NewError("Empty Data after Compress")
	} //end if
	//--
	return SIGNATURE_GZIP_PACK_v1 + "#" + string(Base64BytEncode(gzData)) + "#" + Crc64eB36(data + NULL_BYTE + ConvertIntToStr(len(data)) + VERTICAL_TAB + Sh3a512B64(data)), nil // this have to be fast and url safe, use B64s, intended for Web
	//--
} //END FUNCTION


func GzUnpak(data string) (string, error) { // uncompress gzip style smart archive ; file extension: .smart-gz
	//--
	// compatible PHP
	//--
	defer PanicHandler()
	//--
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return "", nil // should be no error
	} //end if
	//--
	if(uint64(len(data)) > SIZE_BYTES_16M) { // max 16MB ; sync with PHP
		return "", NewError("Data is too large to be UnArchived by this method")
	} //end if
	//--
	if(StrStartsWith(data, SIGNATURE_GZIP_PACK_v1 + "#") != true) {
		return "", NewError("Invalid Package Prefix")
	} //end if
	//--
	arr := ExplodeWithLimit("#", data, 3)
	if(len(arr) != 3) {
		return "", NewError("Invalid Package Format")
	} //end if
	if(StrTrimWhitespaces(arr[0]) != SIGNATURE_GZIP_PACK_v1) {
		return "", NewError("Invalid Package Signature")
	} //end if
	arr[1] = StrTrimWhitespaces(arr[1])
	if(arr[1] == "") {
		return "", NewError("Empty B64 Data")
	} //end if
	var crc string = StrTrimWhitespaces(arr[2])
	if(crc == "") {
		return "", NewError("Empty Checksum")
	} //end if
	data = Base64Decode(arr[1])
	arr = nil // free mem
	if(data == "") {
		return "", NewError("Empty Data after B64 decode")
	} //end if
	//--
	unGzData, errUnGzip := GzDecode([]byte(data)) // uncompress
	if(errUnGzip != nil) {
		return "", errUnGzip
	} //end if
	if(unGzData == nil) {
		return "", NewError("Empty Data after Uncompress")
	} //end if
	//--
	data = string(unGzData)
	unGzData = nil // free mem
	//--
	if(Crc64eB36(data + NULL_BYTE + ConvertIntToStr(len(data)) + VERTICAL_TAB + Sh3a512B64(data)) != crc) {
		return "", NewError("Data Checksum does Not Match")
	} //end if
	//--
	return data, nil
	//--
} //END FUNCTION


func GzEncode(data []byte, level int, verifyCompressed bool) ([]byte, error) { // compress gzip compatible ; file extension: .gz (gunzip)
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by gz encode panic handler with malformed data
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
	w, errInit := gzip.NewWriterLevel(&b, level) // RFC 1952 (gzip compatible)
	if(errInit != nil) {
		return nil, NewError("Compress Init Failed: " + errInit.Error())
	} //end if
	//--
	_, errWr := w.Write(data)
	if(errWr != nil) {
		return nil, NewError("Compress Write Failed: " + errWr.Error())
	} //end if
	//--
	errClose := w.Close()
	if(errClose != nil) {
		return nil, NewError("Compress Close Failed: " + errClose.Error())
	} //end if
	//--
	byts := b.Bytes()
	if(byts == nil) {
		return nil, NewError("Compressed Data is Empty")
	} //end if
	//--
	if(verifyCompressed == true) {
		unarchData, unarchErr := GzDecode(byts)
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


func GzDecode(data []byte) ([]byte, error) { // uncompress gzip compatible ; file extension: .gz (gunzip)
	//--
	// compatible with PHP
	//--
	defer PanicHandler() // req. by gz decode panic handler with malformed data
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	b := bytes.NewReader(data)
	r, errInit := gzip.NewReader(b) // RFC 1952 (gzip compatible)
	if(errInit != nil) {
		return nil, NewError("Uncompress Init Failed: " + errInit.Error())
	} //end if
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


func GzStreamEncode(rdStream io.ReadCloser, level int, wrStreams ...io.WriteCloser) error { // compress gzip compatible ; file extension: .gz (gunzip)
	//--
	// compatible with PHP
	//--
	// the purpose for accepting multiple writers is to allow for multiple outputs (for example a file and a hash)
	//--
	defer PanicHandler() // req. by gz encode panic handler with malformed data
	//--
	if(rdStream == nil) {
		return NewError("Input Stream is Null")
	} //end if
	if(wrStreams == nil) {
		return NewError("Output Stream is Null")
	} //end if
	if(len(wrStreams) < 1) {
		return NewError("Output Streams is Empty")
	} //end if
	//--
	for i:=0; i<len(wrStreams); i++ {
		if(wrStreams[i] == nil) {
			return NewError("Output Stream[" + ConvertIntToStr(i) + "] is Null")
		} //end if
	} //end for
	mw := iox.MultiWriteCloser(wrStreams...)
	defer mw.Close()
	//--
	defer rdStream.Close()
	//--
	if((level < 1) || (level > 9)) {
		level = -1 // zlib default compression
	} //end if
	//--
	w, errInit := gzip.NewWriterLevel(mw, level) // RFC 1952 (gzip compatible)
	if(errInit != nil) {
		return NewError("Compress Init Failed: " + errInit.Error())
	} //end if
	//--
	_, errWr := io.Copy(w, rdStream)
	if(errWr != nil) {
		return NewError("Compress Write Failed: " + errWr.Error())
	} //end if
	//--
	errClose := w.Close()
	if(errClose != nil) {
		return NewError("Compress Close Failed: " + errClose.Error())
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


func GzStreamDecode(rdStream io.ReadCloser, wrStreams ...io.WriteCloser) error { // uncompress gzip compatible ; file extension: .gz (gunzip)
	//--
	// compatible with PHP
	//--
	// the purpose for accepting multiple writers is to allow for multiple outputs (for example a file and a hash)
	//--
	defer PanicHandler() // req. by gz decode panic handler with malformed data
	//--
	if(rdStream == nil) {
		return NewError("Input Stream is Null")
	} //end if
	if(wrStreams == nil) {
		return NewError("Output Streams are Null")
	} //end if
	if(len(wrStreams) < 1) {
		return NewError("Output Streams are Empty")
	} //end if
	//--
	for i:=0; i<len(wrStreams); i++ {
		if(wrStreams[i] == nil) {
			return NewError("Output Stream[" + ConvertIntToStr(i) + "] is Null")
		} //end if
	} //end for
	mw := iox.MultiWriteCloser(wrStreams...)
	defer mw.Close()
	//--
	defer rdStream.Close()
	//--
	r, errInit := gzip.NewReader(rdStream) // RFC 1952 (gzip compatible)
	if(errInit != nil) {
		return NewError("Uncompress Init Failed: " + errInit.Error())
	} //end if
	//--
	_, errWr := io.Copy(mw, r)
	if(errWr != nil) {
		return NewError("Uncompress Write Failed: " + errWr.Error())
	} //end if
	//--
	return nil
	//--
} //END FUNCTION


//-----


func SnappyPak(data string, verifyCompressed bool) (string, error) { // compress snappy style smart archive ; file extension: .smart-sz
	//--
	// compatible with Js and PHP
	//--
	defer PanicHandler()
	//--
	if(data == "") {
		return "", nil // should be no error
	} //end if
	//--
	if(uint64(len(data)) > SIZE_BYTES_1M) { // max 1MB, must preserve compatibility with Js ; sync with Js and PHP
		return "", NewError("Data is too large to be Archived by this method")
	} //end if
	//--
	snap, err := SnappyCompress([]byte(data), verifyCompressed)
	if(err != nil) {
		return "", err
	} //end if
	if(snap == nil) {
		return "", NewError("Empty Data after Compress")
	} //end if
	//--
	return SIGNATURE_SNAPPY_PACK_v1 + ";" + string(Base64uBytEncode(snap)) + ";" + Crc32bB36(data + NULL_BYTE + ConvertIntToStr(len(data)) + VERTICAL_TAB + Sh3a512B64(data)), nil // this have to be fast and url safe, use B64s, intended for Web
	//--
} //END FUNCTION


func SnappyUnpak(data string) (string, error) { // uncompress snappy style smart archive ; file extension: .smart-sz
	//--
	// compatible with Js and PHP
	//--
	defer PanicHandler()
	//--
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return "", nil // should be no error
	} //end if
	//--
	if(uint64(len(data)) > SIZE_BYTES_1M) { // max 1MB, must preserve compatibility with Js ; sync with Js and PHP
		return "", NewError("Data is too large to be UnArchived by this method")
	} //end if
	//--
	if(StrStartsWith(data, SIGNATURE_SNAPPY_PACK_v1 + ";") != true) {
		return "", NewError("Invalid Package Prefix")
	} //end if
	//--
	arr := ExplodeWithLimit(";", data, 3)
	if(len(arr) != 3) {
		return "", NewError("Invalid Package Format")
	} //end if
	if(StrTrimWhitespaces(arr[0]) != SIGNATURE_SNAPPY_PACK_v1) {
		return "", NewError("Invalid Package Signature")
	} //end if
	arr[1] = StrTrimWhitespaces(arr[1])
	if(arr[1] == "") {
		return "", NewError("Empty B64 Data")
	} //end if
	var crc string = StrTrimWhitespaces(arr[2])
	if(crc == "") {
		return "", NewError("Empty Checksum")
	} //end if
	data = Base64uDecode(arr[1])
	arr = nil // free mem
	if(data == "") {
		return "", NewError("Empty Data after B64 decode")
	} //end if
	//--
	unSnap, errUnSnap := SnappyUncompress([]byte(data))
	if(errUnSnap != nil) {
		return "", errUnSnap
	} //end if
	if(unSnap == nil) {
		return "", NewError("Empty Data after Uncompress")
	} //end if
	//--
	data = string(unSnap)
	unSnap = nil // free mem
	//--
	if(Crc32bB36(data + NULL_BYTE + ConvertIntToStr(len(data)) + VERTICAL_TAB + Sh3a512B64(data)) != crc) {
		return "", NewError("Data Checksum does Not Match")
	} //end if
	//--
	return data, nil
	//--
} //END FUNCTION


func SnappyCompress(data []byte, verifyCompressed bool) ([]byte, error) { // compress snappy ; file extension: .sz (snappy)
	//--
	// compatible with Js and PHP
	//--
	defer PanicHandler()
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	byts := snappy.Encode(nil, data)
	if(byts == nil) {
		return nil, NewError("Compressed Data is Empty")
	} //end if
	//--
	if(verifyCompressed == true) {
		unarchData, unarchErr := SnappyUncompress(byts)
		if(unarchErr != nil) {
			return nil, NewError("Compressed Data Verification Failed: " + unarchErr.Error())
		} //end if
		if(unarchData == nil) {
			return nil, NewError("Compressed Data Verification Failed, Empty")
		} //end if
		if(len(unarchData) != len(data)) {
			return nil, NewError("Compressed Data Verification Failed, Length")
		} //end if
		if(string(Sh3aByt512B64(unarchData)) != string(Sh3aByt512B64(data))) {
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


func SnappyUncompress(data []byte) ([]byte, error) { // uncompress snappy ; file extension: .sz (snappy)
	//--
	// compatible with Js and PHP
	//--
	defer PanicHandler()
	//--
	if(data == nil) {
		return nil, NewError("Input Data is Empty")
	} //end if
	//--
	byts, err := snappy.Decode(nil, data)
	if(err != nil) {
		return nil, NewError("Uncompress Failed: " + err.Error())
	} //end if
	if(byts == nil) {
		return nil, NewError("Uncompressed Data is Empty")
	} //end if
	//--
	return byts, nil
	//--
} //END FUNCTION


//-----


func ZipArchive(files map[string][]byte, verifyCompressed bool) ([]byte, error) { // compress zip ; file extension: .zip (zip)
	//--
	// compatible with PHP
	//--
	defer PanicHandler()
	//--
	if((files == nil) || (len(files) <= 0)) {
		return nil, NewError("Zip: No files to add")
	} //end if
	//--
	var buf bytes.Buffer
	//--
	w := zip.NewWriter(&buf)
	//--
	var idx uint64 = 0
	for k, v := range files {
		//--
		k = StrTrimWhitespaces(k) // do trim, spaces are not supported ...
		if(k == "") { // path must not be empty
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # empty file path")
		} //end if
		var isDirectory bool = false
		if(StrEndsWith(k, "/") == true) { // must be test before SafePathFixClean
			if(BytesEqual(v, []byte("/")) == true) { // a directory must end with a slash and content must be a slash
				isDirectory = true
			} else { // file cannot end with a slash
				return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # unsupported dir path for File: `" + k + "`")
			} //end if else
		} //end if
		k = SafePathFixClean(k) // this removes the trailing slash if any
		if(isDirectory == true) { // add trailing slash back, if dir
			k = PathAddDirLastSlash(k)
		} //end if
		if(PathIsEmptyOrRoot(k) == true) { // should not be root o empty path
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # empty or root path for File: `" + k + "`")
		} //end if
		if(PathIsSafeValidPath(k) != true) { // can be: a/b/c.txt
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # invalid path for File: `" + k + "`")
		} //end if
		if(PathIsBackwardUnsafe(k) == true) { // must not be backward unsafe path
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # unsafe backward path for File: `" + k + "`")
		} //end if
		if(PathIsAbsolute(k) == true) { // path must not be absolute
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # unsafe absolute path for File: `" + k + "`")
		} //end if
		if((k == ".") || (k == "..") || (k == "/")) { // disallowed
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + " # disallowed dir path for File: `" + k + "`")
		} //end if
		//-- create with header (better than simple, can set metadata)
		var theComment string = ""
		if(isDirectory == true) {
			theComment = "#" + ConvertUInt64ToStr(idx+1) + " Dir: `" + k + "`"
		} else { // file
			theComment = "#" + ConvertUInt64ToStr(idx+1) + " File: `" + k + "` # Size: " + ConvertIntToStr(len(v)) + " bytes # Checksum SHA3-512/B64: " + string(Sh3aByt512B64(v)) // b64, better for compression
		} //end if
		if(uint64(len(theComment)) > SIZE_BYTES_65K) {
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + ", FileName: `" + k + "` # entry comment is too long")
		} //end if
		zHdr := zip.FileHeader{
			Name: k, // must be a relative path
			Comment: theComment, // must be shorter than 64KiB
			Modified: time.Now(),
		}
		if(isDirectory == true) {
			zHdr.Method = zip.Store
			zHdr.SetDirMode(0755) // required to set the archive in unix mode (do not want msdos mode ...)
		} else {
			zHdr.Method = zip.Deflate
			zHdr.SetMode(0644) // required to set the archive in unix mode (do not want msdos mode ...)
		} //end if else
		f, errHCreate := w.CreateHeader(&zHdr)
		if(errHCreate != nil) {
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + ", FileName: `" + k + "` # Create (with Header) entry Failed: " + errHCreate.Error())
		} //end if
		//--
		var errWrite error
		if(isDirectory == true) { // file only
		//	log.Println("isDirectory:", isDirectory, "; name:", k)
			errWrite = nil // no need to write, dirs only ned to be created as entry
		} else {
			_, errWrite = f.Write(v)
		} //end if
		if(errWrite != nil) {
			return nil, NewError("Zip: position #" + ConvertUInt64ToStr(idx) + ", FileName: `" + k + "` # Write entry Failed: " + errWrite.Error())
		} //end if
		//--
		idx++
		//--
	} //end for
	//--
	var zipComment string = NAME + " " + VERSION + " Zip.Archiver"
	if(uint64(len(zipComment)) > SIZE_BYTES_65K) {
		return nil, NewError("Zip: archive comment is too long")
	} //end if
	//--
	errComment := w.SetComment(zipComment) // sets the end-of-central-directory comment field, it can only be called before Writer.Close
	if(errComment != nil) {
		return nil, NewError("Zip: archive comment error: " + errComment.Error())
	} //end if
	//--
	errClose := w.Close()
	if(errClose != nil) {
		return nil, NewError("Zip: archive close error: " + errClose.Error())
	} //end if
	//--
	byts := buf.Bytes()
	if(byts == nil) {
		return nil, NewError("Zip: archived data is Null")
	} //end if
	//--
	if(verifyCompressed == true) {
		arrUncompressed, errUncompress := ZipUnarchive(byts, false) // non-permissive
		if(errUncompress != nil) {
			return nil, NewError("Compressed Data Verification Failed: " + errUncompress.Error())
		} //end if
		if(arrUncompressed == nil) {
			return nil, NewError("Compressed Data Verification Failed, Null")
		} //end if
		if(len(arrUncompressed) <= 0) {
			return nil, NewError("Compressed Data Verification Failed, Empty")
		} //end if
		if(len(arrUncompressed) != len(files)) {
			return nil, NewError("Compressed Data Verification Failed, Mismatch")
		} //end if
		var ix uint64 = 0
		for k, v := range files {
			vv, ok := arrUncompressed[k]
			if(ok != true) {
				return nil, NewError("Compressed Data Verification Failed, Missing entry at position #" + ConvertUInt64ToStr(ix) + " / Path `" + k + "`")
			} //end if
			if(vv == nil) {
				return nil, NewError("Compressed Data Verification Failed, Content is Null entry at position #" + ConvertUInt64ToStr(ix) + " / Path `" + k + "`")
			} //end if
			if(len(vv) != len(v)) {
				return nil, NewError("Compressed Data Verification Failed, Content Length does Not Match at position #" + ConvertUInt64ToStr(ix) + " / Path `" + k + "`")
			} //end if
			var isDirectory bool = false
			if(StrEndsWith(k, "/") == true) {
				isDirectory = true
			} //end if
			if(isDirectory == true) { // dir only
				if(BytesEqual(vv, []byte("/")) != true) { // trick by unixman, a dir must have the content set as "/"
					return nil, NewError("Compressed Data Verification Failed, Content Dir as Slash does Not Match at position #" + ConvertUInt64ToStr(ix) + " / Dir `" + k + "`")
				} //end if
			} else { // file only
				if(string(Sh3aByt512B64(v)) != string(Sh3aByt512B64(vv))) {
					return nil, NewError("Compressed Data Verification Failed, Content Checksum does Not Match at position #" + ConvertUInt64ToStr(ix) + " / File `" + k + "`")
				} //end if
			} //end if
			if(BytesEqual(vv, v) != true) {
				return nil, NewError("Compressed Data Verification Failed, Content does Not Match at position #" + ConvertUInt64ToStr(ix) + " / Path `" + k + "`")
			} //end if
			ix++
		} //end for
	} //end if
	//--
	return byts, nil
	//--
} //END FUNCTION


//-----


func ZipUnarchive(zipData []byte, permissive bool) (map[string][]byte, error) { // uncompress zip ; file extension: .zip (zip)
	//--
	// compatible with PHP
	//--
	// if permissive is set to TRUE will allow partial extraction if some other file extraction failed ; otherwise will stop and raise error on any failure
	//--
	defer PanicHandler()
	//--
	var noFiles map[string][]byte = map[string][]byte{}
	//--
	if(zipData == nil) {
		return noFiles, NewError("Zip Archive: Content is Empty")
	} //end if
	//--
	zipReader, errReader := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if(errReader != nil) {
		return noFiles, NewError("Zip Archive: Reader ERR: " + errReader.Error())
	} //end if
	if(len(zipReader.File) <= 0) {
		return noFiles, NewError("Zip Archive: Contains No Readable Files")
	} //end if
	//-- read all the files from zip archive
	files := noFiles
	var fName string = ""
	for key, zipFile := range zipReader.File {
		//--
		fName = StrTrimWhitespaces(zipFile.Name)
		if(fName == "") {
			var msg string = "Zip Archive: a File has an Empty Name, at Key: #" + ConvertIntToStr(key)
			if(permissive == true) { // not fatal, let it continue
				log.Println("[NOTICE]", CurrentFunctionName(), msg)
				fName = "#EMPTY#" // fix path
			} else {
				return noFiles, NewError(msg)
			} //end if else
		} //end if
		//--
		if(DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "Entry #", key, zipFile.Name, zipFile.Flags, zipFile.CRC32, string(zipFile.Extra), zipFile.ExternalAttrs)
		} //end if
		//--
		var isDirectory bool = false
		if(((StrEndsWith(fName, "/") == true) || ((zipFile.CRC32 <= 0) && (zipFile.Flags == 0))) && ((zipFile.UncompressedSize <= 0) && (zipFile.UncompressedSize64 <= 0))) { // a directory ending with a slash is optional, but the rule is that a dir must have flags 0 and crc 0 and no content
			isDirectory = true
		} //end if
		//--
		var hexCrc32 string = StrToLower(StrPad2LenLeft(fmt.Sprintf("%x", zipFile.CRC32), "0", 8))
		//--
		var fOriginalName string = fName
		fName = StrTrimWhitespaces(SafePathCleanInvalidChars(fName, true, true, false, false)) // is file ; allow path slash ; disallow absolute path ; not smart safe
		if(isDirectory == true) { // dir
			fName = PathAddDirLastSlash(fName)
		} else { // file
			if(StrEndsWith(fName, "/") == true) { // cannot end with a slash
				fName = StrTrimRightWhitespaces(StrTrimRight(fName, "/")) // fix
			} //end if
		} //end if
		var isFNameOk bool = true
		if(fName == "") {
			isFNameOk = false
		} //end if
		if(PathIsEmptyOrRoot(fName) == true) { // should not be root o empty path
			isFNameOk = false
		} //end if
		if(PathIsSafeValidPath(fName) != true) { // can be: a/b/c.txt
			isFNameOk = false
		} //end if
		if(PathIsBackwardUnsafe(fName) == true) { // must not be backward unsafe path
			isFNameOk = false
		} //end if
		if(PathIsAbsolute(fName) == true) { // path must not be absolute
			isFNameOk = false
		} //end if
		if(isDirectory == true) { // dir
			if(StrEndsWith(fName, "/") != true) { // must end with a slash
				isFNameOk = false
			} //end if
		} else { // file
			if(StrEndsWith(fName, "/") == true) { // cannot end with a slash
				isFNameOk = false
			} //end if
		} //end if
		if((fName == ".") || (fName == "..") || (fName == "/")) { // disallowed
			isFNameOk = false
		} //end if
		//--
		if(isFNameOk != true) {
			var msg string = "Zip Archive: a File has an Invalid Path or Name, at Key: #" + ConvertIntToStr(key) + ", as: `" + fOriginalName + "`"
			if(permissive == true) { // not fatal, let it continue
				log.Println("[NOTICE]", CurrentFunctionName(), msg)
				fName = "#INVALID#" + Sha224(fOriginalName) // fix path, hash
				var fExt string = StrToLower(StrTrimWhitespaces(PathBaseExtension(fOriginalName))) // extract file extension
				if((fExt != "") && (PathIsSafeValidSafeFileName(fExt) == true)) { // add file extension
					fName += fExt
				} //end if
			} else {
				return noFiles, NewError(msg)
			} //end if else
		} //end if
		//--
		if(isDirectory == true) { // dir
			//--
			files[fName] = []byte("/") // mandatory for verify
			//--
		} else {
			//--
			unzippedBytes, errUnzip := zipArchReadFileFromMemory(zipFile)
			if(errUnzip != nil) {
				var msg string = "Zip Archive: the File: `" + fName + "` at Key: #" + ConvertIntToStr(key) + " # Unzip Failed: " + errUnzip.Error()
				if(permissive == true) { // not fatal, let it continue
					log.Println("[NOTICE]", CurrentFunctionName(), msg)
				} else {
					return noFiles, NewError(msg)
				} //end if else
			} else if(unzippedBytes == nil) {
				var msg string = "Zip Archive: the File: `" + fName + "` at Key: #" + ConvertIntToStr(key) + " # Unzip Content is Empty"
				if(permissive == true) { // not fatal, let it continue
					log.Println("[NOTICE]", CurrentFunctionName(), msg)
				} else {
					return noFiles, NewError(msg)
				} //end if else
			} else if(string(CrcByt32b(unzippedBytes)) != hexCrc32) {
				var msg string = "Zip Archive: the File: `" + fName + "` at Key: #" + ConvertIntToStr(key) + " # Unzip Content CRC32 failed"
				return noFiles, NewError(msg)
				// no permissive on broken content CRC32 !
			} else {
				files[fName] = unzippedBytes // all ok, append the file name and the unzipped file bytes
			} //end if
			//--
		} //end if else
		//--
	} //end for
	//--
	return files, nil
	//--
} //END FUNCTION


func zipArchReadFileFromMemory(zf *zip.File) ([]byte, error) {
	//--
	// internal only
	//--
	defer PanicHandler()
	//--
	if(zf == nil) {
		return nil, NewError("File Resource is Null")
	} //end if
	//--
	f, errOpen := zf.Open()
	if(errOpen != nil) {
		return nil, errOpen
	} //end if
	//--
	defer f.Close()
	//--
	data, errRd := io.ReadAll(f)
	if(errRd != nil) {
		return nil, errRd
	} //end if
	//--
	return data, nil
	//--
} //END FUNCTION


//-----


// #END
