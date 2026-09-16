
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2021-present, unix-world.org
// r.20260915.2358 :: STABLE
// [ ARCHIVERS / SNAPPY ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"github.com/unix-world/smartgo/compress/snappy"
)


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


//-----


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


// #END
