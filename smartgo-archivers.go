
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231124.2232 :: STABLE
// [ ARCHIVERS ]

// REQUIRE: go 1.17 or later
package smartgo

import (
	"log"

	"bytes"

	"io"

	"compress/flate"
	"compress/gzip"
)


const (
	SEPARATOR_SFZ_CHECKSUM_V1 string 		= "#CHECKSUM-SHA1#" 							// v1
	SEPARATOR_SFZ_CHECKSUM_V2 string 		= "#CKSUM256#" 									// v2

	SIGNATURE_SFZ_DATA_ARCH_V1 string 		= "PHP.SF.151129/B64.ZLibRaw.HEX" 				// only to support v1 unarchive ; (for v1 no archive is available anymore)
	SIGNATURE_SFZ_DATA_ARCH_V2 string 		= "SFZ.20210818/B64.ZLibRaw.hex" 				// current, v2 ; archive + unarchive
)


//-----


func DataArchive(str string) string {
	//--
	defer PanicHandler() // req. by gz deflate panic handler with malformed data
	//--
	var ulen int = len(str)
	if((str == "") || (ulen <= 0)) {
		return ""
	} //end if
	//--
	var chksum string = Sha256(str)
	var data string = StrTrimWhitespaces(Bin2Hex(str)) + SEPARATOR_SFZ_CHECKSUM_V2 + chksum
	str = ""
	//--
	var arch string = GzDeflate(data, -1)
	var alen int = len(arch)
	//--
	if((arch == "") || (alen <= 0)) { // check also division by zero
		log.Println("[ERROR] " + CurrentFunctionName() + ": ZLib Deflated Data is Empty")
		return ""
	} //end if
	//--
	var ratio = float64(ulen) / float64(alen) // division by zero is checked above by (alen <= 0)
	if(ratio <= 0) {
		log.Println("[ERROR] " + CurrentFunctionName() + ": ZLib Data Ratio is zero:", ratio)
		return ""
	} //end if
	if(ratio > 32768) { // check for this bug in ZLib {{{SYNC-GZ-ARCHIVE-ERR-CHECK}}}
		log.Println("[ERROR] " + CurrentFunctionName() + ": ZLib Data Ratio is higher than 32768:", ratio)
		return ""
	} //end if
	//log.Println("[DEBUG] " + CurrentFunctionName() + ": ZLib Data Ratio is: ", ratio, " by division of: ", ulen, " with: (/) ", alen)
	//--
	arch = StrTrimWhitespaces(Base64Encode(arch)) + "\n" + SIGNATURE_SFZ_DATA_ARCH_V2
	//--
	var unarch_chksum string = Sha256(DataUnArchive(arch))
	if(unarch_chksum != chksum) {
		log.Println("[ERROR] " + CurrentFunctionName() + ": Data Encode Check Failed")
		return ""
	} //end if
	//--
	return arch
	//-- str
} //END FUNCTION


func DataUnArchive(str string) string {
	//--
	defer PanicHandler() // req. by gz / hex2bin panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	arr := Explode("\n", str)
	str = ""
	var alen int = len(arr)
	//--
	arr[0] = StrTrimWhitespaces(arr[0])
	if(arr[0] == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Package Format")
		return ""
	} //end if
	//--
	var versionDetected uint8 = 0
	if(alen < 2) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Empty Package Signature")
		//arr = append(arr, "") // fix: add missing arr[1] to avoid panic below ; no more needed as will exit below if this err happen
		return ""
	} else {
		arr[1] = StrTrimWhitespaces(arr[1])
		if(arr[1] == SIGNATURE_SFZ_DATA_ARCH_V2) {
			versionDetected = 2
		} else if(arr[1] == SIGNATURE_SFZ_DATA_ARCH_V1) {
			versionDetected = 1
		} //end if else
		if(versionDetected <= 0) {
			log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Package (version:", versionDetected, ") Signature:", arr[1])
			return ""
		} //end if
	} //end if
	//--
	arr[0] = Base64Decode(arr[0])
	if(arr[0] == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid B64 Data for packet (version:", versionDetected, ") with signature:", arr[1])
		return ""
	} //end if
	//--
	arr[0] = GzInflate(arr[0])
	if(arr[0] == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Zlib GzInflate Data for packet (version:", versionDetected, ") with signature:", arr[1])
		return ""
	} //end if
	//--
	const txtErrExpl string = "This can occur if decompression failed or an invalid packet has been assigned ..."
	//--
	var versionCksumSeparator string = ""
	if(versionDetected == 1) {
		versionCksumSeparator = SEPARATOR_SFZ_CHECKSUM_V1
	} else { // v2
		versionCksumSeparator = SEPARATOR_SFZ_CHECKSUM_V2
	} //end if else
	//--
	if((versionCksumSeparator == "") || (!StrContains(arr[0], versionCksumSeparator))) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Packet (version:", versionDetected, "), no Checksum:", txtErrExpl)
		return ""
	} //end if
	//--
	darr := Explode(versionCksumSeparator, arr[0])
	arr = nil
	var dlen int = len(darr)
	if(dlen < 2) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Packet (version:", versionDetected, "), Checksum not found:", txtErrExpl)
		return ""
	} //end if
	darr[0] = StrTrimWhitespaces(darr[0])
	darr[1] = StrTrimWhitespaces(darr[1])
	if(darr[1] == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Packet (version:", versionDetected, "), Checksum is Empty:", txtErrExpl)
		return ""
	} //end if
	if(darr[0] == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Packet (version:", versionDetected, "), Data not found:", txtErrExpl)
		return ""
	} //end if
	//--
	if(versionDetected == 1) {
		darr[0] = Hex2Bin(StrToLower(darr[0]))
	} else { // v2
		darr[0] = Hex2Bin(darr[0])
	} //end if else
	if(darr[0] == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid HEX Data for packet (version:", versionDetected, ") with signature:", arr[1])
		return ""
	} //end if
	//--
	var chkSignature bool = false
	if(versionDetected == 1) {
		if(Sha1(darr[0]) == darr[1]) {
			chkSignature = true
		} //end if
	} else { // v2
		if(Sha256(darr[0]) == darr[1]) {
			chkSignature = true
		} //end if
	} //end if else
	//--
	if(chkSignature != true) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ": Invalid Packet (version:", versionDetected, "), Checksum FAILED :: A checksum was found but is invalid:", darr[1])
		return ""
	} //end if
	//--
	return darr[0]
	//--
} //END FUNCTION


//-----


func GzEncode(str string, level int) string {
	//--
	defer PanicHandler() // req. by gz encode panic handler with malformed data
	//--
	if(str == "") {
		return ""
	} //end if
	//--
	if((level < 1) || (level > 9)) {
		level = -1 // zlib default compression
	} //end if
	//--
	var b bytes.Buffer
	w, err := gzip.NewWriterLevel(&b, level) // RFC 1952 (gzip compatible)
	//--
	if(err != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//--
	w.Write([]byte(str))
	w.Close()
	//--
	var out string = b.String()
	if(out == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ":", "Empty Arch Data")
		return ""
	} //end if
	//--
	return out
	//--
} //END FUNCTION


func GzDecode(str string) string {
	//--
	defer PanicHandler() // req. by gz decode panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	b := bytes.NewReader([]byte(str))
	r, err := gzip.NewReader(b) // RFC 1952 (gzip compatible)
	if(err != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	bb2 := new(bytes.Buffer)
	_, _ = io.Copy(bb2, r)
	r.Close()
	byts := bb2.Bytes()
	//--
	var out string = string(byts)
	if(out == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ":", "Empty UnArch Data")
		return ""
	} //end if
	//--
	return out
	//--
} //END FUNCTION


//-----


func GzDeflate(str string, level int) string {
	//--
	defer PanicHandler() // req. by gz deflate panic handler with malformed data
	//--
	if(str == "") {
		return ""
	} //end if
	//--
	if((level < 1) || (level > 9)) {
		level = -1 // zlib default compression
	} //end if
	//--
	var b bytes.Buffer
	w, err := flate.NewWriter(&b, level) // RFC 1951
	//--
	if(err != nil) {
		log.Println("[NOTICE] " + CurrentFunctionName() + ":", err)
		return ""
	} //end if
	//--
	w.Write([]byte(str))
	w.Close()
	//--
	var out string = b.String()
	if(out == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ":", "Empty Arch Data")
		return ""
	} //end if
	//--
	return out
	//--
} //END FUNCTION


func GzInflate(str string) string {
	//--
	defer PanicHandler() // req. by gz inflate panic handler with malformed data
	//--
	str = StrTrimWhitespaces(str)
	if(str == "") {
		return ""
	} //end if
	//--
	b := bytes.NewReader([]byte(str))
	r := flate.NewReader(b) // RFC 1951
	bb2 := new(bytes.Buffer)
	_, _ = io.Copy(bb2, r)
	r.Close()
	byts := bb2.Bytes()
	//--
	var out string = string(byts)
	if(out == "") {
		log.Println("[NOTICE] " + CurrentFunctionName() + ":", "Empty UnArch Data")
		return ""
	} //end if
	//--
	return out
	//--
} //END FUNCTION


//-----


// #END
