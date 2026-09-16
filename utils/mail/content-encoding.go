
package mail

// added by unixman # r.20260915

import (
	"errors"

	"bytes"
	"strings"

	"regexp"

	"hash/crc64"
	"encoding/hex"
	"encoding/base64"
	"mime/quotedprintable"
)

var (
	textBodyRegistered bool = false
	htmlBodyRegistered bool = false

	crc64TableECMA = crc64.MakeTable(crc64.ECMA)
)


func strRegexMatch(rexpr string, s string) bool {
	//--
	defer panicHandler()
	//--
	if(rexpr == "") {
		return false
	} //end if
	//--
	if(s == "") {
		return false
	} //end if
	//--
	matched, errRx := regexp.MatchString(rexpr, s)
	if(errRx != nil) {
		return false
	} //end if
	//--
	return matched
	//--
} //END FUNCTION


func crc64e(data []byte) string {
	//--
	hash := crc64.New(crc64TableECMA)
	hash.Write(data)
	//--
	return strings.ToLower(hex.EncodeToString(hash.Sum(nil))) // hex 16 characters, fixed
	//--
} //END FUNCTION


func chunkSplitB64BytesByLine(p []byte, splitLen int) []byte {
	//--
	data := []byte{}
	//--
	if(len(p) <= 0) {
		return data
	} //end if
	//--
	crlfByt := []byte("\r\n")
	//--
	for i:=0; i<len(p); i++ {
		if(i > 0) {
			if(i % (splitLen) == 0) {
				data = append(data, crlfByt...)
			} //end if
		} //end if
		data = append(data, p[i])
	} //end for
	//--
	return data
	//--
} //END FUNCTION


func bytChunkEncodeBase64(data []byte) []byte {
	//--
	if(len(data) <= 0) {
		return []byte{}
	} //end if
	//--
	var dst []byte = make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(dst, data)
	//--
	return chunkSplitB64BytesByLine(dst, maxLineLen) // chunk !
	//--
} //END FUNCTION


func normalizeLineEndings(data []byte) []byte { // {{{SYNC-MIME-ENCODING-NORMALIZE-LINES}}}
	//--
	if(len(data) <= 0) {
		return []byte{}
	} //end if
	//--
	var lf []byte = []byte("\n")
	//-- do not use StrTr/BytTr, they are unstable in order of replacements and here the order counts
	data = bytes.Replace(data, []byte("\r\n"), lf, -1) // replace all (limit is -1)
	data = bytes.Replace(data, []byte("\r"),   lf, -1) // replace all (limit is -1)
	//--
	return data
	//--
} //END FUNCTION


func normalizeOnlySpaces(data []byte) []byte {
	//--
	if(len(data) <= 0) {
		return []byte{}
	} //end if
	//--
	var space []byte = []byte(" ")
	//-- do not use StrTr here because the order of replacements is random there and here the order of replacements real matters
	data = bytes.Replace(data, []byte("\t"),   space, -1) // replace all (limit is -1)
	data = bytes.Replace(data, []byte("\v"),   space, -1) // replace all (limit is -1)
	data = bytes.Replace(data, []byte("\x00"), space, -1) // replace all (limit is -1)
	data = bytes.Replace(data, []byte("\f"),   space, -1) // replace all (limit is -1)
	data = bytes.Replace(data, []byte("\b"),   space, -1) // replace all (limit is -1)
	data = bytes.Replace(data, []byte("\a"),   space, -1) // replace all (limit is -1)
	//--
	return data
	//--
} //END FUNCTION


func normalizeStrLineEndings(data string) string { // {{{SYNC-MIME-ENCODING-NORMALIZE-LINES}}}
	//--
	if(data == "") {
		return ""
	} //end if
	//-- do not use StrTr/BytTr, they are unstable in order of replacements and here the order counts
	data = strings.Replace(data, "\r\n", "\n", -1) // replace all (limit is -1)
	data = strings.Replace(data, "\r",   "\n", -1) // replace all (limit is -1)
	//--
	return data
	//--
} //END FUNCTION


func normalizeStrOnlySpaces(data string) string {
	//--
	if(data == "") {
		return ""
	} //end if
	//-- do not use StrTr here because the order of replacements is random there and here the order of replacements real matters
	data = strings.Replace(data, "\t",   " ", -1) // replace all (limit is -1)
	data = strings.Replace(data, "\v",   " ", -1) // replace all (limit is -1)
	data = strings.Replace(data, "\x00", " ", -1) // replace all (limit is -1)
	data = strings.Replace(data, "\f",   " ", -1) // replace all (limit is -1)
	data = strings.Replace(data, "\b",   " ", -1) // replace all (limit is -1)
	data = strings.Replace(data, "\a",   " ", -1) // replace all (limit is -1)
	//--
	return data
	//--
} //END FUNCTION


func bytChunkEncodeQuotedPrintable(data []byte) ([]byte, error) {
	//--
	defer panicHandler()
	//--
	if(len(data) <= 0) {
		return []byte{}, nil
	} //end if
	//--
	var buf bytes.Buffer
	qpW := quotedprintable.NewWriter(&buf)
	_, errEnc := qpW.Write(data)
	if(errEnc != nil) {
		return nil, errEnc
	} //end if
	errClose := qpW.Close()
	if(errClose != nil) {
		return nil, errClose
	} //end if
	//--
	return buf.Bytes(), nil // already chunked, nothing to do
	//--
} //END FUNCTION


func encodeBody(data []byte, enc Encoding) (string, []byte, string, error) {
	//--
	defer panicHandler()
	//--
	var digestHeader string = ""
	var out []byte = []byte{}
	var contentCrc64 string = ""
	//--
	if(len(data) <= 0) {
		return digestHeader, out, contentCrc64, errors.New("encodeBody: Body data is Empty")
	} //end if
	//--
	var err error = nil
	if enc == Unencoded {
		out = data
		out = normalizeOnlySpaces(out)
		out = normalizeLineEndings(out) // as in PHP ; normalize line breaks, if contain several sequantial CRLF or CR may break the mime message
		digestHeader = createDigest(out) // digest must be calculated after line normalization and before encoding
		contentCrc64 = crc64e(out) // crc64e must be calculated after line normalization and before encoding
	} else if enc == QuotedPrintable {
		out = data
		out = normalizeOnlySpaces(out)
		out = normalizeLineEndings(out) // as in PHP ; normalize line breaks, if contain several sequantial CRLF or CR may break the mime message
		digestHeader = createDigest(out) // digest must be calculated after line normalization and before encoding
		contentCrc64 = crc64e(out) // crc64e must be calculated after line normalization and before encoding
		out, err = bytChunkEncodeQuotedPrintable(out)
		if(err != nil) {
			digestHeader = "" // reset
			out = []byte{} // reset
		} //end if
	} else if enc == Base64 {
		digestHeader = createDigest(data) // digest must be calculated before B64 encode, there is no line normalization in this case
		contentCrc64 = crc64e(data) // crc64e must be calculated before B64 encode, there is no line normalization in this case
		out = bytChunkEncodeBase64(data)
	} else {
		err = errors.New("encodeBody: Unknown Encoding Selected")
	} //end if else
	if(len(out) <= 0) {
		err = errors.New("encodeBody: Encoded data is Empty")
	} //end if
	//--
	return digestHeader, out, contentCrc64, err
	//--
} //END FUNCTION


// #end
