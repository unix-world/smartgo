
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241221.2358 :: STABLE
// [ XML ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"bytes"
	"strings"

	"encoding/xml"
	"github.com/unix-world/smartgo/data-structs/xml2json"
)


//-----


func XmlEncode(data interface{}, prettyprint bool, includeHeader bool) (string, error) {
	//-- no need any panic handler
	out := bytes.Buffer{}
	//--
	encoder := xml.NewEncoder(&out)
	if(prettyprint == true) {
		encoder.Indent("", "    ") // 4 spaces
	} //end if
	//--
	err := encoder.Encode(data)
	if(err != nil) {
		return "", err
	} //end if
	//--
	var hdr string = ""
	if(includeHeader == true) {
		hdr = xml.Header
		if(prettyprint != true) {
			hdr = StrTrimRightWhitespaces(hdr)
		} //end if
	} //end if
	//--
	return hdr + StrTrimWhitespaces(out.String()), nil // must trim as will add a new line at the end ...
	//--
} //END FUNCTION


func XmlNoErrChkEncode(data interface{}, prettyprint bool, includeHeader bool) string {
	//-- no need any panic handler
	str, _ := XmlEncode(data, prettyprint, includeHeader)
	//--
	return str
	//--
} //END FUNCTION


//-----


func XmlConvertToJson(xmlData string) (string, error) {
	//--
	xml := strings.NewReader(xmlData) // xml is an io.Reader
	json, err := xml2json.Convert(xml)
	if(err != nil) {
		return "", err // returns empty string and the conversion error
	} //end if
	//--
	return json.String(), nil // returns the json as string, no error
	//--
} //END FUNCTION


//-----


// #END
