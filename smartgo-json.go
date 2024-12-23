
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241223.2358 :: STABLE
// [ JSON ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"bytes"
	"strings"

	"encoding/json"

	"github.com/unix-world/smartgo/data-structs/fastjson"
	"github.com/unix-world/smartgo/data-structs/tidwall/gjson"
)

const (
	REGEX_SMART_SAFE_NUMBER_FLOAT string = `^[0-9\-\.]+$` // SAFETY: SUPPORT ONLY THESE CHARACTERS IN SAFE FLOAT (ex: JSON)
)


//-----


func ConvertJsonNumberToStr(data interface{}) string { // after convert to string can be re-converted into int64 / float64 / ...
	//--
	return data.(json.Number).String()
	//--
} //END FUNCTION


//-----


func JsonEncode(data interface{}, prettyprint bool, htmlsafe bool) (string, error) {
	//-- no need any panic handler
	out := bytes.Buffer{}
	//--
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(htmlsafe)
	if(prettyprint == true) {
		encoder.SetIndent("", "    ") // 4 spaces
	} //end if
	//--
	err := encoder.Encode(data)
	if(err != nil) {
		return "", err
	} //end if
	//--
	return StrTrimWhitespaces(out.String()), nil // must trim as will add a new line at the end ...
	//--
} //END FUNCTION


func JsonNoErrChkEncode(data interface{}, prettyprint bool, htmlsafe bool) string {
	//-- no need any panic handler
	str, _ := JsonEncode(data, prettyprint, htmlsafe)
	//--
	return str
	//--
} //END FUNCTION


//-----


func JsonObjDecode(data string) (map[string]interface{}, error) { // can parse just a JSON Object as {"key1":..., "key2":...}
	//-- no need any panic handler
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return nil, nil
	} //end if
	//--
	var dat map[string]interface{}
	dataReader := strings.NewReader(data)
	decoder := json.NewDecoder(dataReader)
	decoder.UseNumber()
	err := decoder.Decode(&dat)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	return dat, nil
	//--
} //END FUNCTION


func JsonArrDecode(data string) ([]interface{}, error) { // can parse just a JSON Array as ["a", 2, "c", { "e": "f" }, ...]
	//-- no need any panic handler
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return nil, nil
	} //end if
	//--
	var dat []interface{}
	dataReader := strings.NewReader(data)
	decoder := json.NewDecoder(dataReader)
	decoder.UseNumber()
	err := decoder.Decode(&dat)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	return dat, nil
	//--
} //END FUNCTION


func JsonStrDecode(data string) (string, error) { // can parse: only a JSON String
	//-- no need any panic handler
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return "", nil
	} //end if
	//--
	var dat string = ""
	dataReader := strings.NewReader(data)
	decoder := json.NewDecoder(dataReader)
	decoder.UseNumber()
	err := decoder.Decode(&dat)
	if(err != nil) {
		return "", err
	} //end if
	//--
	return dat, nil
	//--
} //END FUNCTION


func JsonScalarDecodeToStr(data string) (string, error) { // can parse the following JSON Scalar Types: Int / Float / Bool / Null, String :: will re-map any of these as string only
	//--
	data = StrTrimWhitespaces(data)
	if(data == "") {
		return "", nil
	} //end if
	//--
	switch(data) {
		case "NULL": fallthrough
		case "Null": fallthrough
		case "null":
			data = `""`
			break
		case "FALSE": fallthrough
		case "False": fallthrough
		case "false":
			data = `"false"`
			break
		case "TRUE": fallthrough
		case "True": fallthrough
		case "true":
			data = `"true"`
			break
		default:
			if(StrRegexMatch(REGEX_SMART_SAFE_NUMBER_FLOAT, data)) {
				data = `"` + data + `"`
			} //end if
	} //end switch
	//--
	return JsonStrDecode(data)
	//--
} //END FUNCTION


//-----


func JsonGetValueByKeyPath(json string, path string) gjson.Result {
	//--
	// to return the full json as root, use an empty path: ""
	// path can be: "3" ; "a" ; "0.id" ; "a.b.c.7"
	// will return type Result
	// Result type can be converted to: .String() | .Bool() | .Int() as int64 | .Uint() as uint64 | .Float() as float64 | .Time() as time.Time | .Array() as []Result | .Map() as [string]Result
	// Result can be checked as: .Exists(), .IsObject(), .IsArray(), .IsBool()
	// Sub-Results can get by gjson.Result.Get(path)
	//--
	if(StrTrimWhitespaces(json) == "") {
		return gjson.Result{}
	} //end if
	//--
	if(gjson.Valid(json) != true) {
		return gjson.Result{}
	} //end if
	//--
	if(StrTrimWhitespaces(path) == "") {
		return gjson.Parse(json) // get the root of json
	} //end if
	//--
	return gjson.Get(json, path) // get the path of json
	//--
} //END FUNCTION


func JsonGetValueByKeysPath(json string, keys ...string) (*fastjson.Value, error) {
	//--
	// to return the full json as root, use no keys
	// keys can be: "3" ; "a" ; "0", "id" ; "a", "b", "c", "7"
	// will return type *Value
	// Result type can be converted to: .GetScalarAsString() | .GetStringBytes() | .GetBool() | .GetInt() as int32 | .GetInt64() as int64 | .GetUint() as uint32 | .GetUint64() as uint64 | .GetFloat64() as float64 | .GetArray() as []*Value | .GetObject() as *Object
	// Result can be checked as: .Exists()
	//--
	if(StrTrimWhitespaces(json) == "") {
		return nil, NewError("JSON is Empty") // return null and an empty type error
	} //end if
	//--
	var p fastjson.Parser
	jsonVal, jsonErr := p.Parse(json)
	if(jsonErr != nil) {
		return nil, jsonErr // return null and the parsing error
	} //end if
	//--
	if(len(keys) <= 0) {
		return jsonVal, nil // return the root of json, no error
	} //end if
	//--
	return jsonVal.Get(keys...), nil // return the path of json, no error
	//--
} //END FUNCTION


//-----


// #END
