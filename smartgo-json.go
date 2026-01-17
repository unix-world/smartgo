
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260116.2358 :: STABLE
// [ JSON ]

// REQUIRE: go 1.19 or later
package smartgo

import (
//	"log"

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
	defer PanicHandler()
	//--
	return data.(json.Number).String()
	//--
} //END FUNCTION


func ConvertJsonNumberToInt64(data interface{}) (int64, error) {
	//--
	defer PanicHandler()
	//--
	return data.(json.Number).Int64()
	//--
} //END FUNCTION


func ConvertJsonNumberToFloat64(data interface{}) (float64, error) {
	//--
	defer PanicHandler()
	//--
	return data.(json.Number).Float64()
	//--
} //END FUNCTION


//-----


func JsonEncode(data interface{}, prettyprint bool, htmlsafe bool) (string, error) {
	//--
	defer PanicHandler()
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
	//--
	defer PanicHandler()
	//-- no need any panic handler
	str, _ := JsonEncode(data, prettyprint, htmlsafe)
	//--
	return str
	//--
} //END FUNCTION


//-----


func JsonObjDecode(data string) (map[string]interface{}, error) { // can parse just a JSON Object as {"key1":..., "key2":...}
	//--
	defer PanicHandler()
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
	//--
	defer PanicHandler()
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
	//--
	defer PanicHandler()
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
	defer PanicHandler()
	//-- no need any panic handler
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
	defer PanicHandler()
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
	defer PanicHandler()
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


func ConformSerializedJsObjectForm(jsonStr string, dataKey string) (map[string]interface{}, error) {
	//-- r.20241226.2358
	// normalize serialized form data from jQuery.serializeArray(), created by smartJ$Browser.SerializeFormAsObject()
	//--
	defer PanicHandler()
	//--
	jsonStr = StrTrimWhitespaces(jsonStr)
	if(jsonStr == "") {
		return map[string]interface{}{}, NewError("Json string is Empty")
	} //end if
	if(len(jsonStr) > 65535) {
		return map[string]interface{}{}, NewError("Json string is OverSized")
	} //end if
	//--
	const regexValidKey string = `[a-zA-Z0-9\-]{1,64}`
	//--
	dataKey = StrTrimWhitespaces(dataKey)
	if((dataKey == "") || (!StrRegexMatch(regexValidKey, dataKey))) {
		return map[string]interface{}{}, NewError("DataKey is Empty or Invalid")
	} //end if
	//--
	jsonArray, err := JsonObjDecode(jsonStr)
	if(err != nil) {
		return map[string]interface{}{}, NewError("Json is Invalid: " + err.Error())
	} //end if
	if(len(jsonArray) <= 0) {
		return map[string]interface{}{}, NewError("Json is Empty")
	} //end if
	if(len(jsonArray) > 16384) {
		return map[string]interface{}{}, NewError("Json is OverSized")
	} //end if
	//--
	var convertToStringSlice = func(m []interface{}) ([]string, error) {
		var result []string
		for i:=0; i<len(m); i++ {
			str, ok := m[i].(string)
			if(!ok) {
				return []string{}, NewError("Failed to convert a slice to string")
			} //end if
			result = append(result, str)
		} //end for
		return result, nil
	} //end fx
	//--
	arr := make(map[string]interface{})
	for key, val := range jsonArray {
		//--
		if(!StrRegexMatch(regexValidKey, key)) {
			return map[string]interface{}{}, NewError("a Key is Invalid")
		} //end if
		//--
		valMap, ok2 := val.(map[string]interface{})
		if(!ok2) {
			return map[string]interface{}{}, NewError("a Value is Invalid")
		} //end if
		//--
		_, ok3 := valMap["#"]
		if(!ok3) {
			return map[string]interface{}{}, NewError("Failed to get # Values Map")
		} //end if
		//--
		hashMap, ok4 := valMap["#"].(map[string]interface{})
		if(!ok4) {
			return map[string]interface{}{}, NewError("Failed to get # Hash Map")
		} //end if
		//--
		levels, ok5 := hashMap["levels"]
		if(!ok5) {
			return map[string]interface{}{}, NewError("Failed to get # Levels")
		} //end if
		levelsInt, errLevels := ConvertJsonNumberToInt64(levels)
		if((errLevels != nil) || (levelsInt < 0)) { // can be zero if there is no nested data, but no lower than zero
			return map[string]interface{}{}, NewError("The # Levels must not be lower than zero")
		} //end if
		keys, ok6 := hashMap["keys"]
		if(!ok6) {
			return map[string]interface{}{}, NewError("Failed to get # Keys")
		} //end if
		keysInt, errKeys := ConvertJsonNumberToInt64(keys)
		if((errKeys != nil) || (keysInt <= 0)) { // cannot be zero or lower
			return map[string]interface{}{}, NewError("The # Keys must be higher than zero")
		} //end if
		//--
		size, ok7 := hashMap["size"]
		if(!ok7) {
			return map[string]interface{}{}, NewError("Failed to get # Size")
		} //end if
		sizeInt, errSize := ConvertJsonNumberToInt64(size)
		if((errSize != nil) || (sizeInt <= 0)) { // cannot be zero or lower
			return map[string]interface{}{}, NewError("The # Size must be higher than zero")
		} //end if
		//--
		dataKeyVal, ok8 := valMap[dataKey].(map[string]interface{})
		if(!ok8) {
			return map[string]interface{}{}, NewError("Failed to get the Values Map")
		} //end if
		if(len(dataKeyVal) <= 0) {
			return map[string]interface{}{}, NewError("The Values Map is Empty")
		} //end if
		if(int64(len(dataKeyVal)) != keysInt) {
			return map[string]interface{}{}, NewError("The Values Map length must match the # Keys")
		} //end if
		//--
		var lData int = 0
		data  := make(map[string]interface{})
		items := make(map[string][]string)
		var errConvert error = nil
		for kk, vv := range dataKeyVal {
			vvArr, okVvArr := vv.([]interface{})
			vvMap, okVvMap := vv.(map[string]interface{})
			vvStr, okVvStr := vv.(string)
			if(okVvArr) {
				if(len(vvArr) > 1024) {
					return map[string]interface{}{}, NewError("An item value type List is OverSized")
				} //end if
				items[string(kk)], errConvert = convertToStringSlice(vvArr)
				if(errConvert != nil) {
					return map[string]interface{}{}, NewError("Failed to convert an item value to List: " + errConvert.Error())
				} //end if
			} else if(okVvMap) {
				if(len(vvMap) > 512) {
					return map[string]interface{}{}, NewError("An item value type Map is OverSized")
				} //end if
				data[string(kk)] = vvMap
				lData += len(vvMap)
			} else if(okVvStr) {
				if(len(vvStr) > 8192) {
					return map[string]interface{}{}, NewError("An item value type String is OverSized")
				} //end if
				data[string(kk)] = vvStr
				lData++
			} else {
				return map[string]interface{}{}, NewError("Failed to convert an item value to String or List")
			} //end if else
		} //end for
		//--
		if(len(items) > 512) {
			return map[string]interface{}{}, NewError("Items List is OverSized")
		} //end if
		if(len(data) > 512) {
			return map[string]interface{}{}, NewError("Data List is OverSized")
		} //end if
		//--
		arr[key] = data
		//--
		if(len(items) > 0) {
			//--
			total := len(data) + len(items)
			if(int64(total) != keysInt) {
				return map[string]interface{}{}, NewError("The @ total must match the # Keys")
			} //end if
			//--
			var diff int64 = sizeInt - int64(lData)
			var delta float64 = float64(diff) / float64(len(items))
			var strDelta string = ConvertFloat64ToStr(delta)
			var intDelta int64 = int64(delta)
			//log.Println("[DEBUG]", "key", key, "diff", diff, "len(data)", len(data), data, "delta", delta, "lenItems", int64(len(items)), (diff % int64(len(items))))
			if((delta < 0) || (intDelta < 0) || (IsInteger(strDelta, false) != true) || ((diff % int64(len(items))) != 0)) { // check: the diff size divided to number of items must be an integer, that ~ means each item have the same size
				return map[string]interface{}{}, NewError("The Items Delta is Invalid")
			} //end if
			//--
			ikeys := make([]string, 0) // expects non-associative array (list)
			for ik, iv := range items {
				if(int64(len(iv)) != intDelta) {
					return map[string]interface{}{}, NewError("An Item length does not match the Delta")
				} //end if
				ikeys = append(ikeys, ik)
			} //end for
			//--
			arr[key+":@"] = make([]map[string]string, intDelta)
			var i int64 = 0
			for i=0; i<intDelta; i++ {
				//--
				item := make(map[string]string)
				//--
				for _, itk := range ikeys {
					item[itk] = items[itk][i]
				} //end for
				//--
				arr[key+":@"].([]map[string]string)[i] = item
				//--
			} //end for
			//--
		} //end if
		//--
	} //end for
	//--
	return arr, nil
	//--
} //END FUNCTION


//-----


// #END
