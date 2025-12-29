
// GO Lang :: SmartGo / Web Server / JSON-Validate :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20251216.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"strings"

	smart 		"github.com/unix-world/smartgo"

	jsonschema 	"github.com/unix-world/smartgo/web/jsonschema"
)


func JsonValidateWithSchema(draft uint16, schema string, json string) error { // if OK returns TRUE
	//--
	defer smart.PanicHandler()
	//--
	if(draft <= 0) {
		draft = 7 // the default schema
	} //end if
	//--
	schema = smart.StrTrimWhitespaces(schema)
	if(schema == "") {
		return smart.NewError("JSON Schema is Empty")
	} //end if
	//--
	json = smart.StrTrimWhitespaces(json)
	if(json == "") {
		return smart.NewError("JSON is Empty")
	} //end if
	//--
	compiler := jsonschema.NewCompiler()
	//--
	switch(draft) {
		case 4: // fast, but too old
			compiler.Draft = jsonschema.Draft4
			break
		case 6: // fast, but missing some features
			compiler.Draft = jsonschema.Draft6
			break
		case 7: // default, it is the most complete but still fast
			compiler.Draft = jsonschema.Draft7
			break
		case 2019: // slow
			compiler.Draft = jsonschema.Draft2019
			break
		case 2020: // slow
			compiler.Draft = jsonschema.Draft2020
			break
		default:
			return smart.NewError("JSON Schema Invalid Draft Version: " + smart.ConvertUInt16ToStr(draft))
	} //end switch
	//--
	errInit := compiler.AddResource("schema.json", strings.NewReader(schema));
	if(errInit != nil) {
		return smart.NewError("JSON Schema Init Error: " + errInit.Error())
	} //end if
	//--
	compiledSchema, errCompile := compiler.Compile("schema.json")
	if(errCompile != nil) {
		return smart.NewError("JSON Schema Compile Error: " + errCompile.Error())
	} //end if
	//--
	jsonObj, jsonErr := smart.JsonObjDecode(json)
	if(jsonErr != nil) {
		return smart.NewError("JSON Decode Error: " + jsonErr.Error())
	} //end if
	//--
	errValidate := compiledSchema.Validate(jsonObj);
	if(errValidate != nil) {
		return smart.NewError("JSON is Invalid: " + errValidate.Error())
	} //end if
	//--
	return nil
	//--
	//--
} //END FUNCTION


// #END
