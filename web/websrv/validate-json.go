
// GO Lang :: SmartGo / Web Server / JSON-Validate :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241128.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	smart 		"github.com/unix-world/smartgo"

	jsonschema 	"github.com/unix-world/smartgo/web/jsonschema"
)


func JsonValidateWithSchema(draft uint16, schema string, json string) error { // if OK returns TRUE
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
	var sDraft *jsonschema.Draft
	switch(draft) {
		case 4: // fast, but too old
			sDraft = jsonschema.Draft4
		case 6: // fast, but missing some features
			sDraft = jsonschema.Draft6
		case 7: // default, it is the most complete but still fast
			sDraft = jsonschema.Draft7
		case 2019: // slow
			sDraft = jsonschema.Draft2019
		case 2020: // slow
			sDraft = jsonschema.Draft2020
		default:
			return smart.NewError("JSON Schema Invalid Draft Version: " + smart.ConvertUInt16ToStr(draft))
	} //end switch
	//--
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(sDraft)
	//--
	schJson, errParseSchema := smart.JsonObjDecode(schema)
	if(errParseSchema != nil) {
		return smart.NewError("JSON Schema Parse Error: " + errParseSchema.Error())
	} //end if
	errInit := compiler.AddResource("schema.json", schJson);
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
} //END FUNCTION


// #END
