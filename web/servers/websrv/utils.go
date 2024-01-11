
// GO Lang :: SmartGo / Web Server / Utils :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240111.1742 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"time"
	"strings"
	"net/http"

	smart 		"github.com/unix-world/smartgo"
	jsonschema 	"github.com/unix-world/smartgo/web/jsonschema"
)


func GetBasePath() string {
	//--
	return smart.GetHttpProxyBasePath()
	//--
} //END FUNCTION


func GetCurrentYear() string {
	//--
	return smart.ConvertIntToStr(time.Now().UTC().Year())
	//--
} //END FUNCTION


func RequestHaveQueryString(r *http.Request) bool {
	//--
	defer smart.PanicHandler()
	//--
	return (len(r.URL.RawQuery) > 0)
	//--
} //END FUNCTION


func JsonValidateWithSchema(schema string, json string) error { // if OK returns TRUE
	//--
	schema = smart.StrTrimWhitespaces(schema)
	json = smart.StrTrimWhitespaces(json)
	//--
	if(schema == "") {
		return smart.NewError("JSON Schema is Empty")
	} //end if
	if(json == "") {
		return smart.NewError("JSON is Empty")
	} //end if
	//--
	compiler := jsonschema.NewCompiler()
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
} //END FUNCTION


// #END
