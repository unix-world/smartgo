
// GO Lang :: SmartGo / Web Server / Utils :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241116.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"time"
	"strings"
	"net/http"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
	jsonschema 		"github.com/unix-world/smartgo/web/jsonschema"
)


func GetCookie(r *http.Request, name string) string {
	//--
	return smarthttputils.HttpRequestGetCookie(r, name)
	//--
} //END FUNCTION


func GetUrlQueryParam(r *http.Request, param string) string {
	//--
	param = smart.StrTrimWhitespaces(param)
	if(param == "") {
		return ""
	} //end if
	//--
	return r.URL.Query().Get(param)
	//--
} //END FUNCTION


func GetBaseDomainDomainPort(r *http.Request) (string, string, string, error) {
	//--
	// returns: basedom, dom, port, errDomPort
	//--
	dom, port, errDomPort := smart.GetHttpDomainAndPortFromRequest(r)
	if(errDomPort != nil) {
		return "", "", "", errDomPort
	} //end if
	if(smart.StrTrimWhitespaces(dom) == "") {
		return "", "", "", smart.NewError("Domain is Empty")
	} //end if
	if(smart.StrTrimWhitespaces(port) == "") {
		return "", "", "", smart.NewError("Port is Empty")
	} //end if
	baseDom, errBaseDom := smart.GetBaseDomainFromDomain(dom)
	if(errBaseDom != nil) {
		return "", "", "", errBaseDom
	} //end if
	if(smart.StrTrimWhitespaces(baseDom) == "") {
		return "", "", "", smart.NewError("Base Domain is Empty")
	} //end if
	//--
	return baseDom, dom, port, nil
	//--
} //END FUNCTION


func GetBasePath() string { // includes trailing slashes
	//--
	return smart.GetHttpProxyBasePath() // if no proxy, this is: `/` ; but under proxy may be the same or as: `/custom-path/`
	//--
} //END FUNCTION


func GetCurrentPath(r *http.Request) string { // this does not include the proxy prefix, it is the internal path
	//--
	return smart.GetHttpPathFromRequest(r)
	//--
} //END FUNCTION


func GetCurrentBrowserPath(r *http.Request) string { // this includes the proxy prefix
	//--
	return smart.GetHttpBrowserPathFromRequest(r)
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
