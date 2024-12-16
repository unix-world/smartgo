
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20241216.2358 :: STABLE
// [ YAML (PARSE, COMPOSE) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"github.com/unix-world/smartgo/data-structs/yaml"
)


//-----


func YamlDataParse(yamlData string) (yamlMap map[string]interface{}, errMsg error) {
	//--
	defer PanicHandler() // for YAML Parser
	//--
	yamlData = StrTrimWhitespaces(yamlData)
	if(yamlData == "") {
		return
	} //end if
	yamlData = StrReplaceAll(yamlData, "\r\n", "\n")
	yamlData = StrReplaceAll(yamlData, "\r", "\n")
	yamlData = StrReplaceAll(yamlData, "\t", "    ")
	//--
	errYaml := yaml.Unmarshal([]byte(yamlData), &yamlMap)
	if(errYaml != nil) {
		errMsg = NewError("YAML # Parse Error: " + errYaml.Error())
		yamlMap = nil
	} else if(yamlMap == nil) {
		errMsg = NewError("YAML # Parse Error: Empty Structure")
	} //end if
	//--
	return
	//--
} //END FUNCTION


func YamlDataCompose(yamlMap map[string]interface{}) (yamlData string, errMsg error) {
	//--
	if(yamlMap == nil) {
		errMsg = NewError("YAML Compose # Object is Empty")
		return
	} //end if
	//--
	data, err := yaml.Marshal(yamlMap)
	if(err != nil) {
		errMsg = NewError("YAML # Compose Error: " + err.Error())
		data = nil
	} else if(data == nil) {
		errMsg = NewError("YAML # Compose Error: Empty Structure")
	} //end if
	yamlData = string(data)
	//--
	return
	//--
} //END FUNCTION


//-----


func SafePathYamlFileReadAndParse(yamlFilePath string, allowAbsolutePath bool) (yamlMap map[string]interface{}, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(yamlFilePath) == "") {
		return nil, NewError("YAML File # File Path is Empty")
	} //end if
	//--
	yamlFilePath = SafePathFixClean(yamlFilePath)
	//--
	if(PathIsEmptyOrRoot(yamlFilePath) == true) {
		return nil, NewError("YAML File # File Path is Empty/Root")
	} //end if
	//--
	if((!StrEndsWith(yamlFilePath, ".yaml")) && (!StrEndsWith(yamlFilePath, ".yml"))) {
		return nil, NewError("YAML File # Invalid File Extension, accepted: .yaml ; .yml")
	} //end if
	//--
	yamlData, errYaml := SafePathFileRead(yamlFilePath, allowAbsolutePath)
	if(errYaml != nil) {
		return nil, NewError("YAML File # Read Failed `" + yamlFilePath + "`: " + errYaml.Error())
	} //end if
	if(StrTrimWhitespaces(yamlData) == "") {
		return nil, NewError("YAML File # Content is Empty `" + yamlFilePath + "`")
	} //end if
	//--
	yml, err := YamlDataParse(yamlData)
	if(err != nil) {
		return nil, NewError("YAML File # Parse ERR: " + err.Error() + " # `" + yamlFilePath + "`")
	} //end if
	//--
	return yml, nil
	//--
} //END FUNCTION


//-----


// #END
