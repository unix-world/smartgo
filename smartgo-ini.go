
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260111.2358 :: STABLE
// [ INI (PARSE) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"github.com/unix-world/smartgo/data-structs/parseini"
)


//-----


func IniContentParse(iniContent string, iniKeys []string) (iniMap map[string]string, errMsg error) {
	//--
	defer PanicHandler()
	//-- no panic handler needed
	iniData, errParseIni := parseini.Load(iniContent)
	if(errParseIni != nil) {
		return nil, NewError("INI # Parse Error: " + errParseIni.Error())
	} //end if
	//--
	var strReplacements map[string]string = map[string]string{
		`\\r`: "\r",
		`\\n`: "\n",
		`\\t`: "\t",
	}
	//--
	var settings map[string]string = map[string]string{}
	if(iniKeys != nil) { // get all these keys ; if key does not exist will fill it with an empty string ; ex: []string where each value is "section:key"
		for i := 0; i < len(iniKeys); i++ {
			if(StrContains(iniKeys[i], ":")) {
				sk := Explode(":", iniKeys[i])
				if(len(sk) == 2) {
					sk[0] = StrTrimWhitespaces(sk[0])
					sk[1] = StrTrimWhitespaces(sk[1])
					if((sk[0] != "") && (sk[1] != "")) {
						settings[sk[0] + ":" + sk[1]] = StrTr(parseini.GetIniStrVal(iniData, sk[0], sk[1]), strReplacements)
					} //end if
				} //end if
			} //end if
		} //end for
	} else { // get all existing keys from ini
		for k, v := range iniData {
			if(v != nil) {
				for kk, _ := range v {
					k = StrTrimWhitespaces(k)
					kk = StrTrimWhitespaces(kk)
					if((k != "") && (kk != "")) {
						settings[k + ":" + kk] = StrTr(parseini.GetIniStrVal(iniData, k, kk), strReplacements)
					} //end if
				} //end for
			} //end if
		} //end for
	} //end if else
	//--
	return settings, nil
	//--
} //END FUNCTION


//-----


func SafePathIniFileReadAndParse(iniFilePath string, allowAbsolutePath bool, iniKeys []string) (iniMap map[string]string, errMsg error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(iniFilePath) == "") {
		return nil, NewError("INI File # File Path is Empty")
	} //end if
	//--
	iniFilePath = SafePathFixClean(iniFilePath)
	//--
	if(PathIsEmptyOrRoot(iniFilePath) == true) {
		return nil, NewError("INI File # File Path is Empty/Root")
	} //end if
	//--
	if(!StrEndsWith(iniFilePath, ".ini")) {
		return nil, NewError("INI File # Invalid File Extension, accepted: .ini")
	} //end if
	//--
	iniContent, iniFileErr := SafePathFileRead(iniFilePath, allowAbsolutePath)
	if(iniFileErr != nil) {
		return nil, NewError("INI File # Read Failed `" + iniFilePath + "`: " + iniFileErr.Error())
	} //end if
	if(StrTrimWhitespaces(iniContent) == "") {
		return nil, NewError("INI File # Content is Empty `" + iniFilePath + "`")
	} //end if
	//--
	dat, err := IniContentParse(iniContent, iniKeys)
	if(err != nil) {
		return nil, NewError("INI File # Parse ERR: " + err.Error() + " # `" + iniFilePath + "`")
	} //end if
	//--
	return dat, nil
	//--
} //END FUNCTION


//-----


// #END
