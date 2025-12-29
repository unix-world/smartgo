
// GO Lang :: SmartGo / Web Server / WebApp-Settings :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20251216.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	smart "github.com/unix-world/smartgo"
)


var webappSettings map[string]string = nil // need to be initialized to null


func GetWebAppSetting(key string) (string, error) {
	//--
	defer smart.PanicHandler() // various
	//--
	if((webappSettings == nil) || (len(webappSettings) <= 0)) {
		return "", smart.NewError("WebApp Settings are Empty or Null")
	} //end if
	//--
	key = smart.StrTrimWhitespaces(key)
	if(key == "") {
		return "", smart.NewError("Custom Settings: The search key is empty")
	} //end if
	//--
	value, ok := webappSettings[key]
	if(!ok) {
		return "", smart.NewError("Missing Settings for key: " + key)
	} //end if
	//--
	return value, nil // do not trim, values are parsed by \r \n \t and trimmed in SmartGo INI
	//--
} //END FUNCTION


func GetWebAppSettings() map[string]string {
	//--
	return webappSettings
	//--
} //END FUNCTION


func SetWebAppSettings(appSettingsIni string) error {
	//--
	defer smart.PanicHandler() // various
	//--
	const iniFilePath string = "./settings-custom.ini"
	//--
	setts, err := smart.IniContentParse(appSettingsIni, nil)
	if(err != nil) {
		return err
	} //end if
	if(setts == nil) { // do not check here for (len(setts) <= 0)
		return smart.NewError("App Settings are Null") // no settings
	} //end if
	//--
	webappSettings = setts
	//--
//	log.Println("[DEBUG]", smart.CurrentFunctionName(), "webappSettings:", webappSettings)
	//--
	return nil
	//--
} //END FUNCTION


// #END
