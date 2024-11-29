
// GO Lang :: SmartGo / Web Server / API :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20241128.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	smart "github.com/unix-world/smartgo"
)


type apiMsgStruct struct {
	ErrCode uint16 `json:"errCode,omitempty"`
	ErrMsg  string `json:"errMsg,omitempty"`
	Data       any `json:"data,omitempty"`
}


func ResponseApiJsonERR(errCode uint16, errMsg string, data any) string {
	//--
	if(errCode <= 0) {
		errCode = apiErrorDefaultCode
	} //end if
	errMsg = smart.StrTrimWhitespaces(errMsg)
	if(errMsg == "") {
		errMsg = apiErrorDefaultMsg
	} //end if
	//--
	resp := apiMsgStruct{
		ErrCode: errCode,
		ErrMsg:  errMsg,
		Data:    data,
	}
	//--
	return smart.JsonNoErrChkEncode(resp, false, false)
	//--
} //END FUNCTION


func ResponseApiJsonOK(data any) string {
	//--
	resp := apiMsgStruct{
		ErrCode: 0,
		ErrMsg:  "",
		Data:    data,
	}
	//--
	return smart.JsonNoErrChkEncode(resp, false, false)
	//--
} //END FUNCTION


// #END
