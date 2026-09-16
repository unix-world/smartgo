
// GO Lang :: SmartGo / Web Server / ANY Handler (Zstd or Gzip or Plain, in this order) :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260829.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"net/http"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"
)


func parseHdrAceptEncodingToList(str string) []string {
	//--
	defer smart.PanicHandler()
	//--
	arrList := []string{}
	//--
	str = smart.StrTrimWhitespaces(str)
	if(str == "") {
		return arrList
	} //end if
	if(len(str) > 4096) { // something is wrong
		return arrList
	} //end if
	//--
	str = smart.StrToLower(str)
	if(!smart.StrContains(str, ",")) {
		arrList = append(arrList, str)
		return arrList
	} //end i
	arrStr := smart.Explode(",", str)
	if(len(arrStr) > 0) {
		for i:=0; i<len(arrStr); i++ {
			arrStr[i] = smart.StrTrimWhitespaces(arrStr[i])
			if(arrStr[i] != "") {
				arrList = append(arrList, arrStr[i])
			} //end if
		} //end for
	} //end if
	//--
	return arrList
	//--
} //END FUNCTION


func anyHandler(fn http.HandlerFunc) http.HandlerFunc {
	//--
	defer smart.PanicHandler()
	//--
	return func(w http.ResponseWriter, r *http.Request) {
		//--
		defer smart.PanicHandler()
		//-- check if the client can accept the zstd or gzip encoding, if not fallback to plain
		arrList := parseHdrAceptEncodingToList(r.Header.Get(smarthttputils.HTTP_HEADER_CONTENT_AENC)) // accept encoding header, parse
		//-- try to see what client accepts
		if(smart.InListArr(CONTENT_TYPE_ZSTD, arrList)) { // zstd
			zstdHandleWrite(w, r, fn)
			return
		} else if(smart.InListArr(CONTENT_TYPE_GZIP, arrList)) { // gzip
			gzipHandleWrite(w, r, fn)
			return
		} //end if else
		//-- plain, no support for zstd or gzip
		fn(w, r) // fallback to plain uncompressed, client does not accept zstd or gzip
		return
		//--
	} //end fx
	//--
} //END FUNCTION


// #END
