
// GO Lang :: SmartGo / Web Server / ZSTD Handler :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260829.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"log"

	"io"
	"net/http"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"

	"github.com/unix-world/smartgo/compress/zstd"
)


const (
	CONTENT_TYPE_ZSTD string = "zstd"

	concurrency int = 0
)


type zstdResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w zstdResponseWriter) Write(b []byte) (int, error) {
	//--
	defer smart.PanicHandler()
	//--
	return w.Writer.Write(b)
	//--
} //END FUNCTION


func zstdHandleWrite(w http.ResponseWriter, r *http.Request, fn http.HandlerFunc) {
	//--
	defer smart.PanicHandler()
	//-- prepare the zstd writer ; if error, fallback to plain/uncompressed mode and log the error
	zst, errInit := zstd.NewWriter(w, zstd.WithEncoderCRC(true), zstd.WithEncoderConcurrency(concurrency), zstd.WithEncoderLevel(zstd.SpeedDefault)) // can be: zstd.SpeedDefault or zstd.SpeedFastest
	if(errInit != nil) { // error check and fallback to plaiin uncompressed if there is init error must be done before the below modifications for the heders, otherwise below headers are wrong !
		log.Println("[FATAL]", smart.CurrentFunctionName(), "ZSTD Writer Init Error:", errInit)
		fn(w, r) // there was an error enabling zstd, so return the output uncompressed
		return
	} //end if
	defer zst.Close()
	//--
	// IMPORTANT:
	// 	* all the content length headers were disabled in smart http utils / smart web server if content encoding is used
	// 	* but ... if the content is very small and fits in a single buffer, golang will auto-add the content-length, but in the correct size (raw vs zstd differs !) and is ok ... test with this: lib/app-go.css
	// 	* go hack: net/http server permits setting a `Transfer-Encoding: identity` header to disable chunked response writes (and also close connection after reply, which is better for the case of zstd transfer)
	// 	* in the past setting `Transfer-Encoding: identity` was buggy, because was advertised to clients, but now fixed (`Transfer-Encoding` header is completely deleted if set so), see https://github.com/golang/go/issues/49194
	//-- clear the content length headers, on init only ; this does not work for later writes ...
	w.Header().Del(smarthttputils.HTTP_HEADER_CONTENT_LEN) 						// content length ; for later writes see httputils {{{SYNC-CONTENT-LENGTH-BY-ENCODING}}}
	//-- set the HTTP header indicating encoding
	w.Header().Del(smarthttputils.HTTP_HEADER_CONTENT_SENC) 					// encoding (set)
	w.Header().Set(smarthttputils.HTTP_HEADER_CONTENT_SENC, CONTENT_TYPE_ZSTD) 	// encoding (set)
	w.Header().Del(smarthttputils.HTTP_HEADER_TRANSFER_ENCODING)
	w.Header().Set(smarthttputils.HTTP_HEADER_TRANSFER_ENCODING, CONTENT_TYPE_ZSTD) // add this header just in case the future Go versions will not delete the `Transfer-Encoding: chunked` header when using the hack `Transfer-Encoding: identity`
	w.Header().Set(smarthttputils.HTTP_HEADER_TRANSFER_ENCODING, smarthttputils.HTTP_HEADER_VALUE_IDENTITY) // net/http: server responds with `Transfer-Encoding: identity`
	w.Header().Set("z-compressed", "zstd")
	//-- handle zstd
	fn(zstdResponseWriter{Writer: zst, ResponseWriter: w}, r) // handle zstd compressed output
	//--
} //END FUNCTION


func zstdHandler(fn http.HandlerFunc) http.HandlerFunc {
	//--
	defer smart.PanicHandler()
	//--
	return func(w http.ResponseWriter, r *http.Request) {
		//--
		defer smart.PanicHandler()
		//-- check if the client can accept the zstd encoding, otherwise fall back to plain uncompressed
		arrList := parseHdrAceptEncodingToList(r.Header.Get(smarthttputils.HTTP_HEADER_CONTENT_AENC)) // accept encoding header, parse
		//-- try to see what client accepts
		if(smart.InListArr(CONTENT_TYPE_ZSTD, arrList)) { // client accepts zstd
			zstdHandleWrite(w, r, fn) // zstd
			return
		} //end if
		//-- plain, no support for zstd
		fn(w, r) // fallback to plain uncompressed, client does not accept zstd
		return
		//--
	} //end fx
	//--
} //END FUNCTION


// #END
