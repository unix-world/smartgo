
// GO Lang :: SmartGo / Web Server / GZIP Handler :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260801.2358 :: STABLE

// Req: go 1.16 or later (embed.FS is N/A on Go 1.15 or lower)
package websrv

import (
	"io"
	"net/http"

	smart 			"github.com/unix-world/smartgo"
	smarthttputils 	"github.com/unix-world/smartgo/web/httputils"

	"github.com/unix-world/smartgo/compress/gzip"
)


const (
	CONTENT_TYPE_GZIP string = "gzip"
)


type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	//--
	return w.Writer.Write(b)
	//--
} //END FUNCTION


func gzipHandler(fn http.HandlerFunc) http.HandlerFunc {
	//--
	// IMPORTANT:
	// 	* all the content length headers were disabled in smart http utils / smart web server if content encoding is used
	// 	* but ... if the content is very small and fits in a single buffer, golang will auto-add the content-length, but in the correct size (raw vs gzip differs !) and is ok ... test with this: lib/app-go.css
	// 	* go hack: net/http server permits setting a `Transfer-Encoding: identity` header to disable chunked response writes (and also close connection after reply, which is better for the case of gzip transfer)
	// 	* in the past setting `Transfer-Encoding: identity` was buggy, because was advertised to clients, but now fixed (`Transfer-Encoding` header is completely deleted if set so), see https://github.com/golang/go/issues/49194
	//--
	return func(w http.ResponseWriter, r *http.Request) {
		//-- check if the client can accept the gzip encoding
		var hdrAcceptEncoding string = smart.StrTrimWhitespaces(r.Header.Get(smarthttputils.HTTP_HEADER_CONTENT_AENC)) // accept encoding
		if(smart.StrIContains(hdrAcceptEncoding, CONTENT_TYPE_GZIP) != true) {
			fn(w, r) // The client cannot accept it, so return the output uncompressed
			return
		} //end if
		//-- clear the content length headers, on init only ; this does not work for later writes ...
		w.Header().Del(smarthttputils.HTTP_HEADER_CONTENT_LEN) 						// content length ; for later writes see httputils {{{SYNC-CONTENT-LENGTH-BY-ENCODING}}}
		//-- set the HTTP header indicating encoding
		w.Header().Del(smarthttputils.HTTP_HEADER_CONTENT_SENC) 					// encoding (set)
		w.Header().Set(smarthttputils.HTTP_HEADER_CONTENT_SENC, CONTENT_TYPE_GZIP) 	// encoding (set)
		w.Header().Del(smarthttputils.HTTP_HEADER_TRANSFER_ENCODING)
		w.Header().Set(smarthttputils.HTTP_HEADER_TRANSFER_ENCODING, CONTENT_TYPE_GZIP) // add this header just in case the future Go versions will not delete the `Transfer-Encoding: chunked` header when using the hack `Transfer-Encoding: identity`
		w.Header().Set(smarthttputils.HTTP_HEADER_TRANSFER_ENCODING, smarthttputils.HTTP_HEADER_VALUE_IDENTITY) // net/http: server responds with `Transfer-Encoding: identity`
		//-- prepare the gzip writer
		gz := gzip.NewWriter(w)
		defer gz.Close()
		//-- handle gzip
		fn(gzipResponseWriter{Writer: gz, ResponseWriter: w}, r)
		//--
	} //end fx
	//--
} //END FUNCTION


// #END
