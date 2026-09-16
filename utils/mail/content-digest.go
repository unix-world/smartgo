
package mail

// added by unixman # r.20260915
// {{{SYNC-MIME-UNENCODED-DIGEST-SHA384+SH3A512}}}

import (
	"strings"

	"encoding/base64"
	"crypto/sha512"
	"github.com/unix-world/smartgo/crypto/sha3" // {{{SYNC-SMARTGO-SHA3}}}
)


func shaByt384B64(src []byte) string {
	//--
	hash := sha512.New384()
	//--
	hash.Write(src)
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func sh3aByt512B64(src []byte) string {
	//--
	hash := sha3.New512()
	//--
	hash.Write(src)
	//--
	return base64.StdEncoding.EncodeToString(hash.Sum(nil))
	//--
} //END FUNCTION


func createDigest(data []byte) string {
	//--
	if(data == nil) {
		data = []byte{}
	} //end if
	//--
	var lenOfUnencodedDigestKey int = 27 // `Unencoded-Digest: sha-384=:`
	var hashSha384 string = strings.TrimSpace(strings.Replace(string(chunkSplitB64BytesByLine([]byte(shaByt384B64(data)), maxLineLen - lenOfUnencodedDigestKey)), "\r\n", "\r\n ", -1))
	lenOfUnencodedDigestKey = 29 // for the rest, calculated exactly ... ;-)
	var hashSh3a512 string = strings.TrimSpace(strings.Replace(string(chunkSplitB64BytesByLine([]byte(sh3aByt512B64(data)), maxLineLen - lenOfUnencodedDigestKey)), "\r\n", "\r\n ", -1))
	//--
	return "sha-384=" + ":" + hashSha384 + ":" + ", " + "sha3-512=" + ":" + hashSh3a512 + ":"
	//--
} //END FUNCTION


// #end
