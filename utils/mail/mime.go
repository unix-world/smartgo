
package mail

import (
	"mime"
	"mime/quotedprintable"
	"strings"
)

var newQPWriter = quotedprintable.NewWriter

type mimeEncoder struct {
	mime.WordEncoder
}

var (
	bEncoding     = mimeEncoder{mime.BEncoding}
	qEncoding     = mimeEncoder{mime.QEncoding}
	lastIndexByte = strings.LastIndexByte
)
