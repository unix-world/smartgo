
package mail

// modified by unixman # r.20260915

import (
	"errors"

	"time"
	"bytes"
	"strings"
	"strconv"

	"mime"
	"mime/multipart"

	"io"
	"path/filepath"
)

const (
	maxLineLen int = 76 // As required by RFC 2045, 6.7. (page 21) for quoted-printable, and RFC 2045, 6.8. (page 25) for base64
)


func (w *messageWriter) writeMessage(m *Message) {
	//--
	defer panicHandler()
	//--

	if _, ok := m.header["MIME-Version"]; !ok {
		w.writeString("MIME-Version: 1.0\r\n")
	}
	if _, ok := m.header["Date"]; !ok {
		now := time.Now // unixman: moved from global context to local context
		w.writeHeader("Date", m.FormatDate(now()))
	}
	w.writeHeaders(m.header)

	if m.hasMixedPart() {
		w.openMultipart("mixed", m.boundary)
	}

	if m.hasRelatedPart() {
		w.openMultipart("related", m.rboundary) // unixman, changed from: m.boundary
	}

	if m.hasAlternativePart() {
		w.openMultipart("alternative", m.aboundary) // unixman, changed from: m.boundary
	}
	for _, part := range m.parts {
		w.writePart(part, m.charset)
	}
	if m.hasAlternativePart() {
		w.closeMultipart()
	}

	w.addFiles(m.embedded, false)
	if m.hasRelatedPart() {
		w.closeMultipart()
	}

	w.addFiles(m.attachments, true)
	if m.hasMixedPart() {
		w.closeMultipart()
	}
}


type messageWriter struct {
	w          io.Writer
	n          int64
	writers    [3]*multipart.Writer
	partWriter io.Writer
	depth      uint8
	err        error
}


func (w *messageWriter) openMultipart(mimeType, boundary string) {
	//--
	defer panicHandler()
	//--
	mw := multipart.NewWriter(w)
	if boundary != "" {
		mw.SetBoundary(boundary)
	}
	contentType := "multipart/" + mimeType + ";\r\n boundary=" + `"` + mw.Boundary() + `"` // unixman fix: some mail clients fail to get the boundary value if not enclosed within double quotes
	w.writers[w.depth] = mw

	if w.depth == 0 {
		w.writeHeader("Content-Type", contentType)
		w.writeString("\r\n")
	} else {
		w.createPart(map[string][]string{
			"Content-Type": {contentType},
		})
	}
	w.depth++
}


func (w *messageWriter) createPart(h map[string][]string) {
	//--
	defer panicHandler()
	//--
	w.partWriter, w.err = w.writers[w.depth-1].CreatePart(h)
}


func (w *messageWriter) closeMultipart() {
	//--
	defer panicHandler()
	//--
	if w.depth > 0 {
		w.writers[w.depth-1].Close()
		w.depth--
	}
}


func (w *messageWriter) writePart(p *part, charset string) {
	//--
	defer panicHandler()
	//-- unixman ; {{{SYNC-MIME-UNENCODED-DIGEST-SHA384+SH3A512}}}
	var buf bytes.Buffer
	p.copier(&buf)
	theDigest, encData, theCrc64, encErr := encodeBody(buf.Bytes(), p.encoding)
	if(encErr != nil) {
		w.err = encErr
		return
	}
	var lenData int = len(encData)
	if(lenData <= 0) {
		w.err = errors.New("writePart: Part Content is Empty")
		return
	}
	if(strings.TrimSpace(theDigest) == "") {
		w.err = errors.New("writePart: Part Digest is Empty")
		return
	}
	var theContentId = ""
	if((strings.ToLower(p.contentType) == "text/plain") && (textBodyRegistered != true)) {
		theContentId = "text-body"
		textBodyRegistered = true
	} else if((strings.ToLower(p.contentType) == "text/html") && (htmlBodyRegistered != true)) {
		theContentId = "html-body"
		htmlBodyRegistered = true
	} else {
		theContentId = "part-" + crc64e(encData)
	}
	//-- #
	w.writeHeaders(map[string][]string{
		"Content-Type":              {p.contentType + "; charset=" + charset},
		"Content-Transfer-Encoding": {string(p.encoding)},
		"Content-Id":                {theContentId}, // unixman
		"Content-Length":            {strconv.Itoa(lenData)}, // unixman: length of encoded data
		"Unencoded-Digest":          {theDigest}, // unixman ; {{{SYNC-MIME-UNENCODED-DIGEST-SHA384+SH3A512}}} ; {{{SYNC-CONTENT-DIGEST-UNENCODED}}}
		"X-Unencoded-Crc64e":        {theCrc64}, // unixman ; {{{SYNC-CONTENT-CRC64E-UNENCODED}}}
	})
	w.writeBody(encData)
}


func (w *messageWriter) addFiles(files []*file, isAttachment bool) {
	//--
	defer panicHandler()
	//--
	for _, f := range files {
		if _, ok := f.Header["Content-Type"]; !ok {
			mediaType := mime.TypeByExtension(filepath.Ext(f.Name))
			if mediaType == "" {
				mediaType = "application/octet-stream"
			}
			f.setHeader("Content-Type", mediaType+`; name="`+f.Name+`"`)
		}

		if _, ok := f.Header["Content-Transfer-Encoding"]; !ok {
			f.setHeader("Content-Transfer-Encoding", string(Base64))
		}

		if _, ok := f.Header["Content-Disposition"]; !ok {
			var disp string
			if isAttachment {
				disp = "attachment"
			} else {
				disp = "inline"
			}
			f.setHeader("Content-Disposition", disp+`; filename="`+f.Name+`"`)
		}

		if !isAttachment {
			if _, ok := f.Header["Content-Id"]; !ok {
				f.setHeader("Content-Id", "<"+f.Name+">")
			}
		}
		//-- unixman ; {{{SYNC-MIME-UNENCODED-DIGEST-SHA384+SH3A512}}}
		var buf bytes.Buffer
		f.CopyFunc(&buf)
		theDigest, encData, theCrc64, encErr := encodeBody(buf.Bytes(), Base64)
		if(encErr != nil) {
			w.err = encErr
			return
		}
		var lenData int = len(encData)
		if(lenData <= 0) {
			w.err = errors.New("addFiles: File Content is Empty")
			return
		}
		if(strings.TrimSpace(theDigest) == "") {
			w.err = errors.New("addFiles: File Digest is Empty")
			return
		}
		//--
		f.setHeader("Content-Length", strconv.Itoa(lenData)) // unixman
		f.setHeader("Unencoded-Digest", theDigest) // unixman ; {{{SYNC-MIME-UNENCODED-DIGEST-SHA384+SH3A512}}} ; {{{SYNC-CONTENT-DIGEST-UNENCODED}}}
		f.setHeader("X-Unencoded-Crc64e", theCrc64) // unixman ; {{{SYNC-CONTENT-CRC64E-UNENCODED}}}
		//--
		w.writeHeaders(f.Header)
		w.writeBody(encData)
		//-- #
	}
}


func (w *messageWriter) Write(p []byte) (int, error) {
	//--
	defer panicHandler()
	//--

	if w.err != nil {
		return 0, errors.New("gomail: cannot write as writer is in error")
	}

	var n int
	n, w.err = w.w.Write(p)
	w.n += int64(n)
	return n, w.err
}


func (w *messageWriter) writeString(s string) {
	//--
	defer panicHandler()
	//--

	if w.err != nil { // do nothing when in error
		return
	}
	var n int
	n, w.err = io.WriteString(w.w, s)
	w.n += int64(n)
}


func (w *messageWriter) writeHeader(k string, v ...string) {
	//--
	defer panicHandler()
	//--

	//--
	w.writeString(k)
	//--
	if len(v) <= 0 {
		w.writeString(":\r\n")
		return
	}
	//--
	w.writeString(": ")
	//-- unixman: fix for QP or B64 if all encoded split by `?= =?`
	var numAllParts uint64 = 0
	var isAllEncoded uint64 = 0
	for _, s := range v {
		numAllParts++
		if strings.HasPrefix(s, "=?") && strings.HasSuffix(s, "?=") {
			isAllEncoded++
		}
	}
	if(isAllEncoded == numAllParts) {
		for _, s := range v {
			s = normalizeStrOnlySpaces(s)
			s = normalizeStrLineEndings(s)
			s = strings.Replace(s, "\n", " ", -1) // replace all (limit is -1)
			s = strings.TrimSpace(s)
			s = strings.Replace(s, `?= =?`, `?=` + "\r\n" + " " + `=?`, -1) // replace all (limit is -1)
			w.writeString(s + "\r\n")
		}
		return
	} //end if
	//-- #
	charsLeft := 76 - len(k) - len(": ") // Max header line length is 78 characters in RFC 5322 and 76 characters in RFC 2047. So for the sake of simplicity we use the 76 characters limit.
	//--
	for i, s := range v {
		//-- unixman
		s = normalizeStrOnlySpaces(s)
		s = normalizeStrLineEndings(s)
		s = strings.Replace(s, "\n", " ", -1) // replace all (limit is -1)
		s = strings.TrimSpace(s)
		//-- #
		if charsLeft < 1 { // If the line is already too long, insert a newline right away.
			if i == 0 {
				w.writeString("\r\n ")
			} else {
				w.writeString(",\r\n ")
			}
			charsLeft = 75
		} else if i != 0 {
			w.writeString(", ")
			charsLeft -= 2
		}
		//-- While the header content is too long, fold it by inserting a newline.
		for len(s) > charsLeft {
			s = w.writeLine(s, charsLeft)
			charsLeft = 75
		}
		w.writeString(s)
		if i := lastIndexByte(s, '\n'); i != -1 {
			charsLeft = 75 - (len(s) - i - 1)
		} else {
			charsLeft -= len(s)
		}
		//--
	}
	//--
	w.writeString("\r\n")
	//--
}


func (w *messageWriter) writeLine(s string, charsLeft int) string {
	//--
	defer panicHandler()
	//--

	// If there is already a newline before the limit. Write the line.
//	if i := strings.IndexByte(s, '\n'); i != -1 && i < charsLeft {
	if i := strings.IndexByte(s, '\n'); i > -1 && i < charsLeft { // unixman
		w.writeString(s[:i+1])
		return s[i+1:]
	}

	for i := charsLeft - 1; i >= 0; i-- {
		if s[i] == ' ' {
			w.writeString(s[:i])
			w.writeString("\r\n ")
			return s[i+1:]
		}
	}

	// We could not insert a newline cleanly so look for a space or a newline even if it is after the limit.
	for i := 75; i < len(s); i++ {
		if s[i] == ' ' {
			w.writeString(s[:i])
			w.writeString("\r\n ")
			return s[i+1:]
		}
		if s[i] == '\n' {
			w.writeString(s[:i+1])
			return s[i+1:]
		}
	}

	// Too bad, no space or newline in the whole string. Just write everything.
	w.writeString(s)
	return ""
}


func (w *messageWriter) writeHeaders(h map[string][]string) {
	//--
	defer panicHandler()
	//--

	if w.depth == 0 {
		for k, v := range h {
			if strings.ToLower(strings.TrimSpace(k)) != "bcc" { // this must be protected
				w.writeHeader(k, v...)
			}
		}
	} else {
		w.createPart(h)
	}
}


func (w *messageWriter) writeBody(data []byte) { // modified by unixman
	//--
	defer panicHandler()
	//--

	var subWriter io.Writer
	if w.depth == 0 {
		w.writeString("\r\n")
		subWriter = w.w
	} else {
		subWriter = w.partWriter
	}
	if(subWriter == nil) {
		w.err = errors.New("writeBody: subWriter is Null")
		return
	}
	if(len(data) <= 0) {
		w.err = errors.New("writeBody: Body data is Empty")
		return
	}
	_, w.err = subWriter.Write(data)
}


// #end
