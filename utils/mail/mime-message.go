
package mail

// modified by unixman # r.20260915

import (
//	"fmt"
	"errors"

	"time"

	"bytes"
	"strings"

	"io"

	"mime"
	"net/textproto"

	"os"
	"path/filepath"

	dkim "github.com/unix-world/smartgo/mx/dkim"
)

const (
	VERSION string = "20260915"

	// Base64 represents the base64 encoding as defined in RFC 2045
	Base64 Encoding = "base64"

	// QuotedPrintable represents the quoted-printable encoding as defined in RFC 2045
	QuotedPrintable Encoding = "quoted-printable"

	// Unencoded can be used to avoid encoding the body of an email.
	Unencoded Encoding = "8bit"

	PrefixEpilogue string = "X-Epilogue-"
)

var (
	bEncoding     = mimeEncoder{mime.BEncoding}
	qEncoding     = mimeEncoder{mime.QEncoding}
	lastIndexByte = strings.LastIndexByte
)


type mimeEncoder struct {
	mime.WordEncoder
}


// Encoding represents a MIME encoding scheme like quoted-printable or base64.
type Encoding string


// Message represents an email.
type Message struct {
	header      header
	haveBody    bool
	haveAlt     bool
	parts       []*part
	attachments []*file
	embedded    []*file
	charset     string
	encoding    Encoding
	bodyencqp   bool
	hEncoder    mimeEncoder
	buf         bytes.Buffer
	boundary    string
	aboundary   string // unixman
	rboundary   string // unixman
}


type header map[string][]string


type part struct {
	contentType string
	copier      func(io.Writer) error
	encoding    Encoding
}


// NewMessage creates a new message. It uses UTF-8 and quoted-printable encoding
// by default.
func NewMessage(enc Encoding, mainEncQp bool, settings ...MessageSetting) *Message {
	//--
	defer panicHandler()
	//--
	m := &Message{
		header:   make(header),
		charset:  "UTF-8",
		encoding: enc, // modified by unixman
	}

	m.applySettings(settings)

	if(mainEncQp == true) { // by unixman, option to encode headers and the main body using QP encoding (no matter what encoding is selected for the bodies/embedds/attachments) ...
		m.hEncoder = qEncoding
		m.bodyencqp = true // in this mode if there is an alternate body also use QP encoding ;-) ... better for antispam
	} else {
		if m.encoding == QuotedPrintable {
			m.hEncoder = qEncoding
		} else if m.encoding == Base64 {
			m.hEncoder = bEncoding
		}
	}

	return m
}


// Reset resets the message so it can be reused. The message keeps its previous settings so it is in the same state that after a call to NewMessage.
func (m *Message) Reset() {
	for k := range m.header {
		delete(m.header, k)
	}
	m.parts = nil
	m.attachments = nil
	m.embedded = nil
}


func (m *Message) applySettings(settings []MessageSetting) {
	for _, s := range settings {
		s(m)
	}
}


// A MessageSetting can be used as an argument in NewMessage to configure an email.
type MessageSetting func(m *Message)


// SetCharset is a message setting to set the charset of the email.
func SetCharset(charset string) MessageSetting {
	return func(m *Message) {
		m.charset = charset
	}
}


// SetEncoding is a message setting to set the encoding of the email.
func SetEncoding(enc Encoding) MessageSetting {
	return func(m *Message) {
		m.encoding = enc
	}
}


//-- unixman
type MessageXtraEpilogueFn func(bytMsg []byte, chainChecksum string) (map[string]string, error)

func GetComposedMessageContent(m *Message, dkimOpts *dkim.SignOptions, dkimVfyOpts *dkim.VerifyOptions, msgXtraEpilogueFn MessageXtraEpilogueFn) ([]byte, []string, error) {
	//--
	defer panicHandler()
	//--
	if(m == nil) {
		return nil, nil, errors.New("Mesage is Null")
	} //end if
	//--
	var buf bytes.Buffer
	w := io.Writer(&buf)
	mw := &messageWriter{w: w}
	mw.writeMessage(m)
	if(mw.err != nil) {
		return nil, nil, mw.err
	} //end if
	if(mw.n <= 0) {
		return nil, nil, errors.New("Mesage write failed")
	} //end if
	//--
	var bytMsg []byte = buf.Bytes()
	var lenMsg int64 = int64(len(bytMsg))
	if(lenMsg <= 0) {
		return nil, nil, errors.New("Mesage is empty, write failed")
	} //end if
	if(lenMsg != mw.n) {
		return nil, nil, errors.New("Mesage is incomplete, write was truncated")
	} //end if
	//--
	var signature string = "X-MimeMessage-Composer: Smart.Go.MimeComposer.v" + VERSION + "\r\n"
	bytMsg = append(bytMsg, []byte(signature)...)
	//--
//	fmt.Println("`" + string(bytMsg) + "`")
	var theCrc64e  string = crc64e(bytMsg)
	var theSh3a512 string = sh3aByt512B64(bytMsg)
	var theSha384  string = shaByt384B64(append([]byte(theSh3a512 + "\f" + theCrc64e + "\v"), bytMsg...)) // {{{SYNC-MIME-MESSAGE-SHA384-CHAINING}}}
	//--
	bytMsg = append(bytMsg, []byte("X-MimeMessage-Epilogue-Start: #" + "\r\n")...)
	//--
	var hdrCrc64e string = "X-MimeMessage-Crc64e: " + theCrc64e + "\r\n"
	bytMsg = append(bytMsg, []byte(hdrCrc64e)...)
	//--
	var hdrSh3a512 string = strings.Replace(string(chunkSplitB64BytesByLine([]byte("X-MimeMessage-CheckSum-Sha3-512: " + theSh3a512), maxLineLen)), "\r\n", "\r\n ", -1) + "\r\n"
	bytMsg = append(bytMsg, []byte(hdrSh3a512)...)
	//--
	var hdrSha384 string = strings.Replace(string(chunkSplitB64BytesByLine([]byte("X-MimeMessage-Chained-CheckSum-Sha-384: " + theSha384), maxLineLen)), "\r\n", "\r\n ", -1) + "\r\n"
	bytMsg = append(bytMsg, []byte(hdrSha384)...)
	//--
	if(msgXtraEpilogueFn != nil) { // normally this part is intended for signatures or send logs
		arrEpilogue, errXtraEpilogue := msgXtraEpilogueFn(bytMsg, theSha384)
		if(errXtraEpilogue != nil) {
			return nil, nil, errors.New("Message XTRA Epilogue Fn returned an Error: " + errXtraEpilogue.Error())
		} //end if
		if(len(arrEpilogue) > 0) {
			for eK, eV := range arrEpilogue {
				eK = normalizeStrOnlySpaces(eK)
				eK = normalizeStrLineEndings(eK)
				eK = strings.Replace(eK, "\n", " ", -1) // replace all (limit is -1)
				eK = strings.TrimSpace(eK)
				eK = strings.TrimSpace(textproto.CanonicalMIMEHeaderKey(eK))
				if(eK != "") {
					eV = normalizeStrOnlySpaces(eV)
					eV = normalizeStrLineEndings(eV)
					eV = strings.Replace(eV, "\n", "\r\n ", -1) // replace all (limit is -1)
					eV = strings.TrimSpace(eV)
					if(eV != "") {
						if(len(eV) <= 65535) { // Dilithium 5 signature length is 4.595 bytes raw which encodes to ~ 6.128 characters in base64 format ; also logs can be longer ... ; golang max header size is: 10485760 ~ 1MB ; (maxMIMEHeaderSize = 10 << 20) as hardcoded in `mime/multipart/multipart.go`
							if(strRegexMatch(`^[[:graph:] \r\n]+$`, eV)) {
								bytMsg = append(bytMsg, []byte(PrefixEpilogue + eK + ": " + eV + "\r\n")...)
							} //end if
						} //end if
					} //end if
				} //end if
			} //end for
		} //end if
	} //end if
	//--
	bytMsg = append(bytMsg, []byte("X-MimeMessage-Epilogue-End: #" + "\r\n")...)
	//--
	var dkimVerifications []string
	//--
	if(dkimOpts != nil) {
		//--
		dkimSignature, errDkimSignature := dkim.SignMimeMessage(dkimOpts, bytMsg)
		if(errDkimSignature != nil) {
			return nil, dkimVerifications, errDkimSignature
		} //end if
		//--
		dkimSignature = strings.TrimSpace(dkimSignature)
		if(dkimSignature == "") {
			return nil, dkimVerifications, errors.New("DKIM Message Sign: Signature is Empty")
		} //end if
		//--
		var bytSygnedMsg []byte = []byte(dkimSignature + "\r\n")
		bytMsg = append(bytSygnedMsg, bytMsg...)
		bytSygnedMsg = nil // free mem
		//--
		if(dkimVfyOpts != nil) {
			dkimVerifications = []string{}
			ok, verifications, err := dkim.VerifySignedMimeMessage(dkimVfyOpts, bytMsg)
			if(len(verifications) > 0) {
				for _, v := range verifications {
					if(v != nil) {
						if(v.Err != nil) {
							dkimVerifications = append(dkimVerifications, "FAIL: DKIM Signature is Invalid for domain: `" + v.Domain + "` # ERR: " + v.Err.Error())
						} else {
							dkimVerifications = append(dkimVerifications, "OK: DKIM Signature is Valid for domain: `" + v.Domain + "`")
						} //end if else
					} //end if
				} //end for
			} //end if
			if(err != nil) {
				return nil, dkimVerifications, errors.New("DKIM Signature is Invalid: " + err.Error())
			} //end if
			if(len(verifications) <= 0) {
				return nil, dkimVerifications, errors.New("No DKIM Signature Verified")
			} //end if
			if(!ok) {
				return nil, dkimVerifications, errors.New("DKIM Signature is Invalid")
			} //end if
		} //end if
		//--
	} //end if
	//--
	return bytMsg, dkimVerifications, nil
	//--
} //END FUNCTION
//-- #


func (m *Message) SetCharset(charset string) {
	m.charset = charset
}


func (m *Message) SetEncoding(enc Encoding) {
	m.encoding = enc
}


// SetABoundary sets a custom multipart boundary for alternative parts.
func (m *Message) SetABoundary(aboundary string) {
	m.aboundary = aboundary
}


// SetBoundary sets a custom multipart boundary for related parts.
func (m *Message) SetRBoundary(rboundary string) {
	m.rboundary = rboundary
}
//-- #


// SetBoundary sets a custom multipart boundary, default.
func (m *Message) SetBoundary(boundary string) {
	m.boundary = boundary
}


// SetHeader sets a value to the given header field.
func (m *Message) SetHeader(field string, value ...string) {
	m.encodeHeader(value)
	m.header[field] = value
}


func (m *Message) encodeHeader(values []string) {
	for i := range values {
		values[i] = m.encodeString(values[i])
	}
}


func (m *Message) encodeString(value string) string {
	//--
	defer panicHandler()
	//-- unixman
	if m.hEncoder == bEncoding { // base64
		//--
		return m.hEncoder.Encode(m.charset, value) // base64, encode
		//--
	} else if m.hEncoder == qEncoding { // quoted-printable
		//--
		value = normalizeStrOnlySpaces(value) // quoted-printable, pre-normalize only spaces
		value = normalizeStrLineEndings(value) // quoted-printable, pre-normalize line endings
		return m.hEncoder.Encode(m.charset, value) // quoted-printable, encode
		//--
	} //end if else
	//--
	value = normalizeStrOnlySpaces(value) // 8bit, pre-normalize only spaces
	value = normalizeStrLineEndings(value) // 8bit, pre-normalize
	return value
	//--
}


// SetHeaders sets the message headers.
func (m *Message) SetHeaders(h map[string][]string) {
	for k, v := range h {
		m.SetHeader(k, v...)
	}
}


// SetAddressHeader sets an address to the given header field.
func (m *Message) SetAddressHeader(field, address, name string) {
	m.header[field] = []string{m.FormatAddress(address, name)}
}


// FormatAddress formats an address and a name as a valid RFC 5322 address.
func (m *Message) FormatAddress(address, name string) string {
	//--
	defer panicHandler()
	//--
	if name == "" {
		return address
	}

	enc := m.encodeString(name)
	if enc == name {
		m.buf.WriteByte('"')
		for i := 0; i < len(name); i++ {
			b := name[i]
			if b == '\\' || b == '"' {
				m.buf.WriteByte('\\')
			}
			m.buf.WriteByte(b)
		}
		m.buf.WriteByte('"')
	} else if hasSpecials(name) {
		m.buf.WriteString(bEncoding.Encode(m.charset, name))
	} else {
		m.buf.WriteString(enc)
	}
	m.buf.WriteString(" <")
	m.buf.WriteString(address)
	m.buf.WriteByte('>')

	addr := m.buf.String()
	m.buf.Reset()
	return addr
}


func hasSpecials(text string) bool {
	for i := 0; i < len(text); i++ {
		switch c := text[i]; c {
		case '(', ')', '<', '>', '[', ']', ':', ';', '@', '\\', ',', '.', '"':
			return true
		}
	}

	return false
}


// SetDateHeader sets a date to the given header field.
func (m *Message) SetDateHeader(field string, date time.Time) {
	m.header[field] = []string{m.FormatDate(date)}
}


// FormatDate formats a date as a valid RFC 5322 date.
func (m *Message) FormatDate(date time.Time) string {
	return date.Format(time.RFC1123Z)
}


// GetHeader gets a header field.
func (m *Message) GetHeader(field string) []string {
	return m.header[field]
}


// SetBody sets the body of the message. It replaces any content previously set
// by SetBody, SetBodyWriter, AddAlternative or AddAlternativeWriter.
func (m *Message) SetBody(contentType, body string, settings ...PartSetting) error {
	if(m.haveBody == true) {
		return errors.New("Body has been already set") // allow just once !
	}
	m.SetBodyWriter(contentType, newCopier(body), settings...)
	m.haveBody = true
	return nil
}


// SetBodyWriter sets the body of the message. It can be useful with the
// text/template or html/template packages.
func (m *Message) SetBodyWriter(contentType string, f func(io.Writer) error, settings ...PartSetting) {
	m.parts = []*part{m.newPart(false, contentType, f, settings)}
}


// AddAlternative adds an alternative part to the message.
//
// It is commonly used to send HTML emails that default to the plain text
// version for backward compatibility. AddAlternative appends the new part to
// the end of the message. So the plain text part should be added before the
// HTML part. See http://en.wikipedia.org/wiki/MIME#Alternative
func (m *Message) AddAlternative(contentType, body string, settings ...PartSetting) error {
	if(m.haveAlt == true) {
		return errors.New("Alternative Body has been already set") // allow just once !
	}
	m.AddAlternativeWriter(contentType, newCopier(body), settings...)
	m.haveAlt = true
	return nil
}


func newCopier(s string) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := io.WriteString(w, s)
		return err
	}
}


// AddAlternativeWriter adds an alternative part to the message. It can be
// useful with the text/template or html/template packages.
func (m *Message) AddAlternativeWriter(contentType string, f func(io.Writer) error, settings ...PartSetting) {
	m.parts = append(m.parts, m.newPart(true, contentType, f, settings))
}


func (m *Message) newPart(isAlternative bool, contentType string, f func(io.Writer) error, settings []PartSetting) *part {
	//--
	defer panicHandler()
	//-- unixman
	theEncoding := m.encoding
	if(isAlternative == false) && (m.bodyencqp == true) { // if message have both: body and alt, for the main body which is ussually text use the QP encoding if was also set explicit for the headers ; this targets better anti-spam scores
		theEncoding = QuotedPrintable
	}
	//-- #
	p := &part{
		contentType: contentType,
		copier:      f,
		encoding:    theEncoding,
	}

	for _, s := range settings {
		s(p)
	}

	return p
}


func (m *Message) hasMixedPart() bool { // used by writeto
	return (len(m.parts) > 0 && len(m.attachments) > 0) || len(m.attachments) > 1
}


func (m *Message) hasRelatedPart() bool { // used by writeto
	return (len(m.parts) > 0 && len(m.embedded) > 0) || len(m.embedded) > 1
}


func (m *Message) hasAlternativePart() bool { // used by writeto
	return len(m.parts) > 1
}


func (m *Message) getFrom() (string, error) { // used by send
	//--
	defer panicHandler()
	//--
	from := m.header["Sender"]
	if len(from) <= 0 {
		from = m.header["From"]
		if len(from) <= 0 {
			return "", errors.New(`gomail: invalid message, "From" field is absent`)
		}
	}

	return parseAddress(from[0])
}


func (m *Message) getRecipients() ([]string, error) { // used by send
	//--
	defer panicHandler()
	//--
	n := 0
	for _, field := range []string{"To", "Cc", "Bcc"} {
		if addresses, ok := m.header[field]; ok {
			n += len(addresses)
		}
	}
	list := make([]string, 0, n)

	for _, field := range []string{"To", "Cc", "Bcc"} {
		if addresses, ok := m.header[field]; ok {
			for _, a := range addresses {
				addr, err := parseAddress(a)
				if err != nil {
					return nil, err
				}
				list = addAddress(list, addr)
			}
		}
	}

	return list, nil
}


// A PartSetting can be used as an argument in Message.SetBody,
// Message.SetBodyWriter, Message.AddAlternative or Message.AddAlternativeWriter
// to configure the part added to a message.
type PartSetting func(*part)


// SetPartEncoding sets the encoding of the part added to the message. By
// default, parts use the same encoding than the message.
func SetPartEncoding(e Encoding) PartSetting {
	return PartSetting(func(p *part) {
		p.encoding = e
	})
}


type file struct {
	Name     string
	Header   map[string][]string
	CopyFunc func(w io.Writer) error
}


func (f *file) setHeader(field, value string) {
	f.Header[field] = []string{value}
}


// A FileSetting can be used as an argument in Message.Attach or Message.Embed.
type FileSetting func(*file)


// SetHeader is a file setting to set the MIME header of the message part that
// contains the file content.
//
// Mandatory headers are automatically added if they are not set when sending
// the email.
func SetHeader(h map[string][]string) FileSetting {
	return func(f *file) {
		for k, v := range h {
			f.Header[k] = v
		}
	}
}


// Rename is a file setting to set the name of the attachment if the name is
// different than the filename on disk.
func Rename(name string) FileSetting {
	return func(f *file) {
		f.Name = name
	}
}


// SetCopyFunc is a file setting to replace the function that runs when the
// message is sent. It should copy the content of the file to the io.Writer.
//
// The default copy function opens the file with the given filename, and copy
// its content to the io.Writer.
func SetCopyFunc(f func(io.Writer) error) FileSetting {
	return func(fi *file) {
		fi.CopyFunc = f
	}
}


// AttachReader attaches a file using an io.Reader
func (m *Message) AttachReader(name string, r io.Reader, settings ...FileSetting) {
	m.attachments = m.appendFile(m.attachments, fileFromReader(name, r), settings)
}


// Attach attaches the files to the email.
func (m *Message) Attach(filename string, settings ...FileSetting) {
	m.attachments = m.appendFile(m.attachments, fileFromFilename(filename), settings)
}


// EmbedReader embeds the images to the email.
func (m *Message) EmbedReader(name string, r io.Reader, settings ...FileSetting) {
	m.embedded = m.appendFile(m.embedded, fileFromReader(name, r), settings)
}


// Embed embeds the images to the email.
func (m *Message) Embed(filename string, settings ...FileSetting) {
	m.embedded = m.appendFile(m.embedded, fileFromFilename(filename), settings)
}


func fileFromFilename(name string) *file {
	//--
	defer panicHandler()
	//--
	return &file{
		Name:   filepath.Base(name),
		Header: make(map[string][]string),
		CopyFunc: func(w io.Writer) error {
			h, err := os.Open(name)
			if err != nil {
				return err
			}
			if _, err := io.Copy(w, h); err != nil {
				h.Close()
				return err
			}
			return h.Close()
		},
	}
}


func fileFromReader(name string, r io.Reader) *file {
	//--
	defer panicHandler()
	//--
	return &file{
		Name:   filepath.Base(name),
		Header: make(map[string][]string),
		CopyFunc: func(w io.Writer) error {
			if _, err := io.Copy(w, r); err != nil {
				return err
			}
			return nil
		},
	}
}


func (m *Message) appendFile(list []*file, f *file, settings []FileSetting) []*file {
	for _, s := range settings {
		s(f)
	}

	if list == nil {
		return []*file{f}
	}

	return append(list, f)
}


// #end
