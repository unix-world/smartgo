
package htmlsanitizer

// modified by unixman r.20260829

import (
	"bytes"
	"strings"
	"io"

	validate_url           "github.com/unix-world/smartgo/validate/url"
	validate_data_url      "github.com/unix-world/smartgo/validate/data-url"
	validate_email_address "github.com/unix-world/smartgo/validate/email"
)

// DefaultURLSanitizer is a default and strict sanitizer.
// It only accepts
//   - URL with scheme http or https
//   - relative URL, such as abc, abc?xxx=1, abc#123
//   - absolute URL, such as /abc, /abc?xxx=1, /abc#123
func DefaultURLSanitizer(rawURL string) (sanitized string, ok bool) {
	//-- unixman
	sanitized = ""
	if(strings.HasPrefix(rawURL, "mailto:")) {
		if(len(rawURL) > 7) {
			eml, err := validate_email_address.Validate(rawURL[7:])
			if(err == nil) {
				ok = true
				sanitized = "mailto:" + eml
			}
		}
		return
	} else if(strings.HasPrefix(rawURL, "data:")) {
		u, err := validate_data_url.Validate(rawURL)
		if(err == nil) {
			ok = true
			sanitized = u
		}
		return
	} //end if else
	//-- #

	u, err := validate_url.Validate(rawURL, false) // disallow here `data:` scheme ; allow just `http:` and `https`
	if(err != nil) {
		return
	}
	sanitized = u
	ok = true
	return
}

// HTMLSanitizer is a super fast HTML sanitizer for arbitrary HTML content.
// This is an allowlist-based sanitizer, of which the time complexity is O(n).
type HTMLSanitizer struct {
	*AllowList

	// URLSanitizer is a func used to sanitize all the URLAttr.
	// URLSanitizer returns a sanitized URL and a bool var indicating
	// whether the current attribute is acceptable. If not acceptable,
	// the current attribute will be ignored.
	// If the func is nil, then DefaultURLSanitizer will be used.
	URLSanitizer func(rawURL string) (sanitized string, ok bool)
}

// NewHTMLSanitizer creates a new HTMLSanitizer with the clone of
// the DefaultAllowList.
func NewHTMLSanitizer() *HTMLSanitizer {
	return &HTMLSanitizer{
		AllowList: DefaultAllowList.Clone(),
	}
}

func (f *HTMLSanitizer) urlSanitizer(rawURL string) (sanitized string, ok bool) {
	if f.URLSanitizer != nil {
		return f.URLSanitizer(rawURL)
	}

	return DefaultURLSanitizer(rawURL)
}

// NewWriter returns a new Writer writing sanitized HTML content to w.
func (f *HTMLSanitizer) NewWriter(w io.Writer) io.Writer {
	return &writer{
		HTMLSanitizer: f,
		w:             w,
	}
}

// Sanitize the HTML data and return the sanitized HTML.
func (f *HTMLSanitizer) Sanitize(data []byte) ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, len(data)))

	if _, err := f.NewWriter(buf).Write(data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// SanitizeString sanitizes the HTML string and return the sanitized HTML.
func (f *HTMLSanitizer) SanitizeString(data string) (string, error) {
	ret, err := f.Sanitize([]byte(data))
	var retStr string
	if ret != nil {
		retStr = string(ret)
	}

	return retStr, err
}

var defaultHTMLSanitizer = NewHTMLSanitizer()

// NewWriter returns a new Writer, with DefaultAllowList,
// writing sanitized HTML content to w.
func NewWriter(w io.Writer) io.Writer {
	return defaultHTMLSanitizer.NewWriter(w)
}

// Sanitize uses the DefaultAllowList to sanitize the HTML data.
func Sanitize(data []byte) ([]byte, error) {
	return defaultHTMLSanitizer.Sanitize(data)
}

// SanitizeString uses the DefaultAllowList to sanitize the HTML string.
func SanitizeString(data string) (string, error) {
	return defaultHTMLSanitizer.SanitizeString(data)
}

// #end
