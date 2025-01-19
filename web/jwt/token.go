package jwt

// modified by unixman: fix B64: add panic handler ; jsonEncode ; catch invalid pad L=3
// r.20250110.2358

import (
	"log"
	"errors"
	"runtime/debug"

	"bytes"
	"strings"
	"time"
	"encoding/base64"
	"encoding/json"
)

// DecodePaddingAllowed will switch the codec used for decoding JWTs respectively. Note that the JWS RFC7515
// states that the tokens will utilize a Base64url encoding with no padding. Unfortunately, some implementations
// of JWT are producing non-standard tokens, and thus require support for decoding. Note that this is a global
// variable, and updating it will change the behavior on a package level, and is also NOT go-routine safe.
// To use the non-recommended decoding, set this boolean to `true` prior to using this package.
var DecodePaddingAllowed bool

// DecodeStrict will switch the codec used for decoding JWTs into strict mode.
// In this mode, the decoder requires that trailing padding bits are zero, as described in RFC 4648 section 3.5.
// Note that this is a global variable, and updating it will change the behavior on a package level, and is also NOT go-routine safe.
// To use strict decoding, set this boolean to `true` prior to using this package.
var DecodeStrict bool

// TimeFunc provides the current time when parsing token to validate "exp" claim (expiration time).
// You can override it to use another time value.  This is useful for testing or if your
// server uses a different time zone than your tokens.
var TimeFunc = time.Now

// Keyfunc will be used by the Parse methods as a callback function to supply
// the key for verification.  The function receives the parsed,
// but unverified Token.  This allows you to use properties in the
// Header of the token (such as `kid`) to identify which key to use.
type Keyfunc func(*Token) (interface{}, error)

// Token represents a JWT Token.  Different fields will be used depending on whether you're
// creating or parsing/verifying a token.
type Token struct {
	Raw       string                 // The raw token.  Populated when you Parse a token
	Method    SigningMethod          // The signing method used or to be used
	Header    map[string]interface{} // The first segment of the token
	Claims    Claims                 // The second segment of the token
	Signature string                 // The third segment of the token.  Populated when you Parse a token
	Valid     bool                   // Is the token valid?  Populated when you Parse/Verify a token
}

// New creates a new Token with the specified signing method and an empty map of claims.
func New(method SigningMethod) *Token {
	return NewWithClaims(method, MapClaims{})
}

// NewWithClaims creates a new Token with the specified signing method and claims.
func NewWithClaims(method SigningMethod, claims Claims) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": "JWT",
			"alg": method.Alg(),
		},
		Claims: claims,
		Method: method,
	}
}

// SignedString creates and returns a complete, signed JWT.
// The token is signed using the SigningMethod specified in the token.
func (t *Token) SignedString(key interface{}) (string, error) {
	var sig, sstr string
	var err error
	if sstr, err = t.SigningString(); err != nil {
		return "", err
	}
	if sig, err = t.Method.Sign(sstr, key); err != nil {
		return "", err
	}
	return strings.Join([]string{sstr, sig}, "."), nil
}

// SigningString generates the signing string.  This is the
// most expensive part of the whole deal.  Unless you
// need this for something special, just go straight for
// the SignedString.
func (t *Token) SigningString() (string, error) {
	var err error
	var jsonValue []byte

//	if jsonValue, err = json.Marshal(t.Header); err != nil {
	if jsonValue, err = jsonEncode(t.Header); err != nil { // // fix by unixman ; don't escape html, make JWT shorter
		return "", err
	}
	header := EncodeSegment(jsonValue)

//	if jsonValue, err = json.Marshal(t.Claims); err != nil {
	if jsonValue, err = jsonEncode(t.Claims); err != nil { // // fix by unixman ; don't escape html, make JWT shorter
		return "", err
	}
	claim := EncodeSegment(jsonValue)

	return strings.Join([]string{header, claim}, "."), nil
}

// Parse parses, validates, verifies the signature and returns the parsed token.
// keyFunc will receive the parsed token and should return the cryptographic key
// for verifying the signature.
// The caller is strongly encouraged to set the WithValidMethods option to
// validate the 'alg' claim in the token matches the expected algorithm.
// For more details about the importance of validating the 'alg' claim,
// see https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
func Parse(tokenString string, keyFunc Keyfunc, options ...ParserOption) (*Token, error) {
	return NewParser(options...).Parse(tokenString, keyFunc)
}

// ParseWithClaims is a shortcut for NewParser().ParseWithClaims().
//
// Note: If you provide a custom claim implementation that embeds one of the standard claims (such as RegisteredClaims),
// make sure that a) you either embed a non-pointer version of the claims or b) if you are using a pointer, allocate the
// proper memory for it before passing in the overall claims, otherwise you might run into a panic.
func ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc, options ...ParserOption) (*Token, error) {
	return NewParser(options...).ParseWithClaims(tokenString, claims, keyFunc)
}

//-- unixman
func jsonEncode(data interface{}) ([]byte, error) {
	//--
	defer panicHandler()
	//-- no need any panic handler
	out := bytes.Buffer{}
	//--
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false) // don't escape html, make JWT shorter
	//--
	err := encoder.Encode(data)
	if(err != nil) {
		return nil, err
	} //end if
	//--
	return bytes.TrimSpace(out.Bytes()), nil // must trim as will add a new line at the end ...
	//--
} //END FUNCTION
//-- #

// EncodeSegment encodes a JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	defer panicHandler() // by unixman
	return base64.RawURLEncoding.EncodeToString(seg)
}

// DecodeSegment decodes a JWT specific base64url encoding with padding stripped
// unixman: added panic handler ; fix: if padding is invalid (L=3) exit and notice err
func DecodeSegment(seg string) ([]byte, error) {
	//-- unixman
	defer panicHandler() // req. by base64 decode panic handler with malformed data

	if(seg == "") {
		return nil, errors.New("Empty Data")
	}
	//-- #unixman

	encoding := base64.RawURLEncoding

	if DecodePaddingAllowed {
		//-- fix by unixman
	//	if l := len(seg) % 4; l > 0 {
		var l int = len(seg) % 4
		if(l > 0) {
			if(l == 1) { // {{{SYNC-B64-WRONG-PAD-3}}} ; it cannot end with 3 "=" signs
				return nil, errors.New("Invalid B64 Padding Length, more than 2, L = 3")
			}
			seg += strings.Repeat("=", 4-l)
		}
		//-- #fix
		encoding = base64.URLEncoding
	}

	if DecodeStrict {
		encoding = encoding.Strict()
	}

	return encoding.DecodeString(seg)
}

//-- unixman
func panicHandler() {
	if panicInfo := recover(); panicInfo != nil {
		log.Println("[ERROR] !!! PANIC Recovered:", panicInfo, "by jwt.DecodeSegment")
		log.Println("[PANIC] !!! Debug Stack Trace:", string(debug.Stack()), "from jwt.DecodeSegment")
	} //end if
}
//-- #
