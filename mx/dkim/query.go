
package dkim

// modified by unixman
// r.20260915

import (
	"errors"
	"fmt"

	"strings"
	"encoding/base64"

	"net"
	"crypto"
	"crypto/x509"
	"crypto/rsa"
	"crypto/ed25519"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"math/big"
)

type verifier interface {
	Public() crypto.PublicKey
	Verify(hash crypto.Hash, hashed []byte, sig []byte) error
}


type ed25519Verifier struct {
	ed25519.PublicKey
}

func (v ed25519Verifier) Public() crypto.PublicKey {
	return v.PublicKey
}

func (v ed25519Verifier) Verify(hash crypto.Hash, hashed []byte, sig []byte) error {
	if !ed25519.Verify(v.PublicKey, hashed, sig) {
		return errors.New("dkim: invalid EdDSA/Ed25519 signature")
	}
	return nil
}


type ecdsaSig struct {
	R *big.Int
	S *big.Int
}

type ecdsaVerifier struct {
	*ecdsa.PublicKey
}

func (v ecdsaVerifier) Public() crypto.PublicKey {
	return v.PublicKey
}

func (v ecdsaVerifier) Verify(hash crypto.Hash, hashed []byte, sig []byte) error {
	esig := ecdsaSig{}
	if _, err := asn1.Unmarshal(sig, &esig); err != nil {
		return err
	}
	if !ecdsa.Verify(v.PublicKey, hashed, esig.R, esig.S) {
		return errors.New("dkim: invalid EcDSA signature")
	}
	return nil
}


type rsaVerifier struct {
	*rsa.PublicKey
}

func (v rsaVerifier) Public() crypto.PublicKey {
	return v.PublicKey
}

func (v rsaVerifier) Verify(hash crypto.Hash, hashed []byte, sig []byte) error {
	return rsa.VerifyPKCS1v15(v.PublicKey, hash, hashed, sig)
}


type QueryResult struct { // unixman: json hints
	TxtRecord string 		`json:"-"` // unixman
	Verifier  verifier 		`json:"-"`
	KeyAlgo   string 		`json:"keyAlgo"`
	HashAlgos []string 		`json:"hashAlgos"`
	Notes     string 		`json:"notes,omitempty"`
	Services  []string 		`json:"services,omitempty"`
	Flags     []string 		`json:"flags,omitempty"`
}

type QueryMethod string // QueryMethod is a DKIM query method.

const (
	QueryMethodDNSTXT QueryMethod = "dns/txt" // DNS TXT resource record (RR) lookup algorithm
)

type TxtLookupFunc func(domain string) ([]string, error)
type QueryFunc func(domain, selector string, txtLookup TxtLookupFunc) (*QueryResult, error)

var queryMethods = map[QueryMethod]QueryFunc{
	QueryMethodDNSTXT: QueryDnsTxt,
}


func QueryDnsTxt(domain string, selector string, txtLookup TxtLookupFunc) (*QueryResult, error) {
	//-- unixman
	domain = strings.TrimSpace(domain)
	if(domain == "") {
		return nil, permFailError("domain name is empty")
	}
	selector = strings.TrimSpace(selector)
	if(selector == "") {
		return nil, permFailError("selector name is empty")
	}
	//-- #

	if txtLookup == nil {
		txtLookup = net.LookupTXT
	}

	txts, err := txtLookup(LookUpPrefixWithSelector(selector) + domain)
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return nil, tempFailError("key unavailable: " + err.Error())
	} else if err != nil {
		return nil, permFailError("no key for signature: " + err.Error())
	}

	// net.LookupTXT will concatenate strings contained in a single TXT record.
	// In other words, net.LookupTXT returns one entry per TXT record, even if
	// a record contains multiple strings.
	// RFC 6376 section 3.6.2.2 says multiple TXT records lead to undefined
	// behavior, so reject that.
	switch len(txts) {
		case 0:
			return nil, permFailError("no valid key found")
		case 1:
			return ParsePublicKey(txts[0])
		default:
			return nil, permFailError("multiple TXT records found for key")
	}
}

func ParsePublicKey(s string) (*QueryResult, error) {
	params, err := ParseHeaderParams(s)
	if err != nil {
		return nil, permFailError("key record error: " + err.Error())
	}
	//-- unixman
	if(params == nil) {
		return nil, permFailError("key record error")
	}
	//-- #

	res := QueryResult{}
	res.TxtRecord = s

	if v, ok := params["v"]; ok && v != txtRecordPrefixVal { // unixman
		return nil, permFailError("incompatible public key version")
	}

	p, ok := params["p"]
	if !ok {
		return nil, permFailError("key syntax error: missing public key data")
	}
	if p == "" {
		return nil, permFailError("key revoked")
	}
	p = strings.ReplaceAll(p, " ", "")
	b, err := base64.StdEncoding.DecodeString(p)
	if err != nil {
		return nil, permFailError("key syntax error: " + err.Error())
	}
	switch params["k"] {
		//--
		case "ed25519": // EdDSA
			//-- unixman: bug fix: the X509 key is ASN1 encoded
			var ed25519Pub ed25519.PublicKey
			if(len(b) < ed25519.PublicKeySize) { // fail, expect at least 32 bytes
				return nil, permFailError(fmt.Sprintf("invalid Ed25519 public key size: %v bytes but expected %v bytes", len(b), ed25519.PublicKeySize)) // unixman
			} else if len(b) == ed25519.PublicKeySize {
				ed25519Pub = ed25519.PublicKey(b) // raw, 32 bytes
			} else if len(b) <= 44 { // fix by unixman: if > 32 bytes (raw) but <= 44 bytes (asn1 format), try to parse the ASN1 and get the standard 32 bytes
				pub, err := x509.ParsePKIXPublicKey(b)
				if err != nil {
					return nil, permFailError("key syntax error: " + err.Error())
				}
				var ok bool
				ed25519Pub, ok = pub.(ed25519.PublicKey)
				if !ok {
					return nil, permFailError("key syntax error: not an Ed25519 public key")
				}
			} else { // oversized key
				return nil, permFailError("key is too long")
			} // #end fix
			res.Verifier = ed25519Verifier{ed25519Pub}
			res.KeyAlgo = "ed25519"
			break
		//--
		case "ecdsa521": fallthrough
		case "ecdsa384": fallthrough
		case "ecdsa256": fallthrough
		case "ecdsa":
			pub, err := x509.ParsePKIXPublicKey(b) // EcDSA only supports this type of key in ASN1 format
			if err != nil {
				return nil, permFailError("key syntax error: " + err.Error())
			}
			var ecdsaPub *ecdsa.PublicKey
			var ok bool
			ecdsaPub, ok = pub.(*ecdsa.PublicKey)
			if !ok {
				return nil, permFailError("key syntax error: not an EcDSA public key")
			}
			res.Verifier = ecdsaVerifier{ecdsaPub}
			res.KeyAlgo = ""
			switch ecdsaPub.Curve {
				case elliptic.P256():
					res.KeyAlgo = "ecdsa256"
				case elliptic.P384():
					res.KeyAlgo = "ecdsa384"
				case elliptic.P521():
					res.KeyAlgo = "ecdsa521"
				default:
					return nil, permFailError("key syntax error: not an EcDSA public key Algo")
			}
			break
		//--
		case "rsa": fallthrough
		case "": // default is RSA
			pub, err := x509.ParsePKIXPublicKey(b)
			if err != nil {
				// RFC 6376 is inconsistent about whether RSA public keys should
				// be formatted as RSAPublicKey or SubjectPublicKeyInfo.
				// Erratum 3017 (https://www.rfc-editor.org/errata/eid3017) proposes
				// allowing both.
				pub, err = x509.ParsePKCS1PublicKey(b)
				if err != nil {
					return nil, permFailError("key syntax error: " + err.Error())
				}
			}
			var rsaPub *rsa.PublicKey
			var ok bool
			rsaPub, ok = pub.(*rsa.PublicKey)
			if !ok {
				return nil, permFailError("key syntax error: not an RSA public key")
			}
			// RFC 8301 section 3.2: verifiers MUST NOT consider signatures using
			// RSA keys of less than 1024 bits as valid signatures.
			if rsaPub.Size()*8 < 1024 { // for legacy support accept RSA 1024, otherwise minimum safe RSA is 2048 ...
				return nil, permFailError(fmt.Sprintf("key is too short: want 1024 bits, has %v bits", rsaPub.Size()*8))
			}
			res.Verifier = rsaVerifier{rsaPub}
			res.KeyAlgo = "rsa"
			break
		//--
		default:
			return nil, permFailError("unsupported key algorithm: " + params["k"])
	}

	if hashesStr, ok := params["h"]; ok {
		res.HashAlgos = parseTagList(hashesStr)
	}
	if notes, ok := params["n"]; ok {
		res.Notes = notes
	}
	if servicesStr, ok := params["s"]; ok {
		services := parseTagList(servicesStr)

		hasWildcard := false
		for _, s := range services {
			if s == "*" {
				hasWildcard = true
				break
			}
		}
		if !hasWildcard {
			res.Services = services
		}
	}
	if flagsStr, ok := params["t"]; ok {
		res.Flags = parseTagList(flagsStr)
	}

	return &res, nil
}

// #end
