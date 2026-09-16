
package dmarc

// moved the parser methods to parse.go
// modified by unixman
// r.20260829

import (
	"errors"
	"strings"
	"net"
)

const (
	LookUpPrefix string = "_dmarc."
)

var (
	ErrNoPolicy = errors.New("dmarc: no policy found for domain")
)


// LookupOptions allows to customize the default signature verification behavior
// LookupTXT returns the DNS TXT records for the given domain name. If nil, net.LookupTXT is used
type LookupOptions struct {
	LookupTXT func(domain string) ([]string, error)
}


type tempFailError string

func (err tempFailError) Error() string {
	return "dmarc: " + string(err)
}


// IsTempFail returns true if the error returned by Lookup is a temporary
// failure.
func IsTempFail(err error) bool {
	_, ok := err.(tempFailError)
	return ok
}


// Lookup queries a DMARC record for a specified domain.
func Lookup(domain string) (*Record, error) {
	return LookupWithOptions(domain, nil)
}


func LookupWithOptions(domain string, options *LookupOptions) (*Record, error) {
	var txts []string
	var err error
	if options != nil && options.LookupTXT != nil {
		txts, err = options.LookupTXT(LookUpPrefix + domain)
	} else {
		txts, err = net.LookupTXT(LookUpPrefix + domain)
	}
	if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
		return nil, tempFailError("TXT record unavailable: " + err.Error())
	} else if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return nil, ErrNoPolicy
		}
		return nil, errors.New("dmarc: failed to lookup TXT record: " + err.Error())
	}

	for _, txt := range txts {
		if !strings.HasPrefix(txt, "v=") {
			continue
		}
		record, err := Parse(txt)
		if err == errUnsupportedVersion {
			continue
		}
		return record, err
	}

	return nil, ErrNoPolicy
}


// #end
