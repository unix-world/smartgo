
// Package dmarc implements DMARC as specified in RFC 7489.

package dmarc

// modified by unixman
// r.20260829

import (
	"time"
)

type AlignmentMode string

const (
	AlignmentStrict  AlignmentMode = "s"
	AlignmentRelaxed               = "r"
)

type FailureOptions int

const (
	FailureAll  FailureOptions = 1 << iota // "0"
	FailureAny                             // "1"
	FailureDKIM                            // "d"
	FailureSPF                             // "s"
)

type Policy string

const (
	PolicyNone       Policy = "none"
	PolicyQuarantine        = "quarantine"
	PolicyReject            = "reject"
)

type ReportFormat string

const (
	ReportFormatAFRF ReportFormat = "afrf"
)

// Record is a DMARC record, as defined in RFC 7489 section 6.3.
type Record struct { // unixman: add JSON hints
	DKIMAlignment      AlignmentMode 		`json:"dkimAlignment,omitempty"` 			// "adkim"
	SPFAlignment       AlignmentMode 		`json:"spfAlignment,omitempty"` 			// "aspf"
	FailureOptions     FailureOptions 		`json:"failureOptions,omitempty"` 			// "fo"
	Policy             Policy 				`json:"policy,omitempty"` 					// "p"
	Percent            *int 				`json:"percent,omitempty"` 					// "pct"
	ReportFormat       []ReportFormat 		`json:"reportFormat,omitempty"` 			// "rf"
	ReportInterval     time.Duration 		`json:"reportInterval,omitempty"` 			// "ri"
	ReportURIAggregate []string 			`json:"reportUriAggregate,omitempty"` 		// "rua"
	ReportURIFailure   []string 			`json:"reportUriFailure,omitempty"`	 		// "ruf"
	SubdomainPolicy    Policy 				`json:"subdomainPolicy,omitempty"` 			// "sp"
}

// #end
