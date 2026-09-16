
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE
// [ DNS / MX ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"log"

	"net"

	"github.com/unix-world/smartgo/mx/spf"
	"github.com/unix-world/smartgo/mx/dmarc"
	"github.com/unix-world/smartgo/mx/dkim"
)


//-----


type DnsMxIpSpfEntry struct {
	IpAddress 		string 				`json:"ipAddress"`
	SpfValidation 	spf.Result 			`json:"spfValidation"`
}

type DnsMxDetail struct {
	Preference 		uint16 				`json:"preference"`
	DnsDomain 		string 				`json:"dnsDomain"`
	DnsCName 		string 				`json:"dnsCName"`
	IpAddresses 	[]DnsMxIpSpfEntry 	`json:"ipAddresses"`
}

type DnsSpfRecord struct {
	IsValid 		bool 				`json:"isValid"`
	Record 			spf.SPF 			`json:"record"`
}

type DnsDmarcRecord struct {
	IsValid 		bool 				`json:"isValid"`
	Record 			*dmarc.Record 		`json:"record"`
}

type DnsDkimRecord struct {
	IsValid 		bool 				`json:"isValid"`
	Record 			*dkim.QueryResult 	`json:"record"`
}

type DnsMxEntry struct {
	DnsDomain 		string 				`json:"dnsDomain"`
	DnsCName 		string 				`json:"dnsCName"`
	IpAddresses 	[]string 			`json:"ipAddresses"`
	HasMX 			bool 				`json:"hasMX"`
	MxRecords 		[]DnsMxDetail 		`json:"mxRecords"`
	HasSPF 			bool 				`json:"hasSPF"`
	TxtSPF 			string 				`json:"txtdSPF"`
	SPF 			DnsSpfRecord 		`json:"SPF"`
	HasDMARC 		bool 				`json:"hasDMARC"`
	TxtDMARC 		string 				`json:"txtDMARC"`
	DMARC 			DnsDmarcRecord 		`json:"DMARC"`
	HasDKIM 		bool 				`json:"hasDKIM"`
	TxtDKIM 		[]string 			`json:"txtDKIM"`
	DKIM 			[]DnsDkimRecord 	`json:"DKIM"`
	Errors 			[]string 			`json:"errors,omitempty"`
}


func NetDomainGetMxSpfDmarc(domain string, dkimSelector string) (DnsMxEntry, error) {
	//--
	record := DnsMxEntry{}
	//--
	domain = StrTrimWhitespaces(domain)
	if(domain == "") {
		return record, NewError("DNS domain is Empty")
	} //end if
	if(!IsNetValidHostName(domain)) {
		return record, NewError("DNS domain [" + domain + "] is Invalid")
	} //end if
	//--
	dkimSelector = StrTrimWhitespaces(dkimSelector) // optional, if provided will lookup for the DKIM of domain and to do so the dkimSelector is required ; ex: `google` | `selector1` | `selector2`
	//--
	ipArrAddresses, errIp := NetDomainGetIpAddresses(domain)
	if(errIp != nil) {
		return record, NewError("DNS domain [" + domain + "] IP lookup Failed: " + errIp.Error())
	} //end if
	//--
	var hasMX, hasSPF, hasDMARC, hasDKIM bool
	mxArrRecords := []DnsMxDetail{}
	spfRecord    := ""
	spfPRec      := DnsSpfRecord{}
	dmarcRecord  := ""
	dmarcPRecord := DnsDmarcRecord{}
	dkimRecords  := []string{}
	dkimPRecords := []DnsDkimRecord{}
	errs         := []string{}
	//--
	cName, errCname := net.LookupCNAME(domain)
	if(errCname != nil) {
		errs = append(errs, "Lookup Domain CNAME Record Failed: " + errCname.Error())
		if(DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "CNAME LookUp Failed:", errCname)
		} //end if
	} //end if
	cName = StrTrim(cName, ".") // {{{SYNC-DNS-HOSTNAME-REMOVE-DOTS}}} ; remove the trailing dot as in DNS, but also if have on left
	//--
	spfRecords, errSpf := net.LookupTXT(domain)
	if(errSpf != nil) {
		errs = append(errs, "Lookup Domain SPF Records Failed: " + errSpf.Error())
		if(DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "SPF LookUp Failed:", errSpf)
		} //end if
	} else {
		for _, txtRec := range spfRecords {
			if(StrIStartsWith(txtRec, spf.TxtRecordPrefix)) {
				hasSPF = true
				spfRecord = txtRec
				pRec, errPRec := spf.NewSPFByRecord(domain, spfRecord)
				if(errPRec == nil) {
					spfPRec.IsValid = true
				} //end if
				spfPRec.Record = pRec
				break
			} //end if
		} //end for
	} //end if
	//--
	mxRecords, errMx := net.LookupMX(domain)
	if(errMx != nil) {
		errs = append(errs, "Lookup Domain MX Records Failed: " + errMx.Error())
		if(DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "MX LookUp Failed:", errMx)
		} //end if
	} else {
		if(len(mxRecords) > 0) {
			hasMX = true
			for _, mxRec := range mxRecords {
				theDom := StrTrim(mxRec.Host, ".") // {{{SYNC-DNS-HOSTNAME-REMOVE-DOTS}}} ; remove the trailing dot as in DNS, but also if have on left
				theCName, errMxCname := net.LookupCNAME(theDom)
				theCName = StrTrim(theCName, ".") // {{{SYNC-DNS-HOSTNAME-REMOVE-DOTS}}} ; remove the trailing dot as in DNS, but also if have on left
				if(errMxCname != nil) {
					errs = append(errs, "MX Lookup CNAME Failed: " + theDom + ": " + errMxCname.Error())
				} else if(!IsNetValidHostName(theDom)) {
					errs = append(errs, "Invalid Host Name found for CNAME: " + theDom + ": " + theCName)
				} //end if
				if(IsNetValidHostName(theDom)) { // an MX (Mail Exchange) entry cannot contain an IP address and must point to a domain name or hostname
					arrIps, _ := NetDomainGetIpAddresses(theDom)
					arrSpfIps := []DnsMxIpSpfEntry{}
					if(len(arrIps) > 0) {
						for i:=0; i<len(arrIps); i++ {
							pRec, errPRec := spf.NewSPFByRecord(theDom, spfRecord)
							if(errPRec != nil) {
								errs = append(errs, "SPF Validation for MX Domain [" + theDom  + "] Failed: " + errPRec.Error())
							} //end if
							arrSpfIp := DnsMxIpSpfEntry{
								IpAddress: arrIps[i],
								SpfValidation: pRec.Test(arrIps[i]),
							}
							arrSpfIps = append(arrSpfIps, arrSpfIp)
						} //end for
					} //end if
					mxDetail  := DnsMxDetail{}
					mxDetail.Preference   = mxRec.Pref
					mxDetail.DnsDomain    = theDom
					mxDetail.DnsCName     = theCName
					mxDetail.IpAddresses  = arrSpfIps
					mxArrRecords = append(mxArrRecords, mxDetail)
				} else {
					errs = append(errs, "Invalid Host Name found: " + theDom)
				} //end if else
			} //end for
		} //end if
	} //end if
	//--
	dmarcRecords, errDmarc := net.LookupTXT(dmarc.LookUpPrefix + domain)
	if(errDmarc != nil) {
		errs = append(errs, "Lookup Domain DMARC Records Failed: " + errDmarc.Error())
		if(DEBUG) {
			log.Println("[DEBUG]", CurrentFunctionName(), "DMARC LookUp Failed:", errDmarc)
		} //end if
	} else {
		for _, record := range dmarcRecords {
			if(StrIStartsWith(record, dmarc.TxtRecordPrefix)) {
				hasDMARC = true
				dmarcRecord = record
				dRec, errPDmarc := dmarc.Parse(dmarcRecord)
				if(errPDmarc != nil) {
					errs = append(errs, "DMARC Validation for Domain [" + domain  + "] Failed: " + errPDmarc.Error())
				} else {
					dmarcPRecord.IsValid = true
				} //end if
				dmarcPRecord.Record = dRec
				break
			} //end if
		} //end for
	} //end if
	//--
	if(dkimSelector != "") {
		dkimArrRecords, errDkim := net.LookupTXT(dkim.LookUpPrefixWithSelector(dkimSelector) + domain)
		if(errDkim != nil) {
			errs = append(errs, "Lookup Domain DKIM Records Failed: " + errDkim.Error())
			if(DEBUG) {
				log.Println("[DEBUG]", CurrentFunctionName(), "DKIM LookUp Failed:", errDkim)
			} //end if
		} else {
			for _, record := range dkimArrRecords {
				if(StrIStartsWith(record, dkim.TxtRecordPrefix)) {
					dkimRecords = append(dkimRecords, record)
				} //end if
			} //end for
			if(len(dkimRecords) > 0) {
				hasDKIM = true
				for i:=0; i<len(dkimRecords); i++ {
					dkimPRecord := DnsDkimRecord{}
					dRec, errPDkim := dkim.ParsePublicKey(dkimRecords[i])
					if(errPDkim != nil) {
						errs = append(errs, "DKIM Validation for Domain [" + domain  + "] / Selector [" + dkimSelector + "] Failed: " + errPDkim.Error())
					} else {
						dkimPRecord.IsValid = true
					} //end if else
					dkimPRecord.Record = dRec
					dkimPRecords = append(dkimPRecords, dkimPRecord)
				} //end for
			} //end if
		} //end if
	} //end if
	//--
	record.DnsDomain 		= domain
	record.DnsCName 		= cName
	record.IpAddresses 		= ipArrAddresses
	record.HasMX 			= hasMX
	record.MxRecords 		= mxArrRecords
	record.HasSPF 			= hasSPF
	record.TxtSPF 			= spfRecord
	record.SPF 				= spfPRec
	record.HasDMARC 		= hasDMARC
	record.TxtDMARC 		= dmarcRecord
	record.DMARC 			= dmarcPRecord
	record.HasDKIM 			= hasDKIM
	record.TxtDKIM 		 	= dkimRecords
	record.DKIM 			= dkimPRecords
	if(len(errs) > 0) {
		record.Errors = errs
	} //end if
	//--
	return record, nil
	//--
} //END FUCTION


//-----



func NetDomainGetIpAddresses(domain string) ([]string, error) {
	//--
	ipArrAddresses := []string{}
	//--
	domain = StrTrimWhitespaces(domain)
	if(domain == "") {
		return ipArrAddresses, NewError("DNS domain is Empty")
	} //end if
	if(!IsNetValidHostName(domain)) {
		return ipArrAddresses, NewError("DNS domain [" + domain + "] is Invalid")
	} //end if
	//--
	ipAddresses, errIp := net.LookupIP(domain)
	if(errIp != nil) {
		return ipArrAddresses, NewError("DNS domain [" + domain + "] IP lookup Failed: " + errIp.Error())
	} //end if
	if(len(ipAddresses) > 0) {
		for _, ipAddr := range ipAddresses {
			ipStrAddr := ipAddr.String()
			if(IsNetValidIpAddr(ipStrAddr)) {
				ipArrAddresses = append(ipArrAddresses, ipStrAddr)
			} //end if
		} //end for
	} //end if
	//--
	return ipArrAddresses, nil
	//--
} //END FUNCTION



//-----


// #END
