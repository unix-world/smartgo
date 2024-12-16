
// SmartGo Captcha
// (c) 2024-present unix-world.org
// v.20241216.2358
// license: BSD

package captcha

import (
	smart "github.com/unix-world/smartgo"

	asciicaptcha "github.com/unix-world/smartgo/web/captcha/asciicaptcha"
)

const (
	CAPTCHA_TPL_HTML string = `<!-- Captcha[ascii@[###UUID|htmid|html###]] -->` + "\n" + `<div id="asciiCaptcha-[###UUID|htmid|html###]">` + "\n" + "[###HTML-CODE###]" + "\n" + `<div><b>Captcha:</b>&nbsp;<input type="test" autocomplete="off" maxlength="[###CAPTCHA-CHARS|int###]" title="Captcha Validation Code" placeholder="Validation Code" class="ux-field" style="width:124px; text-align:center;" onclick="this.value = '';" onblur="if((this.value != '') && (this.value.length < 8)) { ckName = '[###COOKIE-NAME|js###]'; ckVal = '[###COOKIE-VAL|js###]'; ckVal = ckVal + '|' + btoa(this.value); this.value = '[###CHARS-MASK|js###]'; try { document.cookie = encodeURIComponent(ckName) + '=' + encodeURIComponent(ckVal) + '; path=/'; } catch(err) { console.warn('Captcha ERR:', err); } }"></div>` + "\n" + `</div>` + "\n" + `<!-- #captcha -->` + "\n"
)

type CaptchaStruct struct {
	Code string `json:"-"` // do not export to json, by accident
	Html string `json:"html"`
}


func ValidateCaptcha(ckVal string, ckName string, clientIdentUidHash string) (bool, error) {
	//--
	clientIdentUidHash = smart.StrTrimWhitespaces(clientIdentUidHash)
	if(len(clientIdentUidHash) < 80) { // expects SHA3-512-B64
		return false, smart.NewError("Invalid Captcha Client UID Hash: too short")
	} //end if
	//--
	ckName = smart.StrCreateStdVarName(ckName)
	if(smart.StrTrimWhitespaces(ckName) == "") {
		return false, smart.NewError("Invalid Captcha Cookie Name: `" + ckName + "`")
	} //end if
	//--
	ckVal = smart.StrTrimWhitespaces(ckVal)
	if(ckVal == "") {
		return false, smart.NewError("Captcha Cookie Value is Empty")
	} //end if
	if(len(ckVal) > 255) {
		return false, smart.NewError("Captcha Cookie Value is Too Long")
	} //end if
	if(!smart.StrContains(ckVal, "|")) {
		return false, smart.NewError("Captcha Cookie Value is Invalid")
	} //end if
	//--
	arr := smart.ExplodeWithLimit("|", ckVal, 2)
	if(len(arr) != 2) {
		return false, smart.NewError("Captcha Cookie Value Mismatch")
	} //end if
	//--
	arr[0] = smart.StrTrimWhitespaces(arr[0]) // signature
	arr[1] = smart.StrTrimWhitespaces(arr[1]) // code
	if(arr[0] == "") {
		return false, smart.NewError("Captcha Cookie Value is Missing the Signature")
	} //end if
	if(arr[1] == "") {
		return false, smart.NewError("Captcha Cookie Value is Contains No Code") // empty code completed by visitor
	} //end if
	arr[1] = smart.StrTrimWhitespaces(smart.Base64Decode(arr[1]))
	if(len(arr[1]) < 3) {
		return false, smart.NewError("Captcha Cookie Value is Too Short") // invalid code completed by visitor
	} //end if
	if(len(arr[1]) > 7) {
		return false, smart.NewError("Captcha Cookie Value is Too Long") // invalid code completed by visitor
	} //end if
	//--
	if(arr[0] != cookieValSafeHash(arr[1], ckName, clientIdentUidHash)) {
		return false, nil // wrong code completed by visitor
	} //end if
	//--
	return true, nil
	//--
} //END FUNCTION


func GetCaptchaHtmlAndCode(mode string, ckName string, clientIdentUidHash string) (CaptchaStruct, error) {
	//--
	captchaStruct := CaptchaStruct{}
	//--
	clientIdentUidHash = smart.StrTrimWhitespaces(clientIdentUidHash)
	if(len(clientIdentUidHash) < 80) { // expects SHA3-512-B64
		return captchaStruct, smart.NewError("Invalid Captcha Client UID Hash: too short")
	} //end if
	//--
	ckName = smart.StrCreateStdVarName(ckName)
	if(smart.StrTrimWhitespaces(ckName) == "") {
		return captchaStruct, smart.NewError("Invalid Captcha Cookie Name: `" + ckName + "`")
	} //end if
	//--
	mode = smart.StrToLower(smart.StrTrimWhitespaces(mode))
	arrMode := smart.Explode(":", mode)
	if(len(arrMode) < 1) {
		return captchaStruct, smart.NewError("Invalid Captcha Mode: `" + mode + "`")
	} //end if
	//--
	json := smart.JsonNoErrChkEncode(arrMode, false, false)
	gJsonRes := smart.JsonGetValueByKeyPath(json, "")
	//--
	switch(arrMode[0]) {
		case "ascii": // ascii:palette:size:chars:pool
			//--
			typ := gJsonRes.Get("0").String()
			if(typ != arrMode[0]) {
				return captchaStruct, smart.NewError("Captcha Mode Mismatch: `" + mode + "` ; [`" + typ + "`=`" + arrMode[0] + "`]")
			} //end if
			//--
			palette := gJsonRes.Get("1").Int()
			if(palette < 0) { // {{{SYNC-ASCII-CAPTCHA-PALETTE-MIN}}}
				palette = 0
			} else if(palette > 3) { // {{{SYNC-ASCII-CAPTCHA-PALETTE-MAX}}}
				palette = 3
			} //end if
			//--
			size := gJsonRes.Get("2").String()
			size = smart.StrTrimWhitespaces(size)
			if(size == "") { // {{{SYNC-ASCII-CAPTCHA-SIZES}}}
				size = "0.375"
			} //end if
			//--
			chars := gJsonRes.Get("3").Int()
			if(chars <= 0) {
				chars = 5 // default
			} //end if
			if(chars < 3) { // {{{SYNC-ASCII-CAPTCHA-CHARS-MIN}}}
				chars = 3
			} else if(chars > 7) { // {{{SYNC-ASCII-CAPTCHA-CHARS-MAX}}}
				chars = 7
			} //end if else
			//--
			pool := gJsonRes.Get("4").String()
			if(pool == "default") {
				pool = asciicaptcha.DefaultPool
			} else { // safe
				pool = asciicaptcha.DefaultSafePool
			} //end if
			//--
			asciiCaptchaStruct := asciicaptcha.GetCaptchaHtmlAndCode(uint8(palette), size, uint8(chars), pool)
			//--
			asciiCaptchaStruct.Code = smart.StrTrimWhitespaces(asciiCaptchaStruct.Code)
			asciiCaptchaStruct.Html = smart.StrTrimWhitespaces(asciiCaptchaStruct.Html)
			if(asciiCaptchaStruct.Code == "") {
				return captchaStruct, smart.NewError("Captcha Code is Empty")
			} //end if
			if(asciiCaptchaStruct.Html == "") {
				return captchaStruct, smart.NewError("Captcha Html is Empty")
			} //end if
			//--
			var ckVal string = cookieValSafeHash(asciiCaptchaStruct.Code, ckName, clientIdentUidHash)
			//--
			captchaStruct.Code = asciiCaptchaStruct.Code
			captchaStruct.Html = smart.RenderMarkersTpl(CAPTCHA_TPL_HTML, map[string]string{
				"UUID": smart.Crc32bB36(typ + smart.FORM_FEED + asciiCaptchaStruct.Html),
				"HTML-CODE": asciiCaptchaStruct.Html,
				"CAPTCHA-CHARS": smart.ConvertInt64ToStr(chars),
				"CHARS-MASK": smart.StrRepeat("*", int(chars)),
				"COOKIE-NAME": ckName,
				"COOKIE-VAL": ckVal,
			})
			//--
			return captchaStruct, nil
			//--
			break
		default:
			// N/A
	} //end switch
	//--
	return captchaStruct, smart.NewError("Unsupported Captcha Mode: `" + mode + "`")
	//--
} //END FUNCTION


func cookieValSafeHash(captchaCode string, ckName string, clientIdentUidHash string) string {
	//--
	captchaCode = smart.StrToUpper(captchaCode) // case insensitive
	//--
	return smart.StrTrimRight(smart.Base64ToBase64s(smart.Sh3a224B64("[" + smart.StrTrimWhitespaces(captchaCode) + "]" + smart.NULL_BYTE + smart.StrTrimWhitespaces(ckName) + smart.NULL_BYTE + "(" + smart.StrTrimWhitespaces(clientIdentUidHash) + ")")), ".")
	//--
} //END FUNCTION


// #END
