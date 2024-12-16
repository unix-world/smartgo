
// SmartGo ASCII Captcha - Plugin for: SmartGo Captcha
// (c) 2024-present unix-world.org
// v.20241216.2358
// license: BSD

//-- based on:
// original work: ASCII Captcha 		@ https://github.com/bohnelang/ascii_captcha 		# head.20210317		! License: CC0
// derived  work: Smart ASCII Captcha 	@ https://github.com/unix-world/Smart.Framework 	# head.20241115 	! License: BSD
//-- #

package asciicaptcha

import (
	"fmt"
	"log"
	"math"

	smart "github.com/unix-world/smartgo"
)


const (
	captchaGlyphsPool string = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" // can also include punctuation, see arr below
	captchaGlyphsRpl  string = "#" // hash # as render character is the best choice because the html hex colors are prefixed also with a hash as: #RRGGBB
	captchaGlyphsChr  string = "*" // the character used in raw representation, below ; DO NOT CHANGE !

	maxPoolSize uint8 = 84

	DefaultNumChars uint8  = 5 // default chars
	DefaultFontSize string = "0.344" // default font size, rem ; 4px = 0.250rem ; 5px = 0.313rem ; 6px = 0.375rem ; 7px = 0.438rem ; 8px = 0.500rem ; 9px = 0.563rem ; 10px = 0.625rem ; 11px = 0.688rem ; 12px = 0.750rem
	DefaultPool     string = captchaGlyphsPool
	DefaultSafePool string = "23467ABcEFHjKLMnPRtuVWxYz" // the safe pool, for avoid character confusion ; original: `247AcEFHKLMNPRTuVwxYz`
)

var (
	captchaGlyphsArr []string = []string{ // {{{SYNC-ASCII-CAPTCHA-GLYPHS-POOL-LEN}}}

		"         ***  **   **  * *   *****          **     ***  ",
		"         ***  **   **  * *  *  *  ***   *  *  *    ***  ",
		"         ***   *   * ********  *   **  *    **      *   ",
		"          *            * *   *****    *    ***     *    ",
		"                     *******   *  *  *    *   * *       ",
		"         ***           * *  *  *  * *  ** *    *        ",
		"         ***           * *   ***** *   **  **** *       ",

		"   **    **                                            *",
		"  *        *   *   *    *                             * ",
		" *          *   * *     *                            *  ",
		" *          * ******* *****   ***   *****           *   ",
		" *          *   * *     *     ***                  *    ",
		"  *        *   *   *    *      *            ***   *     ",
		"   **    **                   *             ***  *      ",

		"  ***     *    *****  ***** *      ******* ***** *******",
		" *   *   **   *     **     **    * *      *     **    * ",
		"*   * * * *         *      **    * *      *          *  ",
		"*  *  *   *    *****  ***** ******* ***** ******    *   ",
		"* *   *   *   *            *     *       **     *  *    ",
		" *   *    *   *      *     *     * *     **     *  *    ",
		"  ***   ***** ******* *****      *  *****  *****   *    ",

		" *****  *****          ***      *           *     ***** ",
		"*     **     *  ***    ***     *             *   *     *",
		"*     **     *  ***           *     *****     *        *",
		" *****  ******         ***   *                 *     ** ",
		"*     *      *         ***    *     *****     *     *   ",
		"*     **     *  ***     *      *             *          ",
		" *****  *****   ***    *        *           *       *   ",

		" *****    *   ******  ***** ****** ************** ***** ",
		"*     *  * *  *     **     **     **      *      *     *",
		"* *** * *   * *     **      *     **      *      *      ",
		"* * * **     ******* *      *     ******  *****  *  ****",
		"* **** ********     **      *     **      *      *     *",
		"*     **     **     **     **     **      *      *     *",
		" ***** *     *******  ***** ****** ********       ***** ",

		"*     *  ***        **    * *      *     **     ********",
		"*     *   *         **   *  *      **   ****    **     *",
		"*     *   *         **  *   *      * * * ** *   **     *",
		"*******   *         ****    *      *  *  **  *  **     *",
		"*     *   *   *     **  *   *      *     **   * **     *",
		"*     *   *   *     **   *  *      *     **    ***     *",
		"*     *  ***   ***** *    * ********     **     ********",

		"******  ***** ******  ***** ********     **     **     *",
		"*     **     **     **     *   *   *     **     **  *  *",
		"*     **     **     **         *   *     **     **  *  *",
		"****** *     *******  *****    *   *     **     **  *  *",
		"*      *   * **   *        *   *   *     * *   * *  *  *",
		"*      *    * *    * *     *   *   *     *  * *  *  *  *",
		"*       **** **     * *****    *    *****    *    ** ** ",

		"*     **     ******** ***** *       *****    *          ",
		" *   *  *   *      *  *      *          *   * *         ",
		"  * *    * *      *   *       *         *  *   *        ",
		"   *      *      *    *        *        *               ",
		"  * *     *     *     *         *       *               ",
		" *   *    *    *      *          *      *               ",
		"*     *   *   ******* *****       * *****        *******",

		"  ***                                                   ",
		"  ***     **   *****   ****  *****  ****** ******  **** ",
		"   *     *  *  *    * *    * *    * *      *      *    *",
		"    *   *    * *****  *      *    * *****  *****  *     ",
		"        ****** *    * *      *    * *      *      *  ***",
		"        *    * *    * *    * *    * *      *      *    *",
		"        *    * *****   ****  *****  ****** *       **** ",

		"                                                        ",
		" *    *    *        * *    * *      *    * *    *  **** ",
		" *    *    *        * *   *  *      **  ** **   * *    *",
		" ******    *        * ****   *      * ** * * *  * *    *",
		" *    *    *        * *  *   *      *    * *  * * *    *",
		" *    *    *   *    * *   *  *      *    * *   ** *    *",
		" *    *    *    ****  *    * ****** *    * *    *  **** ",

		"                                                        ",
		" *****   ****  *****   ****   ***** *    * *    * *    *",
		" *    * *    * *    * *         *   *    * *    * *    *",
		" *    * *    * *    *  ****     *   *    * *    * *    *",
		" *****  *  * * *****       *    *   *    * *    * * ** *",
		" *      *   *  *   *  *    *    *   *    *  *  *  **  **",
		" *       *** * *    *  ****     *    ****    **   *    *",

		"                       ***     *     ***   **    * * * *",
		" *    *  *   * ****** *        *        * *  *  * * * * ",
		"  *  *    * *      *  *        *        *     ** * * * *",
		"   **      *      *  **                 **        * * * ",
		"   **      *     *    *        *        *        * * * *",
		"  *  *     *    *     *        *        *         * * * ",
		" *    *    *   ******  ***     *     ***         * * * *",

	}
)


type CaptchaStruct struct {
	Code string `json:"-"` // do not export to json, by accident
	Html string `json:"html"`
}


func GetCaptchaHtmlAndCode(palette uint8, size string, numChars uint8, pool string) CaptchaStruct {
	//--
	// palette: 0: grey ; 1: blue/yellow ; 2: red/green ; 3: rgb
	// size: @see: DefaultFontSize accepted values
	//--
	captchaStruct := CaptchaStruct{}
	//--
	if(pool == "") {
		pool = captchaGlyphsPool // default, if empty
	} //end if
	//--
	pool = smart.StrTrimWhitespaces(pool)
	if(pool == "") {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Pool is Empty")
		return captchaStruct
	} //end if
	if(!smart.StrRegexMatch(`^[A-Za-z0-9]+$`, pool)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Pool contains Invalid Characters: `" + pool + "`")
		return captchaStruct
	} //end if
	//--
	if(numChars <= 0) {
		numChars = DefaultNumChars // default, if zero
	} //end if
	if(numChars < 3) { // {{{SYNC-ASCII-CAPTCHA-CHARS-MIN}}}
		numChars = 3
	} else if(numChars > 7) { // {{{SYNC-ASCII-CAPTCHA-CHARS-MAX}}}
		numChars = 7
	} //end if
	//--
	if(smart.StrLen(pool) < int(numChars)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Pool is Too Short vs. numChars")
		return captchaStruct
	} else if(smart.StrLen(pool) > int(maxPoolSize)) {
		log.Println("[WARNING]", smart.CurrentFunctionName(), "Pool is Too Long vs. GlyphsPool")
		return captchaStruct
	} //end if else
	//--
	size = smart.ParseFloatStrAsDecimalStr(size, 3)
	switch(size) { // {{{SYNC-ASCII-CAPTCHA-SIZES}}}
		case "0.250": fallthrough //  4px
		case "0.313": fallthrough //  5px
		case "0.375": fallthrough //  6px
		case "0.438": fallthrough //  7px
		case "0.500": fallthrough //  8px
		case "0.563": fallthrough //  9px
		case "0.625": fallthrough // 10px
		case "0.688": fallthrough // 11px
		case "0.750": fallthrough // 12px
		case DefaultFontSize: // special
			break
		default:
			size = DefaultFontSize
	} //end switch
	//--
	if(palette < 0) { // {{{SYNC-ASCII-CAPTCHA-PALETTE-MIN}}} ; 0: grey
		palette = 0
	} else if(palette > 3) { // {{{SYNC-ASCII-CAPTCHA-PALETTE-MAX}}} ; 1: blue/yellow ; 2: red/green ; 3: rgb
		palette = 3
	} //end if else
	//--
	var code string  = generateRandStr(pool, numChars)
	var ascii string = generateAsciiArt(code)
	//--
	captchaStruct.Code = smart.StrToUpper(code)
	captchaStruct.Html = `<div title="Captcha"><div class="Smart-Captcha-AsciiArt" style="background:#FFFFFF; border:1px solid #E7E7E7; display:inline-block!important; padding:0!important; padding-left:5px; padding-right:5px; margin-bottom:5px;"><pre style="margin:3px!important; padding:0!important; font-weight:bold!important; font-size:` + smart.EscapeHtml(size) + `rem!important; line-height:` + smart.EscapeHtml(size) + `rem!important;">` + "\n" + renderHtml(ascii, palette, size) + "\n" + `</pre></div></div>`
	//--
	return captchaStruct
	//--
} //END FUNCTION


func renderHtml(asciiart string, palette uint8, size string) string {
	//--
	if(asciiart == "") {
		return ""
	} //end if
	//--
	var ret string = "" // init
	//--
	for i:=0; i<len(asciiart); i++ {
		//--
		var c string = smart.StrSubstr(asciiart, i, i+1)
		//--
		if(smart.Ord(c) < 32) {
			//--
			ret += "\n"
			//--
		} else { // 0: grey
			//--
			var fsr uint = randColorLow()
			//--
			var fsg uint = fsr
			if((palette == 2) || (palette == 3)) { // 2: red/green ; 3: rgb
				fsg = randColorLow()
			} //end if
			//--
			var fsb uint = fsr
			if((palette == 1) || (palette == 3)) { // 1: blue/yellow ; 3: rgb
				fsb = randColorLow()
			} //end if
			//--
			var fwr uint = randColorHigh()
			//--
			var fwg uint = fwr
			if((palette == 2) || (palette == 3)) { // 2: red/green ; 3: rgb
				fwg = randColorHigh()
			} //end if
			//--
			var fwb uint = fwr
			if((palette == 1) || (palette == 3)) { // 1: blue/yellow ; 3: rgb
				fwb = randColorHigh()
			} //end if
			//--
			var colx string = smart.StrToUpper(fmt.Sprintf("%x%x%x", fsr, fsg, fsb))
			var colw string = smart.StrToUpper(fmt.Sprintf("%x%x%x", fwr, fwg, fwb))
			//--
			var cols string = ""
			if(c == captchaGlyphsChr) {
				cols = colx
			} else {
				cols = colw
			} //end if else
			//--
			ret += `<span style="background:#FFFFFF!important; color:#` + smart.EscapeHtml(cols) + `!important; font-size:` + smart.EscapeHtml(size) + `rem!important; line-height:` + smart.EscapeHtml(size) + `rem!important;">` + smart.EscapeHtml(captchaGlyphsRpl) + `</span>`
			//--
		} //end if else
		//--
	} //end for
	//--
	return smart.StrTrimWhitespaces(ret)
	//--
} //END FUNC


func generateRandStr(pool string, numChars uint8) string {
	//--
	if(numChars < 3) { // {{{SYNC-ASCII-CAPTCHA-CHARS-MIN}}}
		numChars = 3
	} else if(numChars > 7) { // {{{SYNC-ASCII-CAPTCHA-CHARS-MAX}}}
		numChars = 7
	} //end if
	//--
	pool = smart.StrTrimWhitespaces(pool)
	//--
	var len int = smart.StrLen(pool) - 1
	if(len <= 0) {
		return ""
	} //end if
	//--
	var str string = ""
	//--
	for i:=0; i<int(numChars); i++ {
		var rnd uint = smart.NanoTimeRandIntN(0, len)
		if(int64(rnd) > int64(len)) {
			rnd = uint(len)
		} //end if
		str += smart.StrSubstr(pool, int(rnd), int(rnd)+1)
	} //end for
	//--
	return str
	//--
} //END FUNCTION


func generateAsciiArt(codestr string) string {
	//--
	var maxPool int = len(captchaGlyphsArr)
	if(maxPool != int(maxPoolSize)) { // {{{SYNC-ASCII-CAPTCHA-GLYPHS-POOL-LEN}}}
		log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Glyphs Pool Length:", maxPool)
		return ""
	} //end if
	//--
	var cLen int = smart.StrLen(codestr)
	if(cLen < 0) { // check uint8 min limit, for below conversion
		return ""
	} else if(cLen > 255) { // check uint8 max limit, for below conversion
		return ""
	} //end if else
	var emptyLine string = generateAsciiEmptyLine(uint8(cLen)) // safety checks for this conversion are above
	//--
	var ret string = emptyLine + "\n" // add a blank line above
	//--
	for j:=0; j<7; j++ {
		var line string = ""
		for k:=0; k<smart.StrLen(codestr); k++ {
			var ind int = int(smart.Ord(smart.StrSubstr(codestr, k, k+1))) - 32
			var a int = int(math.Floor(float64(ind) / 8)) * 7 + j
			if(a < 0) {
				a = 0
			} else if(a > (maxPool - 1)) {
				log.Println("[ERROR]", smart.CurrentFunctionName(), "Invalid Glyphs Pool Index:", a)
				return ""
			} //end if
			var b int = ind % 8 * 7
			if(b < 0) {
				b = 0
			} //end if
			line += "  "
			line += smart.StrSubstr(captchaGlyphsArr[a], b, b+7)
			line += "  "
		} //end for
		ret += line + "\n"
	} //end for
	//--
	ret += emptyLine + "\n" // add a blank line above
	//--
	return ret
	//--
} //END FUNCTION


func generateAsciiEmptyLine(numChars uint8) string {
	//--
	if(numChars < 3) { // {{{SYNC-ASCII-CAPTCHA-CHARS-MIN}}}
		numChars = 3
	} else if(numChars > 7) { // {{{SYNC-ASCII-CAPTCHA-CHARS-MAX}}}
		numChars = 7
	} //end if
	//--
	return smart.StrRepeat(" ", 11 * int(numChars))
	//--
} //END FUNCTION


func getRandNum() uint {
	//--
	return smart.NanoTimeRandIntN(0, -1) // 0 ... max
	//--
} //END FUNCTION


func randColorShift() uint {
	//--
	return getRandNum() % 50 // return values between 0 and 49
	//--
} //END FUNCTION


func randColorLow() uint { // return values between 65 and 177
	//--
//	return smart.NanoTimeRandIntN(16, 128) + randColorShift() // should not overflow 255 ; rand color shift return values between 0 and 49 !!!
	return smart.NanoTimeRandIntN(32, 128) + randColorShift() // should not overflow 255 ; rand color shift return values between 0 and 49 !!!
	//--
} //END FUNCTION


func randColorHigh() uint { // return values between: 241 and 253
	//--
	return smart.NanoTimeRandIntN(192, 204) + randColorShift() // should not overflow 255 ; rand color shift return values between 0 and 49 !!!
	//--
} //END FUNCTION


// #END
