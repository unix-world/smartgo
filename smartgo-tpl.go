
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260111.2358 :: STABLE
// [ TPL (MARKERS-TPL TEMPLATING) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"regexp"
	"strings"
	"encoding/json"
)

//-----

const (
	SPECIAL_TRIM string = "\n\r\x00\x0B" // {{{SYNC-TPL-FIX-TRIM-PARTS}}}

	UNDEF_VAR_NAME string = "Undef____V_a_r"

	MTPL_FILE_EXTENSION string = ".mtpl.htm"

	MAX_DOC_SIZE_TPL uint64 = SIZE_BYTES_16M // {{{SYNC-TPL-MAX-SIZE}}} ; 16MB
)

//-----


//-----


func RenderMainHtmlMarkersTpl(template string, arrobj map[string]string, arrpobj map[string]string) string {
	//--
	// render a string TPL with markers and placeholders ; this is intended to be used for a main template only
	//--
	defer PanicHandler()
	//--
	if(template == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return ""
	} //end if
	if(uint64(len(template)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	template = MarkersTplRender(template, arrobj, false, false, true, true) // escape remaining syntax + is main html
	//--
	template = PlaceholdersTplRender(template, arrpobj, false, false)
	//--
	return template
	//--
} //END FUNCTION


func RenderMarkersTpl(template string, arrobj map[string]string) string {
	//--
	// render a string TPL with markers ; this is intended to be used for a partial template only
	//--
	defer PanicHandler()
	//--
	if(template == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return ""
	} //end if
	if(uint64(len(template)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	return MarkersTplRender(template, arrobj, false, false, true, false) // escape remaining syntax + is not main html
	//--
} //END FUNCTION


//-----


func RenderMainHtmlMarkersFileTpl(mtplFile string, arrobj map[string]string, arrpobj map[string]string) (string, error) {
	//--
	// render a file TPL with markers, placeholders and sub-templates (1 level only) ; this is intended to be used for a main template only
	//--
	defer PanicHandler()
	//--
	template, err := readTPLFile(mtplFile)
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL Read Error", err, mtplFile)
		return "", err
	} //end if
	if(uint64(len(template)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized", mtplFile)
		return "", NewError("TPL is OverSized")
	} //end if
	//--
	if(StrTrimWhitespaces(template) == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty", mtplFile)
		return "", NewError("TPL File is Empty: `" + mtplFile + "`")
	} //end if
	//--
	var errStplProcess error = nil
	template, errStplProcess = markersTplProcessSubTemplates(mtplFile, template)
	if(errStplProcess != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Sub-TPL Process Failed", mtplFile, "#", errStplProcess)
	} //end if
	//--
	template = MarkersTplRender(template, arrobj, false, false, true, true) // escapes the remaining syntax + is main html
	//--
	template = PlaceholdersTplRender(template, arrpobj, false, false)
	//--
	return template, nil
	//--
} //END FUNCTION


func RenderMarkersFileTpl(mtplFile string, arrobj map[string]string) (string, error) {
	//--
	// render a file TPL with markers and sub-templates (1 level only) ; this is intended to be used for a partial template only
	//--
	defer PanicHandler()
	//--
	template, err := readTPLFile(mtplFile)
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL Read Error", err, mtplFile)
		return "", err
	} //end if
	if(uint64(len(template)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized", mtplFile)
		return "", NewError("TPL is OverSized")
	} //end if
	//--
	if(StrTrimWhitespaces(template) == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty", mtplFile)
		return "", NewError("TPL File is Empty: `" + mtplFile + "`")
	} //end if
	//--
	var errStplProcess error = nil
	template, errStplProcess = markersTplProcessSubTemplates(mtplFile, template)
	if(errStplProcess != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Sub-TPL Process Failed", mtplFile, "#", errStplProcess)
	} //end if
	//--
	template = MarkersTplRender(template, arrobj, false, false, true, false) // escapes the remaining syntax + is not main html
	//--
	return template, nil
	//--
} //END FUNCTION


//-----


func MarkersTplEscapeTpl(tpl string) string {
	//--
	// encode a markers TPL string for safe using with inline javascript code inside HTML to avoid interferences with existing syntax
	//--
	if(tpl == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return ""
	} //end if
	if(uint64(len(tpl)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	return RawUrlEncode(tpl)
	//--
} //END FUNCTION


//-----
//===== below methods are intended just for low level or internal usage
//-----


func MarkersTplPrepareNosyntaxContent(tpl string) string {
	//--
	// low level usage only
	//--
	if(tpl == "") {
		// no warning on empty
		return ""
	} //end if
	if(uint64(len(tpl)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	return StrTr(tpl, map[string]string{ // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
		"[###": "［###",
		"###]": "###］",
		"[%%%": "［%%%",
		"%%%]": "%%%］",
		"[@@@": "［@@@",
		"@@@]": "@@@］",
		"[:::": "［:::",
		":::]": ":::］",
	})
	//--
} //END FUNCTION


func MarkersTplRevertNosyntaxContent(tpl string) string {
	//--
	// low level usage only
	//--
	if(tpl == "") {
		// no warning on empty
		return ""
	} //end if
	if(uint64(len(tpl)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	return StrTr(tpl, map[string]string{ // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
		"［###": "[###",
		"###］": "###]",
		"［%%%": "[%%%",
		"%%%］": "%%%]",
		"［@@@": "[@@@",
		"@@@］": "@@@]",
		"［:::": "[:::",
		":::］": ":::]",
	})
	//--
} //END FUNCTION


func MarkersTplPrepareNosyntaxHtml(tpl string, isMainHtml bool) string {
	//--
	// low level usage only
	//--
	if(tpl == "") {
		// no warning on empty
		return ""
	} //end if
	if(uint64(len(tpl)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "[###", "&lbrack;&num;&num;&num;")
	tpl = StrReplaceAll(tpl, "###]", "&num;&num;&num;&rbrack;")
	tpl = StrReplaceAll(tpl, "[%%%", "&lbrack;&percnt;&percnt;&percnt;")
	tpl = StrReplaceAll(tpl, "%%%]", "&percnt;&percnt;&percnt;&rbrack;")
	tpl = StrReplaceAll(tpl, "[@@@", "&lbrack;&commat;&commat;&commat;")
	tpl = StrReplaceAll(tpl, "@@@]", "&commat;&commat;&commat;&rbrack;")
	if(isMainHtml == false) { // for a main template these must remain to be able to post replace placeholders
		tpl = StrReplaceAll(tpl, "[:::", "&lbrack;&colon;&colon;&colon;")
		tpl = StrReplaceAll(tpl, ":::]", "&colon;&colon;&colon;&rbrack;")
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "［###", "&lbrack;&num;&num;&num;")
	tpl = StrReplaceAll(tpl, "###］", "&num;&num;&num;&rbrack;")
	tpl = StrReplaceAll(tpl, "［%%%", "&lbrack;&percnt;&percnt;&percnt;")
	tpl = StrReplaceAll(tpl, "%%%］", "&percnt;&percnt;&percnt;&rbrack;")
	tpl = StrReplaceAll(tpl, "［@@@", "&lbrack;&commat;&commat;&commat;")
	tpl = StrReplaceAll(tpl, "@@@］", "&commat;&commat;&commat;&rbrack;")
	tpl = StrReplaceAll(tpl, "［:::", "&lbrack;&colon;&colon;&colon;")
	tpl = StrReplaceAll(tpl, ":::］", "&colon;&colon;&colon;&rbrack;")
	//--
	return tpl
	//--
} //END FUNCTION


func MarkersTplEscapeSyntaxContent(tpl string, isMainHtml bool) string {
	//--
	// low level usage only ; this is applied automatically on render
	// escapes a markers TPL string before injecting into a TPL, to avoid interferences
	//--
	if(tpl == "") {
		// no warning on empty
		return ""
	} //end if
	if(uint64(len(tpl)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "[###", "⁅###¦")
	tpl = StrReplaceAll(tpl, "###]", "¦###⁆")
	tpl = StrReplaceAll(tpl, "[%%%", "⁅%%%¦")
	tpl = StrReplaceAll(tpl, "%%%]", "¦%%%⁆")
	tpl = StrReplaceAll(tpl, "[@@@", "⁅@@@¦")
	tpl = StrReplaceAll(tpl, "@@@]", "¦@@@⁆")
	if(isMainHtml == false) { // for a main template these must remain to be able to post replace placeholders
		tpl = StrReplaceAll(tpl, "[:::", "⁅:::¦")
		tpl = StrReplaceAll(tpl, ":::]", "¦:::⁆")
	} //end if
	//--
	return tpl
	//--
} //END FUNCTION


func PlaceholdersTplRender(template string, arrpobj map[string]string, isEncoded bool, revertSyntax bool) string {
	//--
	// render a file TPL with placeholders
	// this is intended for low level usage only
	// use Render* methods from above
	//--
	defer PanicHandler() // url decode may panic
	//--
	if(StrTrimWhitespaces(template) == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return ""
	} //end if
	if(uint64(len(template)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	if(isEncoded == true) {
		template = RawUrlDecode(template)
	} //end if
	if(revertSyntax == true) {
		template = MarkersTplRevertNosyntaxContent(template)
	} //end if
	//-- trim whitespaces
	template = StrTrimWhitespaces(template)
	//--
	const regexPlaceholderVarName string = `^[A-Z0-9_\-]+$`
	//--
	if(arrpobj != nil) {
		for k, v := range arrpobj {
			if(k != "") {
				if(StrRegexMatch(regexPlaceholderVarName, k)) {
					template = StrReplaceAll(template, "[:::" + k + ":::]", v)
				} //end if
			} //end if
		} //end for
	} //end if
	//--
	return template
	//--
} //END FUNCTION


func MarkersTplRender(template string, arrobj map[string]string, isEncoded bool, revertSyntax bool, escapeRemainingSyntax bool, isMainHtml bool) string {
	//-- syntax: r.20250126
	// render a string TPL with markers and placeholders and custom options
	// low level usage only
	// use Render* methods from above
	//--
	defer PanicHandler() // url decode may panic
	//--
	if(StrTrimWhitespaces(template) == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return ""
	} //end if
	if(uint64(len(template)) > MAX_DOC_SIZE_TPL) {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is OverSized")
		return ""
	} //end if
	//--
	if(isEncoded == true) {
		template = RawUrlDecode(template)
	} //end if
	if(revertSyntax == true) {
		template = MarkersTplRevertNosyntaxContent(template)
	} //end if
	//-- trim whitespaces
	template = StrTrimWhitespaces(template)
	//-- replace out comments
	if((StrContains(template, "[%%%COMMENT%%%]") == true) && (StrContains(template, "[%%%/COMMENT%%%]") == true)) {
		template = StrRegexReplaceAll(`(?s)\s??\[%%%COMMENT%%%\](.*?)??\[%%%\/COMMENT%%%\]\s??`, template, "") // regex syntax as in PHP
	} //end if
	//-- process loop syntax
	if(StrContains(template, "[%%%LOOP:") == true) {
	//	log.Println("[DEBUG]", CurrentFunctionName(), "Processing LOOP Syntax")
		template = markersTplProcessLoopSyntax(template, arrobj)
	} //end if
	//-- process if (conditionals) syntax
	if(StrContains(template, "[%%%IF:") == true) {
	//	log.Println("[DEBUG]", CurrentFunctionName(), "Processing IF Syntax")
		template = markersTplProcessIfSyntax(template, arrobj)
	} //end if
	//-- process markers
	if(StrContains(template, "[###") == true) {
	//	log.Println("[DEBUG]", CurrentFunctionName(), "Processing MARKER Syntax")
		template = markersTplProcessMarkerSyntax(template, arrobj, "")
	} //end if
	//-- replace specials: Square-Brackets(L/R) R N TAB SPACE
	if(StrContains(template, "[%%%|") == true) {
	//	log.Println("[DEBUG]", CurrentFunctionName(), "Processing SPECIALS Syntax")
		template = StrReplaceAll(template, "[%%%|SB-L%%%]", "［")
		template = StrReplaceAll(template, "[%%%|SB-R%%%]", "］")
		template = StrReplaceAll(template, "[%%%|R%%%]",    CARRIAGE_RETURN)
		template = StrReplaceAll(template, "[%%%|N%%%]",    LINE_FEED)
		template = StrReplaceAll(template, "[%%%|T%%%]",    HORIZONTAL_TAB)
		template = StrReplaceAll(template, "[%%%|SPACE%%%]", " ")
	} //end if
	//--
	template = StrReplaceAll(template, NULL_BYTE, " ")
	template = StrReplaceAll(template, BACK_SPACE, " ")
	template = StrReplaceAll(template, ASCII_BELL, " ")
	template = StrReplaceAll(template, FORM_FEED, " ")
	template = StrReplaceAll(template, VERTICAL_TAB, " ")
	//--
	if(escapeRemainingSyntax == true) {
		//--
		if(isMainHtml == false) {
			if(StrContains(template, "[:::") == true) {
				log.Println("[WARNING]", CurrentFunctionName(), ": {### Undefined Placeholders detected in Template ###}")
			} //end if
		} //end if
		if(StrContains(template, "[###") == true) {
			log.Println("[WARNING]", CurrentFunctionName(), ": {### Undefined Markers detected in Template ###}")
		} //end if
		if(StrContains(template, "[%%%") == true) {
			log.Println("[WARNING]", CurrentFunctionName(), ": {### Undefined Marker Syntax detected in Template ###}")
		} //end if
		if(StrContains(template, "[@@@") == true) {
			log.Println("[WARNING]", CurrentFunctionName(), ": {### Undefined Marker Sub-Templates detected in Template ###}")
		} //end if
		//--
		template = MarkersTplEscapeSyntaxContent(template, isMainHtml) // this will not escape the syntax already prepared by MarkersTplPrepareNosyntaxContent (PrepareNosyntax) that comes from a value, but only remaining syntax
		//--
	} //end if
	//--
	if(isMainHtml == true) {
		template = MarkersTplPrepareNosyntaxHtml(template, true) // this will revert to html entities the Syntax or PrepareNosyntax ; but in the case if syntax is escaped above, will just process PrepareNosyntax
	} //end if
	//--
	return template
	//--
} //END FUNCTION


//-----
//===== below methods are intended just for internal usage
//-----


func markersTplProcessSubTemplates(mtplFile string, template string) (string, error) {
	//--
	// the current implementation supports just 1st level sub-templates, to simplify things and have a better security management
	//--
	if((template == "") || (!StrContains(template, "[@@@SUB-TEMPLATE:")) || (!StrContains(template, "@@@]"))) {
		return template, nil
	} //end if
	//--
	arrSTPLs := markersTplDetectSubTemplates(template)
	//--
	if((arrSTPLs != nil) && (len(arrSTPLs) > 0)) {
		var errStplLoad error = nil
		template, errStplLoad = markersTplLoadSubTemplates(mtplFile, template, arrSTPLs)
		if(errStplLoad != nil) {
			return template, errStplLoad
		} //end if
	} //end if
	//--
	return template, nil
	//--
} //END FUNCTION


func markersTplDetectSubTemplates(template string) map[string]string {
	//
	// may return: nil | map[string]string
	//--
	defer PanicHandler()
	//--
	if(template == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return nil
	} //end if
	//-- detect all sub templates
//	var rExp string = `\[@@@SUB\-TEMPLATE\:([a-zA-Z0-9_\-\.\/\!\?\|]+)@@@\]` // {{{SYNC-TPL-EXPR-SUBTPL}}} ; full support, compatible with Smart.Framework.PHP
	var rExp string = `\[@@@SUB\-TEMPLATE\:([a-zA-Z0-9_\-\.\/\|]+)@@@\]`     // {{{SYNC-TPL-EXPR-SUBTPL}}} ; partial support, for Go only ; unsupported mode: `!?`
	var arrSTPLs map[string]string = map[string]string{}
//	matches, errRx := StrRegex2FindAllMatches("PERL", rExp, template, 0, 0)
	matches, errRx := StrRegexFindAllMatches(rExp, template, 0)
	if(errRx != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Regex Failed", errRx)
		return arrSTPLs
	} //end if
	for c := 0; c < len(matches); c++ {
		//--
		g := matches[c]
		//--
		if(len(g) != 2) { // expects 2 regex groups
			//--
			log.Println("[WARNING]", CurrentFunctionName(), "Regex Group Size Error, Expected is # 2 but having #", len(g))
			return arrSTPLs
			//--
		} else {
			//--
			var tmp_stpl_expr string = g[0] // the whole subtpl expression: [@@@SUB-TEMPLATE:sub-templates/sub-tpl.inc.mtpl.htm|xyz@@@]
			var tmp_stpl_fpth string = g[1] // the path part, includding escapes: sub-templates/sub-tpl.inc.mtpl.htm|xyz
			//--
			arrSTPLs[tmp_stpl_expr] = tmp_stpl_fpth
			//--
		} //end if
		//--
	} //end for
	//--
	return arrSTPLs
	//--
} //END FUNCTION


func markersTplLoadSubTemplates(mtplFile string, template string, arrSTPLs map[string]string) (string, error) {
	//--
	// supported escapings: `|trim` `|js` `|js|html` `|html`
	//--
	mtplFile = StrTrimWhitespaces(mtplFile)
	if(
		(mtplFile == "") ||
		(PathIsEmptyOrRoot(mtplFile) == true) ||
		(PathIsSafeValidPath(mtplFile) != true) ||
		(PathIsBackwardUnsafe(mtplFile) == true) ||
		(PathIsAbsolute(mtplFile) == true)) {
		return template, NewError("Sub-TPL File Path is Empty or Unsafe")
	} //end if
	if(!StrEndsWith(mtplFile, MTPL_FILE_EXTENSION)) {
		return template, NewError("Sub-TPL File Path is Not MTPL")
	} //end if
	if(!PathIsFile(mtplFile)) {
		return template, NewError("TPL File Path does not exists")
	} //end if
	//--
	mtplDir := StrTrimWhitespaces(PathDirName(mtplFile))
	if(
		(mtplDir == "") ||
		(PathIsEmptyOrRoot(mtplDir) == true) ||
		(PathIsSafeValidPath(mtplDir) != true) ||
		(PathIsBackwardUnsafe(mtplDir) == true) ||
		(PathIsAbsolute(mtplDir) == true)) {
		return template, NewError("Sub-TPL Dir Path is Empty or Unsafe")
	} //end if
	if(!PathIsDir(mtplDir)) {
		return template, NewError("Sub-TPL Dir Path is Not a Dir")
	} //end if
	//--
	if((template == "") || (!StrContains(template, "[@@@SUB-TEMPLATE:")) || (!StrContains(template, "@@@]"))) {
		return template, NewError("Sub-TPL Syntax Not Found")
	} //end if
	//--
	if((arrSTPLs == nil) || (len(arrSTPLs) <= 0)) {
		return template, NewError("Sub-TPL Map List is Empty")
	} //end if
	//--
	for key, val := range arrSTPLs {
		key = StrTrimWhitespaces(key)
		val = StrTrimWhitespaces(val)
		if(key == "") {
			return template, NewError("Sub-TPL Map Key is Empty")
		} //end if
		if(val == "") {
			return template, NewError("Sub-TPL Map Val is Empty for Key: `" + key + "`")
		} //end if
		if(StrContains(template, key)) { // if does not contain is not an error, maybe already replaced at a previous cycle if duplicate ...
			//--
			arrVal := ExplodeWithLimit("|", val, 2) // allow just one level escaping: |xyz
			//--
			var stplFName string = StrTrimWhitespaces(arrVal[0])
			if(stplFName == "") {
				return template, NewError("Sub-TPL File Value Name is Empty for Key: `" + key + "`")
			} //end if
			//--
			var stplEscape string = ""
			if(len(arrVal) > 1) {
				stplEscape = StrTrimWhitespaces(arrVal[1])
				if(stplEscape != "") {
					stplEscape = "|" + stplEscape
				} //end if
			} //end if
			//--
			stplFContent, stplErr := readTPLFile(PathAddDirLastSlash(mtplDir) +  stplFName)
			if(stplErr != nil) {
				return template, NewError("Sub-TPL Read SubTemplate ERR for Key: `" + key + "` # " + stplErr.Error())
			} //end if
			switch(stplEscape) {
				//--
				case "": // no process
					break
				//--
				case "|tpl-trim":
					stplFContent = StrTrimWhitespaces(stplFContent)
					break
				case "|tpl-uri-encode":
					stplFContent = RawUrlEncode(stplFContent)
					break
				case "|tpl-b64-encode":
					stplFContent = Base64Encode(stplFContent)
					break
				//--
				case "|plain": 		// plain only TPL: all syntax inside will be escaped
					stplFContent = MarkersTplPrepareNosyntaxContent(stplFContent) // disable all syntax
					break
				case "|html": 		// plain only TPL: all syntax inside will be escaped ; intended only to display a tpl in html context, will preserve the syntax as escaped html
					stplFContent = EscapeHtml(stplFContent) // escape html before prepare nosyntax
					stplFContent = MarkersTplPrepareNosyntaxHtml(stplFContent, true) // escape also placeholders, mark as being main tpl
					break
				case "|js": 		// plain only TPL: all syntax inside will be escaped ; intended only to display a tpl in js context, will preserve the syntax as escaped html
					stplFContent = MarkersTplPrepareNosyntaxHtml(stplFContent, true) // escape also placeholders, mark as being main tpl
					stplFContent = EscapeJs(stplFContent) // escape js after prepare nosyntax
					break
				//--
				default:
					return template, NewError("Sub-TPL Escape Value is Unsupported for Key: `" + key + "` ; Escape: `" + stplEscape + "`")
				//--
			} //end switch
			if(stplFContent == "") {
				return template, NewError("Sub-TPL Read SubTemplate ERR: Empty content after escaping for Key: `" + key + "`")
			} //end if
			//--
			template = StrReplaceAll(template, key, stplFContent)
			if(StrTrimWhitespaces(template) == "") {
				return template, NewError("Sub-TPL Read SubTemplate ERR: Empty content after processing for Key: `" + key + "`")
			} //end if
			//--
		} //end if
	} //end for
	//--
	return template, nil
	//--
} //END FUNCTION


func markersTplProcessIfSyntax(template string, arrobj map[string]string) string {
	//--
	defer PanicHandler()
	//--
	if(template == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return ""
	} //end if
	//-- process if (conditionals)
	var rExp string = `(?s)\[%%%IF\:([a-zA-Z0-9_\-\.]+?)\:(@\=\=|@\!\=|@\<\=|@\<|@\>\=|@\>|\=\=|\!\=|\<\=|\<|\>\=|\>|\!%|%|\!\?|\?|\^~|\^\*|&~|&\*|\$~|\$\*)([^\[\]]*?);((\([0-9]+\))??)%%%\](.*?)??(\[%%%ELSE\:\1\4%%%\](.*?)??)??\[%%%\/IF\:\1\4%%%\]` // {{{SYNC-TPL-EXPR-IF}}} ; {{{SYNC-TPL-EXPR-IF-IN-LOOP}}}
	matches, errRx := StrRegex2FindAllMatches("PERL", rExp, template, 0, 0)
	if(errRx != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Regex Failed", errRx)
		return template
	} //end if
	for c := 0; c < len(matches); c++ {
		//--
		g := matches[c]
		//--
		if(len(g) != 9) { // expects 9 regex groups
			//--
			log.Println("[WARNING]", CurrentFunctionName(), "Regex Group Size Error, Expected is # 9 but having #", len(g))
			return template
			//--
		} else {
			//--
			var tmp_ifs_cond_block string 		= g[0] 				// the whole conditional block [%%%IF:VARNAME:==xyz;%%%] .. ([%%%ELSE:VARNAME%%%] ..) [%%%/IF:VARNAME%%%]
			var tmp_ifs_part_if string			= g[6] 				// the part between IF and ELSE ; or the part between IF and /IF in the case that ELSE is missing
			var tmp_ifs_part_else string		= g[8] 				// the part between ELSE and /IF
		//	var tmp_ifs_tag_if string			= "" 				// [%%%IF:VARNAME:==xyz;%%%]
		//	var tmp_ifs_tag_else string			= "" 				// [%%%ELSE:VARNAME%%%]
		//	var tmp_ifs_tag_endif string 		= "" 				// [%%%/IF:VARNAME%%%]
			var tmp_ifs_var_if string 			= g[1] 				// the 'VARNAME' part of IF
			var tmp_ifs_var_else string 		= tmp_ifs_var_if 	// the 'VARNAME' part of ELSE
			var tmp_ifs_var_endif string 		= tmp_ifs_var_if 	// the 'VARNAME' part of \IF
			var tmp_ifs_operation string 		= g[2] 				// the IF operation ; at the moment just '==' or '!=' are supported
			var tmp_ifs_value string 			= g[3] 				// the IF value to compare the VARNAME with
			//--
	//		log.Println("[DEBUG]", CurrentFunctionName(), "---------- : `" + tmp_ifs_cond_block + "`")
	//	//	log.Println("[DEBUG]", CurrentFunctionName(), "[IF] : `" + tmp_ifs_tag_if + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[IF] VAR : `" + tmp_ifs_var_if + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[IF] OPERATION : `" + tmp_ifs_operation + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[IF] VALUE : `" + tmp_ifs_value + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[IF] PART : `" + tmp_ifs_part_if + "`")
	//	//	log.Println("[DEBUG]", CurrentFunctionName(), "[ELSE] : `" + tmp_ifs_tag_else + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[ELSE] VAR : `" + tmp_ifs_var_else + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[ELSE] PART : `" + tmp_ifs_part_else + "`")
	//	//	log.Println("[DEBUG]", CurrentFunctionName(), "[/IF] : `" + tmp_ifs_tag_endif + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[/IF] VAR : `" + tmp_ifs_var_endif + "`")
			//--
			var isConditionalBlockERR string = ""
			//-- check the conditional block: should not be empty
			if(isConditionalBlockERR == "") {
				if((StrTrimWhitespaces(tmp_ifs_cond_block) == "") || (StrStartsWith(tmp_ifs_cond_block, "[%%%IF:") != true)) {
					isConditionalBlockERR = "Conditional IF/(ELSE)/IF block is empty or invalid"
				} //end if
			} //end if
			//-- check if tag: should not be empty ; DISABLED, it is wrong !
		//	if(isConditionalBlockERR == "") {
		//		if(StrTrimWhitespaces(tmp_ifs_tag_if) == "") {
		//			isConditionalBlockERR = "IF tag is empty"
		//		} //end if
		//	} //end if
			//-- check /if tag: should not be empty ; DISABLED, it is wrong !
		//	if(isConditionalBlockERR == "") {
		//		if(StrTrimWhitespaces(tmp_ifs_tag_endif) == "") {
		//			isConditionalBlockERR = "/IF tag is empty"
		//		} //end if
		//	} //end if
			//-- check if var: should not be empty
			if(isConditionalBlockERR == "") {
				if(StrTrimWhitespaces(tmp_ifs_var_if) == "") {
					isConditionalBlockERR = "IF var name is empty"
				} //end if
			} //end if
			//-- check if var: should match a particular regex ; DISABLED, it is wrong !
		//	if(isConditionalBlockERR == "") {
		//		if(!StrRegexMatch(regexIfVarName, tmp_ifs_var_if)) {
		//			isConditionalBlockERR = "IF var name is invalid: `" + tmp_ifs_var_if + "`"
		//		} //end if
		//	} //end if
			//-- check if var vs. endif var: should be the same
			if(isConditionalBlockERR == "") {
				if(tmp_ifs_var_if != tmp_ifs_var_endif) {
					isConditionalBlockERR = "IF var `" + tmp_ifs_var_if + "` name does not match /IF var name `" + tmp_ifs_var_endif + "`"
				} //end if
			} //end if
			//-- check if var vs. else var (just in the case that else tag exists): should be the same, in the given case only
			if(isConditionalBlockERR == "") {
			//	if(tmp_ifs_tag_else != "") { // else tag is missing
					if(tmp_ifs_var_if != tmp_ifs_var_else) {
						isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` does not match ELSE var name `" + tmp_ifs_var_else + "`"
					} //end if
			//	} //end if
			} //end if
			//-- check if operation
			if(isConditionalBlockERR == "") {
				if(
					(tmp_ifs_operation != "==") &&
					(tmp_ifs_operation != "!=") &&
					(tmp_ifs_operation != "<=") &&
					(tmp_ifs_operation != "<") &&
					(tmp_ifs_operation != ">=") &&
					(tmp_ifs_operation != ">") &&
					(tmp_ifs_operation != "%") &&
					(tmp_ifs_operation != "!%") &&
					(tmp_ifs_operation != "?") &&
					(tmp_ifs_operation != "!?") &&
					(tmp_ifs_operation != "^~") &&
					(tmp_ifs_operation != "^*") &&
					(tmp_ifs_operation != "&~") &&
					(tmp_ifs_operation != "&*") &&
					(tmp_ifs_operation != "$~") &&
					(tmp_ifs_operation != "$*")) { // {{{SYNC-MTPL-IFS-OPERATIONS}}}
					isConditionalBlockERR = "IF operation is invalid: `" + tmp_ifs_operation + "`"
				} //end if
			} //end if
			//-- get the value and exists from arrobj by if var name as key
			var theIfVar string = tmp_ifs_var_if
			var theIfSubVar string = ""
			var theIfSubSubVar string = ""
			var isOkIfVar bool = true
			var varDotParts []string = nil
			if(StrContains(tmp_ifs_var_if, ".") == true) {
				varDotParts = ExplodeWithLimit(".", theIfVar, 4)
				if(len(varDotParts) > 3) { // currently support only max 2 sub-levels as VAR.SUBKEY.SUBSUBKEY ; {{{SYNC-GO-TPL-SUBKEY-LEVELS-IF}}}
					isOkIfVar = false
				} else {
					theIfVar = varDotParts[0] // first key is supposed to be always UPPER CASE, leave as it is ...
					if(len(varDotParts) > 1) {
						theIfSubVar = varDotParts[1] // leave keys as they are, CASE SENSITIVE, can be upper or lower or camer case {{{SYNC-GO-TPL-LOWER-UPPER-CAMELCASE-KEYS}}} ; the Markers syntax also uses like this
						if(len(varDotParts) > 2) {
							theIfSubSubVar = varDotParts[2] // leave keys as they are, CASE SENSITIVE, can be upper or lower or camer case {{{SYNC-GO-TPL-LOWER-UPPER-CAMELCASE-KEYS}}} ; the Markers syntax also uses like this
						} //end if
					} //end if
				} //end if
			} //end if
			if(isOkIfVar != true) {
				if(isConditionalBlockERR == "") {
					isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` is invalid: contains #" + ConvertIntToStr(len(varDotParts)) + " dot.parts"
				} //end if
			} //end if else
			//--
			if(isConditionalBlockERR == "") {
				//--
			//	iKeyValue, iKeyExists := arrobj[theIfVar]
				var iKeyValue string = ""
				var iKeyExists bool = false
				iKeyExists = ArrMapKeyExists(theIfVar, arrobj)
				//--
				if(!iKeyExists) {
					isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` is invalid: does not exists"
				} else {
					iKeyValue = arrobj[theIfVar]
				} //end if
				//--
				if(isConditionalBlockERR == "") {
					//--
					if(theIfSubVar != "") {
						iKeyValue = StrTrimWhitespaces(iKeyValue)
						if((iKeyValue != "") && (StrStartsWith(iKeyValue, "{") || StrStartsWith(iKeyValue, "["))) { // {{{SYNC-GO-TPL-JSON-STARTS}}}
						//	log.Println("[DEBUG]", CurrentFunctionName(), "iKeyValue @ 0", iKeyValue)
							jsonDat, jsonErr := JsonGetValueByKeysPath(iKeyValue) // get fastjson root, no keys
							iKeyValue = "" // reset
							if(jsonErr != nil) {
								if(isConditionalBlockERR == "") {
									isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` JSON Parse Error: `" + jsonErr.Error() + "`"
								} //end if
							} else if(jsonDat == nil) {
								if(isConditionalBlockERR == "") {
									isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` Parsed JSON is NULL"
								} //end if
							} else {
								if(jsonDat.Exists(theIfSubVar)) {
									if(theIfSubSubVar != "") {
										iKeyValue = jsonDat.GetScalarAsString(theIfSubVar, theIfSubSubVar)
									//	log.Println("[DEBUG]", CurrentFunctionName(), "iKeyValue @ 2", theIfSubVar, theIfSubSubVar, iKeyValue)
									} else {
										iKeyValue = jsonDat.GetScalarAsString(theIfSubVar)
									//	log.Println("[DEBUG]", CurrentFunctionName(), "iKeyValue @ 1", theIfSubVar, iKeyValue)
									} //end if else
								} else {
									if(isConditionalBlockERR == "") {
										isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` JSON Key does not exists: `" + theIfSubVar + "`"
									} //end if
								} //end if
							} //end if
						} else {
							iKeyValue = "" // reset
						} //end if else
					} //end if
					//--
					var theConditionalResult = ""
					//-- fix ###var###
					//origIfsValue := tmp_ifs_value
					if(StrStartsWith(tmp_ifs_value, "###") && StrEndsWith(tmp_ifs_value, "###")) { // compare with a comparison marker (from a variable) instead of static value
						realIfVar := StrTrim(tmp_ifs_value, "#")
						if((realIfVar != "") && ArrMapKeyExists(realIfVar, arrobj)) {
							tmp_ifs_value = arrobj[realIfVar]
						} //end if
					} //end if
					//log.Println("[DEBUG]", CurrentFunctionName(), "IF variable: `" + tmp_ifs_var_if + "` ; IF value [`" + origIfsValue + "`]:`" + tmp_ifs_value + "` ; Required value: `" + iKeyValue + "`")
					//-- strings or numbers (compare all as strings)
					if(tmp_ifs_operation == "==") {
						if(iKeyValue == tmp_ifs_value) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if else
					} else if(tmp_ifs_operation == "!=") {
						if(iKeyValue != tmp_ifs_value) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if else
					//-- numbers
					} else if(tmp_ifs_operation == "<=") {
						if(ParseStrAsFloat64(iKeyValue) <= ParseStrAsFloat64(tmp_ifs_value)) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if else
					} else if(tmp_ifs_operation == "<") {
						if(ParseStrAsFloat64(iKeyValue) < ParseStrAsFloat64(tmp_ifs_value)) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if else
					} else if(tmp_ifs_operation == ">=") {
						if(ParseStrAsFloat64(iKeyValue) >= ParseStrAsFloat64(tmp_ifs_value)) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if else
					} else if(tmp_ifs_operation == ">") {
						if(ParseStrAsFloat64(iKeyValue) > ParseStrAsFloat64(tmp_ifs_value)) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if else
					} else if(tmp_ifs_operation == "%") { // modulo (true/false)
						if((ParseStrAsInt64(iKeyValue) % ParseStrAsInt64(tmp_ifs_value)) == 0) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if else
					} else if(tmp_ifs_operation == "!%") { // not modulo (false/true)
						if((ParseStrAsInt64(iKeyValue) % ParseStrAsInt64(tmp_ifs_value)) != 0) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if else
					//-- string lists
					} else if(tmp_ifs_operation == "?") { // in list (elements separed by |)
						tmpArr := Explode("|", tmp_ifs_value)
						if(InListArr(iKeyValue, tmpArr) == true) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					} else if(tmp_ifs_operation == "!?") { // not in list (elements separed by |)
						tmpArr := Explode("|", tmp_ifs_value)
						if(InListArr(iKeyValue, tmpArr) == false) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					//-- strings
					} else if(tmp_ifs_operation == "^~") { // if variable starts with part, case sensitive
						if(StrStartsWith(iKeyValue, tmp_ifs_value) == true) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					} else if(tmp_ifs_operation == "^*") { // if variable starts with part, case insensitive
						if(StrIStartsWith(iKeyValue, tmp_ifs_value) == true) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					} else if(tmp_ifs_operation == "&~") { // if variable contains part, case sensitive
						if(StrContains(iKeyValue, tmp_ifs_value) == true) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					} else if(tmp_ifs_operation == "&*") { // if variable contains part, case insensitive
						if(StrIContains(iKeyValue, tmp_ifs_value) == true) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					} else if(tmp_ifs_operation == "$~") { // if variable ends with part, case sensitive
						if(StrEndsWith(iKeyValue, tmp_ifs_value) == true) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					} else if(tmp_ifs_operation == "$*") { // if variable ends with part, case insensitive
						if(StrIEndsWith(iKeyValue, tmp_ifs_value) == true) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					//-- arrays: NOT Implemented ... yet ...
				//	} else if(tmp_ifs_operation == "@==") { // array count ==
				//	} else if(tmp_ifs_operation == "@!=") { // array count !=
				//	} else if(tmp_ifs_operation == "@<=") { // array count <=
				//	} else if(tmp_ifs_operation == "@<") { // array count <
				//	} else if(tmp_ifs_operation == "@>=") { // array count >=
				//	} else if(tmp_ifs_operation == "@>") { // array count >
					//--
					} else { // ERR
						isConditionalBlockERR = "IF operation mismatch: `" + tmp_ifs_operation + "`"
					} //end if else
					//--
					theConditionalResult = StrTrim(theConditionalResult, SPECIAL_TRIM) // special trim ; {{{SYNC-TPL-FIX-TRIM-PARTS}}}
					//--
					if(theConditionalResult != "") {
						if(StrContains(theConditionalResult, "[%%%IF:") == true) {
							theConditionalResult = markersTplProcessIfSyntax(theConditionalResult, arrobj)
						} //end if
					} //end if
					//--
					if(isConditionalBlockERR == "") {
						template = StrReplaceWithLimit(template, tmp_ifs_cond_block, theConditionalResult, 1) // MUST REPLACE ONLY THE FIRST OCCURENCE
					} //end if
					//--
				} //end if
				//--
			} //end if
			//--
			if(isConditionalBlockERR != "") {
				log.Println("[WARNING]", CurrentFunctionName(), ": {### Invalid Conditional #" + ConvertIntToStr(c) + ": [" + isConditionalBlockERR + "] for Block `" + tmp_ifs_cond_block + "`" + " ###}")
			} //end if
			//--
		} //end if
		//--
	} //end for
	//--
	return template
	//--
} //END FUNCTION


func markersTplProcessMarkerSyntax(template string, arrobj map[string]string, context string) string {
	//--
	defer PanicHandler() // regex compile
	//--
	if(template == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return ""
	} //end if
	//-- trim context if any
	context = StrTrimWhitespaces(context) // do not make context uppercase, leave as is, is case-sensitive ; this can affect level 1 ...
	//-- process markers
	var mKeyValue string = ""
	var mKeyExists bool = false
	//--
	regexMarkers, errRx := regexp.Compile(`\[\#\#\#([a-zA-Z0-9_\-\.]+)((\|[a-z0-9]+)*)\#\#\#\]`) // {{{SYNC-REGEX-MARKER-TEMPLATES}}} ; allow lowercase in golang, they can be json keys ; regex markers as in Javascript + lowercase
	if((errRx != nil) || (regexMarkers == nil)) {
		log.Println("[WARNING]", CurrentFunctionName(), "Regex Failed", errRx)
		return template
	} //end if
	//--
	for i, match := range regexMarkers.FindAllStringSubmatch(template, -1) {
		//--
		var tmp_marker_val string			= "" 				// just initialize
		var tmp_marker_id  string			= string(match[0]) 	// [###THE-MARKER|escapings...###]
		var tmp_marker_key string			= string(match[1]) 	// THE-MARKER
		var tmp_marker_esc string			= string(match[2]) 	// |escaping1(|escaping2...|escaping99)
		//--
		if(context != "") {
			if(StrContains(tmp_marker_key, ".") == true) {
				if(StrStartsWith(tmp_marker_key, context + ".")) {
					tmp_marker_key = StrReplaceWithLimit(tmp_marker_key, context + ".", "", 1)
					tmp_marker_key = StrTrimWhitespaces(tmp_marker_key) // leave keys as they are, CASE SENSITIVE, can be upper or lower or camer case {{{SYNC-GO-TPL-LOWER-UPPER-CAMELCASE-KEYS}}} ; the If syntax also uses like this
				} //end if
			} //end if
		} //end if
		if(StrContains(tmp_marker_key, ".") == true) {
			var varDotParts []string = nil
			varDotParts = ExplodeWithLimit(".", tmp_marker_key, 3) // marker supports only 2 levels ; only IF supports 3 levels
			if((len(varDotParts) <= 0) || (len(varDotParts) > 2)) { // currently support only max 1 sub-level as VAR.SUBKEY ; {{{SYNC-GO-TPL-SUBKEY-LEVELS}}}
				tmp_marker_key = "" // skip ; too many levels
			} else {
			//	log.Println("[DEBUG]", CurrentFunctionName(), "Arr Type Key", tmp_marker_key, varDotParts)
				var theDotFirstPart string = StrTrimWhitespaces(varDotParts[0])
				if(theDotFirstPart != "") {
					mKeyValue, mKeyExists = arrobj[theDotFirstPart]
					mKeyValue = StrTrimWhitespaces(mKeyValue)
					//-- handle here only associative arrays, for one level ; non-associative arrays can be handled only inside a loop
					if((mKeyExists == true) && (mKeyValue != "") && (StrStartsWith(mKeyValue, "{") == true)) { // || ((StrStartsWith(mKeyValue, "{") == true) || (StrStartsWith(mKeyValue, "[") == true)) { // {{{SYNC-GO-TPL-JSON-STARTS}}}
						if(StrStartsWith(mKeyValue, "{") == true) { // associative array ; {{{SYNC-GO-TPL-JSON-STARTS}}}
							var arrA map[string]string
							dataReaderA := strings.NewReader(mKeyValue)
							decoderA := json.NewDecoder(dataReaderA)
							errA := decoderA.Decode(&arrA)
							if(errA == nil) {
								//	log.Println("[DEBUG]", CurrentFunctionName(), "arrA", arrA)
								if(arrA != nil) {
									template = markersTplProcessMarkerSyntax(template, arrA, theDotFirstPart)
								} else { // can be null, is valid json if no error ...
									log.Println("[WARNING]", CurrentFunctionName(), "JSON Parse is Null on key `" + tmp_marker_key + "`")
									tmp_marker_key = "" // skip ; cannot map, to arrA type, is null
								} //end if
							} else {
								log.Println("[WARNING]", CurrentFunctionName(), "JSON Parse Error on key `" + tmp_marker_key + "`", errA)
								tmp_marker_key = "" // skip ; cannot map, to arrA type, have errors
							} //end if else
							arrA = nil // free mem
						} //end if
					} //end if
					//--
				} else {
					tmp_marker_key = "" // skip ; invalid
				} //end if else
				theDotFirstPart = "" // free mem
			} //end if else
			varDotParts = nil // free mem
		} //end if
		//--
		mKeyValue = ""
		mKeyExists = false
		if(tmp_marker_key != "") {
			mKeyValue, mKeyExists = arrobj[tmp_marker_key]
		} //end if
		//log.Println("[DEBUG]", CurrentFunctionName(), "Context:", context, "Key:", tmp_marker_key, "Exists:", mKeyExists)
		//--
		if(mKeyExists == true) {
			//--
			tmp_marker_val = MarkersTplPrepareNosyntaxContent(mKeyValue)
			//--
			if((tmp_marker_id != "") && (tmp_marker_key != "")) {
				//--
			//	log.Println("[DEBUG]", CurrentFunctionName(), ": ---------- : " + tmp_marker_val)
			//	log.Println("[DEBUG]", CurrentFunctionName(), ": tmp_marker_id  + " # found Marker at index: " + ConvertIntToStr(i))
			//	log.Println("[DEBUG]", CurrentFunctionName(), ": tmp_marker_key + " # found Marker Key at index:", ConvertIntToStr(i))
			//	log.Println("[DEBUG]", CurrentFunctionName(), ": tmp_marker_esc + " # found Marker Escaping at index:", ConvertIntToStr(i))
				//--
				if(tmp_marker_esc != "") {
					//--
					var tmp_marker_arr_esc []string	= Explode("|", tmp_marker_esc) // just initialize
					//--
					for j, tmp_marker_each_esc := range tmp_marker_arr_esc {
						//--
						if(tmp_marker_each_esc != "") {
							//--
							var escaping string = "|" + tmp_marker_each_esc
							//--
						//	log.Println("[DEBUG]", CurrentFunctionName(), ": escaping + " # found Marker Escaping [Arr] at index: " + ConvertIntToStr(i) + "." + ConvertIntToStr(j))
							//--
							if(escaping == "|bool") { // Boolean
								tmp_marker_val = ParseBoolStrAsStdBoolStr(tmp_marker_val)
							} else if(escaping == "|int") { // Integer
								tmp_marker_val = ConvertInt64ToStr(ParseStrAsInt64(tmp_marker_val))
							} else if(escaping == "|dec1") { // Decimals: 1
								tmp_marker_val = ParseFloatStrAsDecimalStr(tmp_marker_val, 1)
							} else if(escaping == "|dec2") { // Decimals: 2
								tmp_marker_val = ParseFloatStrAsDecimalStr(tmp_marker_val, 2)
							} else if(escaping == "|dec3") { // Decimals: 3
								tmp_marker_val = ParseFloatStrAsDecimalStr(tmp_marker_val, 3)
							} else if(escaping == "|dec4") { // Decimals: 4
								tmp_marker_val = ParseFloatStrAsDecimalStr(tmp_marker_val, 4)
							} else if(escaping == "|num") { // Number (Float / Decimal / Integer)
								tmp_marker_val = ParseStrAsFloat64StrFixedPrecision(tmp_marker_val)
							//--
							} else if(escaping == "|date") { // Expects Unix Epoch Time to format as YYYY-MM-DD
								tmp_marker_val = DateNoTimeFromUnixTimeLocal(ParseStrAsInt64(tmp_marker_val))
							} else if(escaping == "|datetime") { // Expects Unix Epoch Time to format as YYYY-MM-DD HH:II:SS
								tmp_marker_val = DateIsoFromUnixTimeLocal(ParseStrAsInt64(tmp_marker_val))
							} else if(escaping == "|datetimez") { // Expects Unix Epoch Time to format as YYYY-MM-DD HH:II:SS +0000
								tmp_marker_val = DateFromUnixTimeLocal(ParseStrAsInt64(tmp_marker_val))
							//--
							} else if(escaping == "|url") { // escape URL
								tmp_marker_val = EscapeUrl(tmp_marker_val)
							} else if((escaping == "|json") || (escaping == "|jsonpretty")) { // format as Json Data ; expects pure JSON !!!
								jsonObj, jsonErrObj := JsonObjDecode(tmp_marker_val)
								if((jsonErrObj != nil) || (jsonObj == nil)) {
									tmp_marker_val = "null"
								} else {
									var jsonPretty bool = false
									if(escaping == "|jsonpretty") {
										jsonPretty = true
									} //end if
									tmp_marker_val = StrTrimWhitespaces(JsonNoErrChkEncode(jsonObj, jsonPretty, true)) // json HTMLSafe
									if(tmp_marker_val == "") {
										tmp_marker_val = "null"
									} //end if
								} //end if else
								jsonObj = nil
							} else if(escaping == "|js") { // Escape JS
								tmp_marker_val = EscapeJs(tmp_marker_val)
							} else if(escaping == "|html") { // Escape HTML
								tmp_marker_val = EscapeHtml(tmp_marker_val)
							} else if(escaping == "|xml") { // Escape XML (default)
								tmp_marker_val = EscapeXml(tmp_marker_val, false)
							} else if(escaping == "|exml") { // Escape XML (extra)
								tmp_marker_val = EscapeXml(tmp_marker_val, true)
							} else if(escaping == "|css") { // Escape CSS
								tmp_marker_val = EscapeCss(tmp_marker_val)
							} else if(escaping == "|nl2br") { // Format NL2BR
								tmp_marker_val = Nl2Br(tmp_marker_val)
							} else if(escaping == "|nbsp") { // Transform Spaces and Tabs to nbsp;
								tmp_marker_val = StrReplaceAll(tmp_marker_val, " ", "&nbsp;")
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\t", "&nbsp;")
							} else if(escaping == "|striptags") { // Apply Strip Tags
								tmp_marker_val = HTMLCodeStripTags(tmp_marker_val)
							} else if(escaping == "|emptye") { // if empty, display [EMPTY]
								if(StrTrimWhitespaces(tmp_marker_val) == "") {
									tmp_marker_val = "[EMPTY]"
								} //end if
							} else if(escaping == "|emptyna") { // if empty, display [N/A]
								if(StrTrimWhitespaces(tmp_marker_val) == "") {
									tmp_marker_val = "[N/A]"
								} //end if
							} else if(escaping == "|idtxt") { // id_txt: Id-Txt
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, "_", "-", -1) // replace all
								tmp_marker_val = StrUcWords(tmp_marker_val)
							} else if(escaping == "|slug") { // Slug: a-zA-Z0-9_- / - / -- : -
								tmp_marker_val = StrCreateSlug(tmp_marker_val)
							} else if(escaping == "|htmid") { // HTML-ID: a-zA-Z0-9_-
								tmp_marker_val = StrCreateHtmId(tmp_marker_val)
							} else if(escaping == "|jsvar") { // JS-Variable: a-zA-Z0-9_$
								tmp_marker_val = StrCreateJsVarName(tmp_marker_val)
							} else if(escaping == "|stdvar") { // Standard Variable: a-zA-Z0-9_
								tmp_marker_val = StrCreateStdVarName(tmp_marker_val)
								if(StrTrimWhitespaces(tmp_marker_val) == "") {
									tmp_marker_val = UNDEF_VAR_NAME
								} //end if
							} else if(escaping == "|normspaces") { // normalize spaces
								tmp_marker_val = StrNormalizeSpaces(tmp_marker_val)
							} else if(escaping == "|nospaces") { // no spaces
								tmp_marker_val = StrTrimWhitespaces(StrReplaceAll(StrNormalizeSpaces(tmp_marker_val), " ", ""))
							} else if(escaping == "|nobackslash") { // remove backslashes from a string
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\", "")
							} else if(escaping == "|rxpattern") { // prepare a regex escaped pattern for a browser input ; the following characters need to be not escaped in a browser pattern sequence, but in PHP they are, in a regex pattern
								// the `-` and `/` must remain escaped
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\.", ".")
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\:", ":")
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\#", "#")
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\=", "=")
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\!", "!")
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\<", "<")
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\>", ">")
							//--
							} else if((StrSubstr(escaping, 0, 7) == "|substr") || (StrSubstr(escaping, 0, 7) == "|subtxt")) { // Sub(String|Text) (0,num)
								xstrnum := StrTrimWhitespaces(StrSubstr(escaping, 7, 0))
								xnum := int(ParseStrAsInt64(xstrnum))
								if(xnum < 1) {
									xnum = 1
								} else if(xnum > 65535) {
									xnum = 65535
								} //end if else
								if(xnum >= 1 && xnum <= 65535) {
									if(len(tmp_marker_val) > xnum) {
										if(StrSubstr(escaping, 0, 7) == "|subtxt") {
											tmp_marker_val = TextCutByLimit(tmp_marker_val, xnum)
										} else { // '|substr'
											tmp_marker_val = StrMBSubstr(tmp_marker_val, 0, xnum)
										} //end if
									} //end if else
								} //end if
								xstrnum = ""
								xnum = 0
							//--
							} else if(escaping == "|lower") { // apply lowercase
								tmp_marker_val = StrToLower(tmp_marker_val)
							} else if(escaping == "|upper") { // apply uppercase
								tmp_marker_val = StrToUpper(tmp_marker_val)
							} else if(escaping == "|ucfirst") { // apply uppercase first character
								tmp_marker_val = StrUcFirst(tmp_marker_val)
							} else if(escaping == "|ucwords") { // apply uppercase on each word
								tmp_marker_val = StrUcWords(tmp_marker_val)
							} else if(escaping == "|trim") { // apply trim
								tmp_marker_val = StrTrimWhitespaces(tmp_marker_val)
							} else if(escaping == "|rev") { // reverse string
								tmp_marker_val = StrRev(tmp_marker_val)
							//--
							} else if(escaping == "|smartlist") { // Apply SmartList Fix Replacements ; {{{SYNC-SMARTLIST-BRACKET-REPLACEMENTS}}}
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, "<", "‹", -1) // replace all
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, ">", "›", -1) // replace all
							} else if(escaping == "|syntaxhtml") { // fix back markers tpl escapings in html
								tmp_marker_val = MarkersTplPrepareNosyntaxHtml(tmp_marker_val, false)
							//--
							} else if(escaping == "|hexi10") { // Converts a 64-bit positive integer number to hex (string)
								tmp_marker_val = UInt64ToHex(ParseStrAsUInt64(tmp_marker_val))
							} else if(escaping == "|hex") { // Apply Bin2Hex Encode
								tmp_marker_val = Bin2Hex(tmp_marker_val)
							//--
							} else if(escaping == "|b64tob64s") { // Convert from Base64 Encoding to Base64 Safe URL Encoding
								tmp_marker_val = Base64ToBase64s(tmp_marker_val)
							} else if(escaping == "|b64stob64") { // Convert from Base64 Safe URL Encoding to Base64 Encoding
								tmp_marker_val = Base64sToBase64(tmp_marker_val)
							//--
							} else if(escaping == "|b64") { // Apply Base64 Encode
								tmp_marker_val = BaseEncode([]byte(tmp_marker_val), "b64")
							} else if(escaping == "|b64s") { // Apply Base64 Encode
								tmp_marker_val = BaseEncode([]byte(tmp_marker_val), "b64s")
							//--
							} else if(escaping == "|b32") { // Apply Base32 Encode
								tmp_marker_val = BaseEncode([]byte(tmp_marker_val), "b32")
							} else if(escaping == "|b36") { // Apply Base36 Encode
								tmp_marker_val = BaseEncode([]byte(tmp_marker_val), "b36")
							} else if(escaping == "|b58") { // Apply Base58 Encode
								tmp_marker_val = BaseEncode([]byte(tmp_marker_val), "b58")
							} else if(escaping == "|b62") { // Apply Base62 Encode
								tmp_marker_val = BaseEncode([]byte(tmp_marker_val), "b62")
							} else if(escaping == "|b85") { // Apply Base85 Encode
								tmp_marker_val = BaseEncode([]byte(tmp_marker_val), "b85")
							} else if(escaping == "|b92") { // Apply Base92 Encode
								tmp_marker_val = BaseEncode([]byte(tmp_marker_val), "b92")
							//--
							} else if(escaping == "|crc32b") { // Apply Crc32b/B16 (default) Hashing
								tmp_marker_val = Crc32b(tmp_marker_val)
							} else if(escaping == "|crc32b36") { // Apply Crc32b/B36 Hashing
								tmp_marker_val = Crc32bB36(tmp_marker_val)
							//--
							} else if(escaping == "|md5") { // Apply MD5 Hash, Hex
								tmp_marker_val = Md5(tmp_marker_val)
							} else if(escaping == "|md5b64") { // Apply MD5 Hash, Base64
								tmp_marker_val = Md5B64(tmp_marker_val)
							//--
							} else if(escaping == "|sha1") { // Apply SHA1 Hash, Hex
								tmp_marker_val = Sha1(tmp_marker_val)
							} else if(escaping == "|sha1b64") { // Apply SHA1 Hash, Base64
								tmp_marker_val = Sha1B64(tmp_marker_val)
							//--
							} else if(escaping == "|sha224") { // Apply SHA224 Hash, Hex
								tmp_marker_val = Sha224(tmp_marker_val)
							} else if(escaping == "|sha224b64") { // Apply SHA224 Hash, Base64
								tmp_marker_val = Sha224B64(tmp_marker_val)
							//--
							} else if(escaping == "|sha256") { // Apply SHA256 Hash, Hex
								tmp_marker_val = Sha256(tmp_marker_val)
							} else if(escaping == "|sha256b64") { // Apply SHA256 Hash, Base64
								tmp_marker_val = Sha256B64(tmp_marker_val)
							//--
							} else if(escaping == "|sha384") { // Apply SHA384 Hash, Hex
								tmp_marker_val = Sha384(tmp_marker_val)
							} else if(escaping == "|sha384b64") { // Apply SHA384 Hash, Base64
								tmp_marker_val = Sha384B64(tmp_marker_val)
							//--
							} else if(escaping == "|sha512") { // Apply SHA512 Hash, Hex
								tmp_marker_val = Sha512(tmp_marker_val)
							} else if(escaping == "|sha512b64") { // Apply SHA512 Hash, Base64
								tmp_marker_val = Sha512B64(tmp_marker_val)
							//--
							} else if(escaping == "|sh3a224") { // Apply SHA3-224 Hash, Hex
								tmp_marker_val = Sh3a224(tmp_marker_val)
							} else if(escaping == "|sh3a224b64") { // Apply SHA3-224 Hash, Base64
								tmp_marker_val = Sh3a224B64(tmp_marker_val)
							//--
							} else if(escaping == "|sh3a256") { // Apply SHA3-256 Hash, Hex
								tmp_marker_val = Sh3a256(tmp_marker_val)
							} else if(escaping == "|sh3a256b64") { // Apply SHA3-256 Hash, Base64
								tmp_marker_val = Sh3a256B64(tmp_marker_val)
							//--
							} else if(escaping == "|sh3a384") { // Apply SHA3-384 Hash, Hex
								tmp_marker_val = Sh3a384(tmp_marker_val)
							} else if(escaping == "|sh3a384b64") { // Apply SHA3-384 Hash, Base64
								tmp_marker_val = Sh3a384B64(tmp_marker_val)
							//--
							} else if(escaping == "|sh3a512") { // Apply SHA3-512 Hash, Hex
								tmp_marker_val = Sh3a512(tmp_marker_val)
							} else if(escaping == "|sh3a512b64") { // Apply SHA3-512 Hash, Base64
								tmp_marker_val = Sh3a512B64(tmp_marker_val)
							//--
							} else if(escaping == "|prettybytes") { // Display Pretty Bytes
								tmp_marker_val = PrettyPrintBytes(ParseStrAsUInt64(tmp_marker_val))
							} else {
								log.Println("[WARNING]", CurrentFunctionName(), ": {### Invalid or Undefined Escaping " + escaping + " [" + ConvertIntToStr(j) + "]" + " for Marker `" + tmp_marker_key + "` " + "[" + ConvertIntToStr(i) + "]: " + " - detected in Replacement Key: " + tmp_marker_id + " ###}")
							} //end if
							//--
						} //end if
						//--
					} //end for
					//--
				} //end if
				//--
				template = StrReplaceWithLimit(template, tmp_marker_id, tmp_marker_val, -1) // replace all (testing also for replace with limit -1 !)
				//--
			} //end if
			//--
		} //end if
		//--
	} //end for
	//--
	return template
	//--
} //END FUNCTION


func markersTplProcessLoopSyntax(template string, arrobj map[string]string) string {
	//--
	defer PanicHandler()
	//--
	if(template == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "TPL is Empty")
		return ""
	} //end if
	//-- process loop (conditionals)
//	var rExp string = `(?s)\[%%%LOOP\:([a-zA-Z0-9_\-\.]+?)((\([0-9]+?\))??%)%%\](.*?)??\[%%%\/LOOP\:\1\2%%\]` // {{{SYNC-TPL-EXPR-LOOP}}}
	var rExp string = `(?s)\[%%%LOOP\:([a-zA-Z0-9_\-\.]+?)((\([0-9]+?\))??%)%%\](.*?)??\[%%%\/LOOP\:\1\2%%\]\n?` // {{{SYNC-TPL-EXPR-LOOP}}} ; {{{SYNC-TPL-FIX-TRIM-PARTS}}}
	matches, errRx := StrRegex2FindAllMatches("PERL", rExp, template, 0, 0)
	if(errRx != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "Regex Failed", errRx)
		return template
	} //end if
	for c := 0; c < len(matches); c++ {
		//--
		g := matches[c]
		//--
		if(len(g) != 5) { // expects 5 regex groups
			//--
			log.Println("[WARNING]", CurrentFunctionName(), "Regex Group Size Error, Expected is # 5 but having #", len(g))
			return template
			//--
		} else {
			//--
			var part_orig string 	= g[0]
			var part_var string 	= g[1]
		//	var part_uniqid string 	= g[2] // not used ; ex: `%` or `(1)%` as starting uid
		//	var part_uniqix string 	= g[3] // not used ; ex: ``  or `(1)` as ending uid
			var part_loop string 	= g[4]
			//--
	//		log.Println("[DEBUG]", CurrentFunctionName(), "---------- : `" + part_orig + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[LOOP] VAR : `" + part_var + "`")
	//	//	log.Println("[DEBUG]", CurrentFunctionName(), "[LOOP] UNIQID : `" + part_uniqid + "`")
	//	//	log.Println("[DEBUG]", CurrentFunctionName(), "[LOOP] UNIQIX : `" + part_uniqix + "`")
	//		log.Println("[DEBUG]", CurrentFunctionName(), "[LOOP] LOOP : `" + part_loop + "`")
			//--
			if((part_orig != "") && (StrStartsWith(part_orig, "[%%%LOOP:") == true) && (StrContains(template, part_orig) == true)) { // check ; is possible that an identical loop to be present more than once, and if identical was replaced at a previous step ...
				//--
			//	log.Println("[DEBUG]", CurrentFunctionName(), "---- Processing ---- : `" + part_orig + "`")
				//--
				var isLoopBlockERR string = ""
				//--
				var isOkLoopVar bool = true
				var loopContext string = part_var
				if(StrContains(part_var, ".") == true) {
				//	var varDotParts []string = nil
				//	varDotParts = ExplodeWithLimit(".", part_var, 3) // loop supports only 2 levels ; only IF supports 3 levels
				//	if(len(varDotParts) > 2) { // currently support only max 1 sub-level as VAR.SUBKEY ; {{{SYNC-GO-TPL-SUBKEY-LEVELS}}}
						isOkLoopVar = false // invalid, can only handle 2 levels and if loops on 2nd cannot, is supposed to be string
				//	} else {
				//		loopContext = StrTrimWhitespaces(varDotParts[0])
				//	} //end if
				} //end if
				//--
				if(isOkLoopVar != true) {
					//--
					if(isLoopBlockERR == "") {
						isLoopBlockERR = "LOOP var name `" + part_var + "` is Invalid (too many levels): `" + part_var + "`"
					} //end if
					//--
				} else {
					//--
					mKeyValue, mKeyExists := arrobj[part_var]
					mKeyValue = StrTrimWhitespaces(mKeyValue)
					//--
					if((mKeyExists == true) && (mKeyValue != "") && (StrStartsWith(mKeyValue, "[") == true)) { // {{{SYNC-GO-TPL-JSON-STARTS}}} ; do not handle here values starting with "{", they are handled by process marker syntax directly in go ...
						//--
					//	log.Println("[DEBUG]", CurrentFunctionName(), "[LOOP] VAR EXISTS : `" + part_var + "`", mKeyExists, mKeyValue)
						//--
						var arrL []map[string]string
						dataReaderL := strings.NewReader(mKeyValue)
						decoderL := json.NewDecoder(dataReaderL)
						errL := decoderL.Decode(&arrL)
						//--
						if(errL != nil) {
							//--
							if(isLoopBlockERR == "") {
								isLoopBlockERR = "LOOP var name `" + part_var + "` JSON Parse Error: `" + errL.Error() + "`"
							} //end if
							//--
						} else if(arrL == nil) {
							//--
							template = StrReplaceAll(template, part_orig, "") // array contains no elements, perhaps an empty array as: []
							//--
						} else {
							//--
							var stpl string = ""
							//--
							var maxx int = len(arrL)
							for d := 0; d < maxx; d++ {
								//--
								var ttpl string = ""
								if(arrL[d] == nil) {
									arrL[d] = map[string]string{}
								} //end if
								//-- prepare loop internal vars for markers and/or ifs
								arrL[d]["_-ITERATOR-_"] = ConvertUInt64ToStr(uint64(d))
								arrL[d]["-_INDEX_-"]    = ConvertUInt64ToStr(uint64(d) + 1)
								arrL[d]["-_MAXSIZE_-"]  = ConvertUInt64ToStr(uint64(maxx))
								arrL[d]["_-MAXCOUNT-_"] = ConvertUInt64ToStr(uint64(maxx) - 1)
								//-- prepare loop internal vars for ifs, also add separate loop data to root to speedup accessing it without . (dot) context
								var arrJ map[string]string = map[string]string{
									loopContext: 		JsonNoErrChkEncode(arrL[d], false, false),
									"_-ITERATOR-_": 	arrL[d]["_-ITERATOR-_"],
									"-_INDEX_-": 		arrL[d]["-_INDEX_-"],
									"-_MAXSIZE_-": 		arrL[d]["-_MAXSIZE_-"],
									"_-MAXCOUNT-_": 	arrL[d]["_-MAXCOUNT-_"],
								}
								//--
							//	log.Println("[DEBUG]", CurrentFunctionName(), "loopContext", loopContext, arrJ)
								//--
							//	ttpl = part_loop
								ttpl = StrTrim(part_loop, SPECIAL_TRIM) // special trim ; {{{SYNC-TPL-FIX-TRIM-PARTS}}}
								ttpl = markersTplProcessIfSyntax(ttpl, arrJ)
								ttpl = markersTplProcessMarkerSyntax(ttpl, arrL[d], loopContext)
								//--
								stpl += ttpl // add each loop part
								//--
							} //end for
							//--
							template = StrReplaceAll(template, part_orig, stpl)
							//--
						} //end if else
						//--
					} //end if
					//--
				} //end if
				//--
				if(isLoopBlockERR != "") {
					log.Println("[WARNING]", CurrentFunctionName(), ": {### Invalid Conditional #" + ConvertIntToStr(c) + ": [" + isLoopBlockERR + "] for Block `" + part_orig + "`" + " ###}")
				} //end if
				//--
			} //end if
			//--
		} //end if
		//--
	} //end for
	//--
	return template
	//--
} //END FUNCTION


//-----


func readTPLFile(mtplFile string) (string, error) {
	//--
	defer PanicHandler()
	//--
	mtplFile = StrTrimWhitespaces(mtplFile)
	//--
	if(mtplFile == "") {
		return "", NewError("Empty TPL File Path")
	} //end if
	if(!StrEndsWith(mtplFile, MTPL_FILE_EXTENSION)) {
		return "", NewError("Invalid TPL File Extension")
	} //end if
	//--
	fileSize, errSize := SafePathFileGetSize(mtplFile, false)
	if(errSize != nil) {
		return "", errSize
	} //end if
	if(uint64(fileSize) > MAX_DOC_SIZE_TPL) {
		return "", NewError("TPL is OverSized")
	} //end if
	//--
	template, errRd := SafePathFileRead(mtplFile, false)
	if(errRd != nil) {
		return "", errRd
	} //end if
	if(template == "") {
		return "", NewError("TPL File is Unreadable or Empty")
	} //end if
	if(StrTrimWhitespaces(template) == "") {
		return "", NewError("TPL File is Empty or Contains just Spacing characters")
	} //end if
	//--
	return template, nil
	//--
} //END FUNCTION


//-----


// #END
