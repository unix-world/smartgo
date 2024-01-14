
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2024 unix-world.org
// r.20240114.2007 :: STABLE
// [ TPL (MARKER-TPL TEMPLATING) ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	"regexp"
	"strings"
	"encoding/json"

	"github.com/unix-world/smartgo/data-structs/fastjson"
)

//-----

const (
	SPECIAL_TRIM string = "\n\r\x00\x0B"

	UNDEF_VAR_NAME string = "Undef____V_a_r"
)

//-----


func MarkersTplEscapeTpl(template string) string {
	//--
	return RawUrlEncode(template)
	//--
} //END FUNCTION


func MarkersTplEscapeSyntaxContent(tpl string, isMainHtml bool) string {
	//--
	if(tpl == "") {
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


func MarkersTplPrepareNosyntaxContent(tpl string) string {
	//--
	if(tpl == "") {
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "[###", "［###")
	tpl = StrReplaceAll(tpl, "###]", "###］")
	tpl = StrReplaceAll(tpl, "[%%%", "［%%%")
	tpl = StrReplaceAll(tpl, "%%%]", "%%%］")
	tpl = StrReplaceAll(tpl, "[@@@", "［@@@")
	tpl = StrReplaceAll(tpl, "@@@]", "@@@］")
	tpl = StrReplaceAll(tpl, "[:::", "［:::")
	tpl = StrReplaceAll(tpl, ":::]", ":::］")
	//--
	return tpl
	//--
} //END FUNCTION


func MarkersTplRevertNosyntaxContent(tpl string) string {
	//--
	if(tpl == "") {
		return ""
	} //end if
	//--
	tpl = StrReplaceAll(tpl, "［###", "[###")
	tpl = StrReplaceAll(tpl, "###］", "###]")
	tpl = StrReplaceAll(tpl, "［%%%", "[%%%")
	tpl = StrReplaceAll(tpl, "%%%］", "%%%]")
	tpl = StrReplaceAll(tpl, "［@@@", "[@@@")
	tpl = StrReplaceAll(tpl, "@@@］", "@@@]")
	tpl = StrReplaceAll(tpl, "［:::", "[:::")
	tpl = StrReplaceAll(tpl, ":::］", ":::]")
	//--
	return tpl
	//--
} //END FUNCTION


func MarkersTplPrepareNosyntaxHtml(tpl string, isMainHtml bool) string {
	//--
	if(tpl == "") {
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


func PlaceholdersTplRender(template string, arrpobj map[string]string, isEncoded bool, revertSyntax bool) string {
	//--
	defer PanicHandler() // url decode may panic
	//-- syntax: r.20231228
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
				if(StrRegexMatchString(regexPlaceholderVarName, k)) {
					template = StrReplaceAll(template, "[:::" + k + ":::]", v)
				} //end if
			} //end if
		} //end for
	} //end if
	//--
	return template
	//--
} //END FUNCTION


func markersTplProcessIfSyntax(template string, arrobj map[string]string) string {
	//--
	defer PanicHandler()
	//-- process if (conditionals)
	var rExp string = `(?s)\[%%%IF\:([a-zA-Z0-9_\-\.]+?)\:(@\=\=|@\!\=|@\<\=|@\<|@\>\=|@\>|\=\=|\!\=|\<\=|\<|\>\=|\>|\!%|%|\!\?|\?|\^~|\^\*|&~|&\*|\$~|\$\*)([^\[\]]*?);((\([0-9]+\))??)%%%\](.*?)??(\[%%%ELSE\:\1\4%%%\](.*?)??)??\[%%%\/IF\:\1\4%%%\]` // {{{SYNC-TPL-EXPR-IF}}} ; {{{SYNC-TPL-EXPR-IF-IN-LOOP}}}
	re, matches := StrRegex2FindAllStringMatches("PERL", rExp, template, 0, 0)
	for c := 0; c < len(matches); c++ {
		//--
		if m, e := re.FindStringMatch(matches[c]); m != nil && e == nil {
			//--
			g := m.Groups()
			//--
			var tmp_ifs_cond_block string 		= string(g[0].String()) 				// the whole conditional block [%%%IF:VARNAME:==xyz;%%%] .. ([%%%ELSE:VARNAME%%%] ..) [%%%/IF:VARNAME%%%]
			var tmp_ifs_part_if string			= string(g[6].String()) 				// the part between IF and ELSE ; or the part between IF and /IF in the case that ELSE is missing
			var tmp_ifs_part_else string		= string(g[8].String()) 				// the part between ELSE and /IF
		//	var tmp_ifs_tag_if string			= "" 									// [%%%IF:VARNAME:==xyz;%%%]
		//	var tmp_ifs_tag_else string			= "" 									// [%%%ELSE:VARNAME%%%]
		//	var tmp_ifs_tag_endif string 		= "" 									// [%%%/IF:VARNAME%%%]
			var tmp_ifs_var_if string 			= string(g[1].String()) 				// the 'VARNAME' part of IF
			var tmp_ifs_var_else string 		= tmp_ifs_var_if 						// the 'VARNAME' part of ELSE
			var tmp_ifs_var_endif string 		= tmp_ifs_var_if 						// the 'VARNAME' part of \IF
			var tmp_ifs_operation string 		= string(g[2].String()) 				// the IF operation ; at the moment just '==' or '!=' are supported
			var tmp_ifs_value string 			= string(g[3].String()) 				// the IF value to compare the VARNAME with
			//--
	//		log.Println("[DEBUG] ---------- : `" + tmp_ifs_cond_block + "`")
	//	//	log.Println("[DEBUG] [IF] : `" + tmp_ifs_tag_if + "`")
	//		log.Println("[DEBUG] [IF] VAR : `" + tmp_ifs_var_if + "`")
	//		log.Println("[DEBUG] [IF] OPERATION : `" + tmp_ifs_operation + "`")
	//		log.Println("[DEBUG] [IF] VALUE : `" + tmp_ifs_value + "`")
	//		log.Println("[DEBUG] [IF] PART : `" + tmp_ifs_part_if + "`")
	//	//	log.Println("[DEBUG] [ELSE] : `" + tmp_ifs_tag_else + "`")
	//		log.Println("[DEBUG] [ELSE] VAR : `" + tmp_ifs_var_else + "`")
	//		log.Println("[DEBUG] [ELSE] PART : `" + tmp_ifs_part_else + "`")
	//	//	log.Println("[DEBUG] [/IF] : `" + tmp_ifs_tag_endif + "`")
	//		log.Println("[DEBUG] [/IF] VAR : `" + tmp_ifs_var_endif + "`")
			//--
			var isConditionalBlockERR string = ""
			//-- check the conditional block: should not be empty
			if(isConditionalBlockERR == "") {
				if((StrTrimWhitespaces(tmp_ifs_cond_block) == "") || (StrPos(tmp_ifs_cond_block, "[%%%IF:") != 0)) {
					isConditionalBlockERR = "Conditional IF/(ELSE)/IF block is empty"
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
		//		if(!StrRegexMatchString(regexIfVarName, tmp_ifs_var_if)) {
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
							var p fastjson.Parser
							jsonDat, jsonErr := p.Parse(iKeyValue)
							iKeyValue = "" // reset
							if(jsonErr != nil) {
								if(isConditionalBlockERR == "") {
									isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` JSON Parse Error: `" + jsonErr.Error() + "`"
								} //end if
							} else {
								if(jsonDat.Exists(theIfSubVar)) {
									if(theIfSubSubVar != "") {
										iKeyValue = string(jsonDat.GetStringBytes(theIfSubVar, theIfSubSubVar)) // try as string
										if(iKeyValue == "") {
											iKeyValue = ConvertFloat64ToStr(jsonDat.GetFloat64(theIfSubVar, theIfSubSubVar)) // if could not get as string, try as float64 which covers also INT/INT64/UINT/UINT64
										} //end if
									} else {
										iKeyValue = string(jsonDat.GetStringBytes(theIfSubVar)) // try as string
										if(iKeyValue == "") {
											iKeyValue = ConvertFloat64ToStr(jsonDat.GetFloat64(theIfSubVar)) // if could not get as string, try as float64 which covers also INT/INT64/UINT/UINT64
										} //end if
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
					//	if(StrPos(iKeyValue, tmp_ifs_value) == 0) {
						if(StrStartsWith(iKeyValue, tmp_ifs_value) == true) {
							theConditionalResult = tmp_ifs_part_if
						} else {
							theConditionalResult = tmp_ifs_part_else
						} //end if
					} else if(tmp_ifs_operation == "^*") { // if variable starts with part, case insensitive
					//	if(StrIPos(iKeyValue, tmp_ifs_value) == 0) {
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
					theConditionalResult = StrTrim(theConditionalResult, SPECIAL_TRIM) // special trim
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
				log.Println("[WARNING] " + CurrentFunctionName() + ": {### Invalid Conditional #" + ConvertIntToStr(c) + ": [" + isConditionalBlockERR + "] for Block `" + tmp_ifs_cond_block + "`" + " ###}")
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
	defer PanicHandler()
	//-- trim context if any
	context = StrTrimWhitespaces(context) // do not make context uppercase, leave as is, is case-sensitive ; this can affect level 1 ...
	//-- process markers
	var mKeyValue string = ""
	var mKeyExists bool = false
	//--
	var regexMarkers = regexp.MustCompile(`\[\#\#\#([a-zA-Z0-9_\-\.]+)((\|[a-z0-9]+)*)\#\#\#\]`) // {{{SYNC-REGEX-MARKER-TEMPLATES}}} ; allow lowercase in golang, they can be json keys ; regex markers as in Javascript + lowercase
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
				if(StrStartsWith(tmp_marker_key, context)) {
					tmp_marker_key = StrReplaceWithLimit(tmp_marker_key, context, "", 1)
					tmp_marker_key = StrTrimLeft(tmp_marker_key, ".")
					tmp_marker_key = StrTrimWhitespaces(tmp_marker_key) // leave keys as they are, CASE SENSITIVE, can be upper or lower or camer case {{{SYNC-GO-TPL-LOWER-UPPER-CAMELCASE-KEYS}}} ; the If syntax also uses like this
				} //end if
			} //end if
		} //end if
		if(StrContains(tmp_marker_key, ".") == true) {
			var varDotParts []string = nil
			varDotParts = ExplodeWithLimit(".", tmp_marker_key, 3) // marker supports only 2 levels ; only IF supports 3 levels
			if(len(varDotParts) > 2) { // currently support only max 1 sub-level as VAR.SUBKEY ; {{{SYNC-GO-TPL-SUBKEY-LEVELS}}}
				tmp_marker_key = "" // skip ; too many levels
			} else {
			//	log.Println("[DEBUG]", "Arr Type Key", tmp_marker_key, varDotParts)
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
							//	log.Println("[DEBUG]", "arrA", arrA)
								if(arrA != nil) {
									template = markersTplProcessMarkerSyntax(template, arrA, theDotFirstPart)
								} //end if
							} else {
								tmp_marker_key = "" // skip ; cannot map, to arrA type
							} //end if else
						} //end if
					} //end if
					//--
				} else {
					tmp_marker_key = "" // skip ; invalid
				} //end if else
			} //end if else
		} //end if
		//--
		mKeyValue = ""
		mKeyExists = false
		if(tmp_marker_key != "") {
			mKeyValue, mKeyExists = arrobj[tmp_marker_key]
		} //end if
		//--
		if(mKeyExists == true) {
			//--
			tmp_marker_val = MarkersTplPrepareNosyntaxContent(mKeyValue)
			//--
			if((tmp_marker_id != "") && (tmp_marker_key != "")) {
				//--
			//	log.Println("[DEBUG] " + CurrentFunctionName() + ": ---------- : " + tmp_marker_val)
			//	log.Println("[DEBUG] " + CurrentFunctionName() + ": tmp_marker_id  + " # found Marker at index: " + ConvertIntToStr(i))
			//	log.Println("[DEBUG] " + CurrentFunctionName() + ": tmp_marker_key + " # found Marker Key at index:", ConvertIntToStr(i))
			//	log.Println("[DEBUG] " + CurrentFunctionName() + ": tmp_marker_esc + " # found Marker Escaping at index:", ConvertIntToStr(i))
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
						//	log.Println("[DEBUG] " + CurrentFunctionName() + ": escaping + " # found Marker Escaping [Arr] at index: " + ConvertIntToStr(i) + "." + ConvertIntToStr(j))
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
						//	} else if(escaping == "|date") { // Expects Unix Epoch Time to format as YYYY-MM-DD
							// TODO
						//	} else if(escaping == "|datetime") { // Expects Unix Epoch Time to format as YYYY-MM-DD HH:II:SS
							// TODO
						//	} else if(escaping == "|datetimez") { // Expects Unix Epoch Time to format as YYYY-MM-DD HH:II:SS +0000
							// TODO
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
							} else if(escaping == "|xml") { // Escape XML
								tmp_marker_val = EscapeXml(tmp_marker_val)
							} else if(escaping == "|css") { // Escape CSS
								tmp_marker_val = EscapeCss(tmp_marker_val)
							} else if(escaping == "|nl2br") { // Format NL2BR
								tmp_marker_val = StrNl2Br(tmp_marker_val)
							} else if(escaping == "|nbsp") { // Transform Spaces and Tabs to nbsp;
								tmp_marker_val = StrReplaceAll(tmp_marker_val, " ", "&nbsp;")
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\t", "&nbsp;")
						//	} else if(escaping == "|striptags") { // Apply Strip Tags
								// TODO # https://github.com/grokify/html-strip-tags-go/blob/master/strip.go
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
								tmp_marker_val = StrCreateJsVarName(tmp_marker_val)
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "$", "")
								tmp_marker_val = StrTrimWhitespaces(tmp_marker_val)
								if(tmp_marker_val == "") {
									tmp_marker_val = UNDEF_VAR_NAME
								} //end if
							} else if(escaping == "|normspaces") { // normalize spaces
								tmp_marker_val = StrNormalizeSpaces(tmp_marker_val)
							} else if(escaping == "|nospaces") { // no spaces
								tmp_marker_val = StrTrimWhitespaces(StrReplaceAll(StrNormalizeSpaces(tmp_marker_val), " ", ""))
							} else if(escaping == "|nobackslash") { // remove backslashes from a string
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\", "")
							} else if(escaping == "|rxpattern") { // prepare a regex escaped pattern for a browser input ; the following characters need tot to be escaped in a browser pattern sequence, but in PHP they are, in a regex pattern
								tmp_marker_val = StrReplaceAll(tmp_marker_val, "\\/", "/")
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
								tmp_marker_val = PrettyPrintBytes(ParseStrAsInt64(tmp_marker_val))
							} else {
								log.Println("[WARNING] " + CurrentFunctionName() + ": {### Invalid or Undefined Escaping " + escaping + " [" + ConvertIntToStr(j) + "]" + " for Marker `" + tmp_marker_key + "` " + "[" + ConvertIntToStr(i) + "]: " + " - detected in Replacement Key: " + tmp_marker_id + " ###}")
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
	//-- process loop (conditionals)
	var rExp string = `(?s)\[%%%LOOP\:([a-zA-Z0-9_\-\.]+?)((\([0-9]+?\))??%)%%\](.*?)??\[%%%\/LOOP\:\1\2%%\]` // {{{SYNC-TPL-EXPR-LOOP}}}
	re, matches := StrRegex2FindAllStringMatches("PERL", rExp, template, 0, 0)
	for c := 0; c < len(matches); c++ {
		//--
		if m, e := re.FindStringMatch(matches[c]); m != nil && e == nil {
			//--
			g := m.Groups()
			//--
			var part_orig string 	= string(g[0].String())
			var part_var string 	= string(g[1].String())
		//	var part_uniqid string 	= string(g[2].String()) // not used ; ex: `%` or `(1)%` as starting uid
		//	var part_uniqix string 	= string(g[3].String()) // not used ; ex: ``  or `(1)` as ending uid
			var part_loop string 	= string(g[4].String())
			//--
	//		log.Println("[DEBUG] ---------- : `" + part_orig + "`")
	//		log.Println("[DEBUG] [LOOP] VAR : `" + part_var + "`")
	//	//	log.Println("[DEBUG] [LOOP] UNIQID : `" + part_uniqid + "`")
	//	//	log.Println("[DEBUG] [LOOP] UNIQIX : `" + part_uniqix + "`")
	//		log.Println("[DEBUG] [LOOP] LOOP : `" + part_loop + "`")
			//--
			if((part_orig != "") && (StrPos(part_orig, "[%%%LOOP:") == 0) && (StrContains(template, part_orig) == true)) { // check ; is possible that an identical loop to be present more than once, and if identical was replaced at a previous step ...
				//--
			//	log.Println("[DEBUG] ---- Processing ---- : `" + part_orig + "`")
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
					//	log.Println("[DEBUG] [LOOP] VAR EXISTS : `" + part_var + "`", mKeyExists, mKeyValue)
						//--
						var arrL []map[string]string
						dataReaderL := strings.NewReader(mKeyValue)
						decoderL := json.NewDecoder(dataReaderL)
						errL := decoderL.Decode(&arrL)
						if(errL != nil) {
							if(isLoopBlockERR == "") {
								isLoopBlockERR = "LOOP var name `" + part_var + "` JSON Parse Error: `" + errL.Error() + "`"
							} //end if
						} else if(arrL == nil) {
							template = StrReplaceAll(template, part_orig, "") // array contains no elements, perhaps an empty array as: []
						} else {
							var stpl string = ""
							var maxx int = len(arrL)
							for d := 0; d < maxx; d++ {
								var ttpl string = ""
								var arrJ map[string]string = map[string]string{
									loopContext: 		JsonNoErrChkEncode(arrL[d], false, false),
									"_-ITERATOR-_": 	ConvertUInt64ToStr(uint64(d)),
									"-_INDEX_-": 		ConvertUInt64ToStr(uint64(d) + 1),
									"-_MAXSIZE_-": 		ConvertUInt64ToStr(uint64(maxx)),
									"_-MAXCOUNT-_": 	ConvertUInt64ToStr(uint64(maxx) - 1),
								}
							//	log.Println("[DEBUG]", "loopContext", loopContext, arrJ)
								ttpl = part_loop
								ttpl = markersTplProcessIfSyntax(ttpl, arrJ)
								ttpl = markersTplProcessMarkerSyntax(ttpl, arrL[d], loopContext)
								stpl += ttpl
							} //end for
							template = StrReplaceAll(template, part_orig, stpl)
						} //end if else
						//--
					} //end if
					//--
				} //end if
				//--
				if(isLoopBlockERR != "") {
					log.Println("[WARNING] " + CurrentFunctionName() + ": {### Invalid Conditional #" + ConvertIntToStr(c) + ": [" + isLoopBlockERR + "] for Block `" + part_orig + "`" + " ###}")
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



func MarkersTplRender(template string, arrobj map[string]string, isEncoded bool, revertSyntax bool, escapeRemainingSyntax bool, isMainHtml bool) string {
	//-- syntax: r.20231228
	defer PanicHandler() // url decode may panic
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
	//	log.Println("[NOTICE]", "Processing LOOP Syntax")
		template = markersTplProcessLoopSyntax(template, arrobj)
	} //end if
	//-- process if (conditionals) syntax
	if(StrContains(template, "[%%%IF:") == true) {
	//	log.Println("[NOTICE]", "Processing IF Syntax")
		template = markersTplProcessIfSyntax(template, arrobj)
	} //end if
	//-- process markers
	if(StrContains(template, "[###") == true) {
	//	log.Println("[NOTICE]", "Processing MARKER Syntax")
		template = markersTplProcessMarkerSyntax(template, arrobj, "")
	} //end if
	//-- replace specials: Square-Brackets(L/R) R N TAB SPACE
	if(StrContains(template, "[%%%|") == true) {
	//	log.Println("[NOTICE]", "Processing SPECIALS Syntax")
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
				log.Println("[WARNING] " + CurrentFunctionName() + ": {### Undefined Placeholders detected in Template ###}")
			} //end if
		} //end if
		if(StrContains(template, "[###") == true) {
			log.Println("[WARNING] " + CurrentFunctionName() + ": {### Undefined Markers detected in Template ###}")
		} //end if
		if(StrContains(template, "[%%%") == true) {
			log.Println("[WARNING] " + CurrentFunctionName() + ": {### Undefined Marker Syntax detected in Template ###}")
		} //end if
		if(StrContains(template, "[@@@") == true) {
			log.Println("[WARNING] " + CurrentFunctionName() + ": {### Undefined Marker Sub-Templates detected in Template ###}")
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


func RenderMainHtmlMarkersTpl(template string, arrobj map[string]string, arrpobj map[string]string) string {
	//--
	defer PanicHandler()
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
	defer PanicHandler()
	//--
	return MarkersTplRender(template, arrobj, false, false, true, false) // escape remaining syntax + is not main html
	//--
} //END FUNCTION


//-----


// #END
