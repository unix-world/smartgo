
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231124.2232 :: STABLE
// [ TPL (MARKERS-TPL) ]

// REQUIRE: go 1.17 or later
package smartgo

import (
	"log"

	"regexp"

	"github.com/unix-world/smartgo/base32"
	"github.com/unix-world/smartgo/base36"
	"github.com/unix-world/smartgo/base58"
	"github.com/unix-world/smartgo/base62"
	"github.com/unix-world/smartgo/base85"
	"github.com/unix-world/smartgo/base92"

	"github.com/unix-world/smartgo/fastjson"
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
	//-- syntax: r.20220331
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
	//-- process ifs (conditionals)
//	const regexIfVarChars string = `[a-zA-Z0-9_\-]+`
//	const regexIfVarName string = `^` + regexIfVarChars + `$`
//	var regexIfs = regexp.MustCompile(`(?s)(\[%%%IF\:(` + regexIfVarChars + `)\:(\=\=|\!\=){1}(.*?)(;%%%\]){1}){1}(.*?)((\[%%%ELSE\:(` + regexIfVarChars + `)%%%\])(.*?)){0,1}(\[%%%\/IF\:(` + regexIfVarChars + `)%%%\]){1}`) // Go lang have no backreferences in regex, thus it is too complex at the moment to process nested ifs, thus does not support also (0..9) terminators ; because there is no support for loops yet, dissalow "." in variable names ; also operations between different data type gets too much overhead ; thus keep is simple: no nested if syntax ; allow only (strings): == != ; {{{SYNC-MTPL-IFS-OPERATIONS}}}
//	for c, imatch := range regexIfs.FindAllStringSubmatch(template, -1) {
//		//--
//		var tmp_ifs_cond_block string 		= string(imatch[0]) 					// the whole conditional block [%%%IF:VARNAME:==xyz;%%%] .. ([%%%ELSE:VARNAME%%%] ..) [%%%/IF:VARNAME%%%]
//		var tmp_ifs_part_if string			= string(imatch[6]) 					// the part between IF and ELSE ; or the part between IF and /IF in the case that ELSE is missing
//		var tmp_ifs_part_else string		= string(imatch[10]) 					// the part between ELSE and /IF
//		var tmp_ifs_tag_if string			= string(imatch[1]) 					// [%%%IF:VARNAME:==xyz;%%%]
//		var tmp_ifs_tag_else string			= string(imatch[8]) 					// [%%%ELSE:VARNAME%%%]
//		var tmp_ifs_tag_endif string 		= string(imatch[11]) 					// [%%%/IF:VARNAME%%%]
//		var tmp_ifs_var_if string 			= string(imatch[2]) 					// the 'VARNAME' part of IF
//		var tmp_ifs_var_else string 		= string(imatch[9]) 					// the 'VARNAME' part of ELSE
//		var tmp_ifs_var_endif string 		= string(imatch[12]) 					// the 'VARNAME' part of \IF
//		var tmp_ifs_operation string 		= string(imatch[3]) 					// the IF operation ; at the moment just '==' or '!=' are supported
//		var tmp_ifs_value string 			= string(imatch[4]) 					// the IF value to compare the VARNAME with
		//--
	var rExp string = `(?s)\[%%%IF\:([a-zA-Z0-9_\-\.]+?)\:(@\=\=|@\!\=|@\<\=|@\<|@\>\=|@\>|\=\=|\!\=|\<\=|\<|\>\=|\>|\!%|%|\!\?|\?|\^~|\^\*|&~|&\*|\$~|\$\*)([^\[\]]*?);((\([0-9]+\))??)%%%\](.*?)??(\[%%%ELSE\:\1\4%%%\](.*?)??)??\[%%%\/IF\:\1\4%%%\]` // {{{SYNC-TPL-EXPR-IF}}} ; {{{SYNC-TPL-EXPR-IF-IN-LOOP}}}
	re, matches := StrRegex2FindAllStringMatches("PERL", rExp, template, 0, 0)
	for c := 0; c < len(matches); c++ {
		if m, e := re.FindStringMatch(matches[c]); m != nil && e == nil {
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
				if(StrTrimWhitespaces(tmp_ifs_cond_block) == "") {
					isConditionalBlockERR = "Conditional IF/(ELSE)/IF block is empty"
				} //end if
			} //end if
			//-- check if tag: should not be empty
		//	if(isConditionalBlockERR == "") {
		//		if(StrTrimWhitespaces(tmp_ifs_tag_if) == "") {
		//			isConditionalBlockERR = "IF tag is empty"
		//		} //end if
		//	} //end if
			//-- check /if tag: should not be empty
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
			//-- check if var: should match a particular regex
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
				if((tmp_ifs_operation != "==") && (tmp_ifs_operation != "!=") && (tmp_ifs_operation != "<=") && (tmp_ifs_operation != "<") && (tmp_ifs_operation != ">=") && (tmp_ifs_operation != ">")) { // {{{SYNC-MTPL-IFS-OPERATIONS}}}
					isConditionalBlockERR = "IF operation is invalid: `" + tmp_ifs_operation + "`"
				} //end if
			} //end if
			//-- get the value and exists from arrobj by if var name as key
			var theIfVar string = tmp_ifs_var_if
			var theIfSubVar string = ""
			var theIfSubSubVar string = ""
			var isOkIfVar bool = true
			var varDotParts []string = nil
			if(StrContains(tmp_ifs_var_if, ".")) {
				varDotParts = ExplodeWithLimit(".", theIfVar, 4)
				if(len(varDotParts) > 3) {
					isOkIfVar = false // currently support only max 2 sub-levels as VAR.SUBKEY.SUBSUBKEY
				} else {
					theIfVar = varDotParts[0]
					if(len(varDotParts) > 1) {
						theIfSubVar = varDotParts[1]
						if(len(varDotParts) > 2) {
							theIfSubSubVar = varDotParts[2]
						} //end if
					} //end if
				} //end if
			} //end if
			if(isOkIfVar != true) {
				if(isConditionalBlockERR == "") {
					isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` is invalid: contains #" + ConvertIntToStr(len(varDotParts)) + " dot.parts"
				} //end if
			} //end if
			iKeyValue, iKeyExists := arrobj[theIfVar]
			//--
			if(isConditionalBlockERR == "") {
				if(!iKeyExists) {
					isConditionalBlockERR = "IF var name `" + tmp_ifs_var_if + "` is invalid: does not exists"
				} //end if
			} //end if
			//--
			if(isConditionalBlockERR == "") {
				//--
				if(theIfSubVar != "") {
					iKeyValue = StrTrimWhitespaces(iKeyValue)
					if((iKeyValue != "") && (StrStartsWith(iKeyValue, "{") || StrStartsWith(iKeyValue, "["))) {
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
				//--
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
				} else { // ERR
					isConditionalBlockERR = "IF operation mismatch: `" + tmp_ifs_operation + "`"
				} //end if else
				//--
				theConditionalResult = StrTrim(theConditionalResult, "\n\r\x00\x0B") // special trim
				//--
				if(theConditionalResult != "") {
					if(StrContains(theConditionalResult, "[%%%IF:")) {
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
			if(isConditionalBlockERR != "") {
				log.Println("[WARNING] " + CurrentFunctionName() + ": {### Invalid Conditional #" + ConvertIntToStr(c) + ": [" + isConditionalBlockERR + "] for Block `" + tmp_ifs_cond_block + "`" + " ###}")
			} //end if
			//--
		} //end if
	} //end for
	//--
	return template
	//--
} //END FUNCTION


func markersTplProcessMarkerSyntax(template string, arrobj map[string]string) string {
	//-- process markers
	var regexMarkers = regexp.MustCompile(`\[\#\#\#([A-Z0-9_\-\.]+)((\|[a-z0-9]+)*)\#\#\#\]`) // regex markers as in Javascript {{{SYNC-REGEX-MARKER-TEMPLATES}}}
	for i, match := range regexMarkers.FindAllStringSubmatch(template, -1) {
		//--
		var tmp_marker_val string			= "" 									// just initialize
		var tmp_marker_id  string			= string(match[0]) 						// [###THE-MARKER|escapings...###]
		var tmp_marker_key string			= string(match[1]) 						// THE-MARKER
		var tmp_marker_esc string			= string(match[2]) 						// |escaping1(|escaping2...|escaping99)
		//--
		mKeyValue, mKeyExists := arrobj[tmp_marker_key]
		//--
		if(mKeyExists) {
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
							} else if(escaping == "|idtxt") { // id_txt: Id-Txt
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, "_", "-", -1) // replace all
								tmp_marker_val = StrUcWords(tmp_marker_val)
							} else if(escaping == "|slug") { // Slug: a-zA-Z0-9_- / - / -- : -
								tmp_marker_val = StrCreateSlug(tmp_marker_val)
							} else if(escaping == "|htmid") { // HTML-ID: a-zA-Z0-9_-
								tmp_marker_val = StrCreateHtmId(tmp_marker_val)
							} else if(escaping == "|jsvar") { // JS-Variable: a-zA-Z0-9_
								tmp_marker_val = StrCreateJsVarName(tmp_marker_val)
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
							} else if(escaping == "|url") { // escape URL
								tmp_marker_val = EscapeUrl(tmp_marker_val)
							} else if(escaping == "|json") { // format as Json Data ; expects pure JSON !!!
								jsonObj, jsonErrObj := JsonObjDecode(tmp_marker_val)
								if((jsonErrObj != nil) || (jsonObj == nil)) {
									tmp_marker_val = "null"
								} else {
									tmp_marker_val = StrTrimWhitespaces(JsonNoErrChkEncode(jsonObj, false, true)) // json HTMLSafe
									if(tmp_marker_val == "") {
										tmp_marker_val = "null"
									} //end if
								} //end if else
								jsonObj = nil
							} else if(escaping == "|js") { // Escape JS
								tmp_marker_val = EscapeJs(tmp_marker_val)
							} else if(escaping == "|html") { // Escape HTML
								tmp_marker_val = EscapeHtml(tmp_marker_val)
							} else if(escaping == "|css") { // Escape CSS
								tmp_marker_val = EscapeCss(tmp_marker_val)
							} else if(escaping == "|nl2br") { // Format NL2BR
								tmp_marker_val = StrNl2Br(tmp_marker_val)
							} else if(escaping == "|smartlist") { // Apply SmartList Fix Replacements ; {{{SYNC-SMARTLIST-BRACKET-REPLACEMENTS}}}
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, "<", "‹", -1) // replace all
								tmp_marker_val = StrReplaceWithLimit(tmp_marker_val, ">", "›", -1) // replace all
							} else if(escaping == "|syntaxhtml") { // fix back markers tpl escapings in html
								tmp_marker_val = MarkersTplPrepareNosyntaxHtml(tmp_marker_val, false)
							} else if(escaping == "|hex") { // Apply Bin2Hex Encode
								tmp_marker_val = Bin2Hex(tmp_marker_val)
							} else if(escaping == "|b64") { // Apply Base64 Encode
								tmp_marker_val = Base64Encode(tmp_marker_val)
							} else if(escaping == "|b64s") { // Apply Base64 Encode
								tmp_marker_val = Base64sEncode(tmp_marker_val)
							} else if(escaping == "|b32") { // Apply Base32 Encode
								tmp_marker_val = base32.Encode([]byte(tmp_marker_val))
							} else if(escaping == "|b36") { // Apply Base36 Encode
								tmp_marker_val = base36.Encode([]byte(tmp_marker_val))
							} else if(escaping == "|b58") { // Apply Base58 Encode
								tmp_marker_val = base58.Encode([]byte(tmp_marker_val))
							} else if(escaping == "|b62") { // Apply Base62 Encode
								tmp_marker_val = base62.Encode([]byte(tmp_marker_val))
							} else if(escaping == "|b85") { // Apply Base85 Encode
								tmp_marker_val = base85.Encode([]byte(tmp_marker_val))
							} else if(escaping == "|b92") { // Apply Base92 Encode
								tmp_marker_val = base92.Encode([]byte(tmp_marker_val))
							} else if(escaping == "|crc32") { // Create Crc32b Hash
								tmp_marker_val = Crc32b(tmp_marker_val)
							} else if(escaping == "|crc32e36") { // Create Crc32b Hash, Base36
								tmp_marker_val = Crc32bB36(tmp_marker_val)
							} else if(escaping == "|md5") { // Create MD5 Hash, Hex
								tmp_marker_val = Md5(tmp_marker_val)
							} else if(escaping == "|md5e64") { // Create MD5 Hash, Base64
								tmp_marker_val = Md5B64(tmp_marker_val)
							} else if(escaping == "|sha1") { // Create SHA1 Hash, Hex
								tmp_marker_val = Sha1(tmp_marker_val)
							} else if(escaping == "|sha1e64") { // Create SHA1 Hash, Base64
								tmp_marker_val = Sha1B64(tmp_marker_val)
							} else if(escaping == "|sha256") { // Create SHA256 Hash, Hex
								tmp_marker_val = Sha256(tmp_marker_val)
							} else if(escaping == "|sha256e64") { // Create SHA256 Hash, Base64
								tmp_marker_val = Sha256B64(tmp_marker_val)
							} else if(escaping == "|sha384") { // Create SHA384 Hash, Hex
								tmp_marker_val = Sha384(tmp_marker_val)
							} else if(escaping == "|sha384e64") { // Create SHA384 Hash, Base64
								tmp_marker_val = Sha384B64(tmp_marker_val)
							} else if(escaping == "|sha512") { // Create SHA512 Hash, Hex
								tmp_marker_val = Sha512(tmp_marker_val)
							} else if(escaping == "|sha512e64") { // Create SHA512 Hash, Base64
								tmp_marker_val = Sha512B64(tmp_marker_val)
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


func MarkersTplRender(template string, arrobj map[string]string, isEncoded bool, revertSyntax bool, escapeRemainingSyntax bool, isMainHtml bool) string {
	//-- syntax: r.20220331
	if(isEncoded == true) {
		template = RawUrlDecode(template)
	} //end if
	if(revertSyntax == true) {
		template = MarkersTplRevertNosyntaxContent(template)
	} //end if
	//-- trim whitespaces
	template = StrTrimWhitespaces(template)
	//-- replace out comments
	if((StrContains(template, "[%%%COMMENT%%%]")) && (StrContains(template, "[%%%/COMMENT%%%]"))) {
		template = StrRegexReplaceAll(`(?s)\s??\[%%%COMMENT%%%\](.*?)??\[%%%\/COMMENT%%%\]\s??`, template, "") // regex syntax as in PHP
	} //end if
	//-- process ifs (conditionals)
	if(StrContains(template, "[%%%IF:")) {
		template = markersTplProcessIfSyntax(template, arrobj)
	} //end if
	//-- process markers
	if(StrContains(template, "[###")) {
		template = markersTplProcessMarkerSyntax(template, arrobj)
	} //end if
	//-- replace specials: Square-Brackets(L/R) R N TAB SPACE
	if(StrContains(template, "[%%%|")) {
		template = StrReplaceAll(template, "[%%%|SB-L%%%]", "［")
		template = StrReplaceAll(template, "[%%%|SB-R%%%]", "］")
		template = StrReplaceAll(template, "[%%%|R%%%]",    "\r")
		template = StrReplaceAll(template, "[%%%|N%%%]",    "\n")
		template = StrReplaceAll(template, "[%%%|T%%%]",    "\t")
		template = StrReplaceAll(template, "[%%%|SPACE%%%]", " ")
	} //end if
	//--
	if(escapeRemainingSyntax == true) {
		//--
		if(isMainHtml == false) {
			if(StrContains(template, "[:::")) {
				log.Println("[WARNING] " + CurrentFunctionName() + ": {### Undefined Placeholders detected in Template ###}")
			} //end if
		} //end if
		if(StrContains(template, "[###")) {
			log.Println("[WARNING] " + CurrentFunctionName() + ": {### Undefined Markers detected in Template ###}")
		} //end if
		if(StrContains(template, "[%%%")) {
			log.Println("[WARNING] " + CurrentFunctionName() + ": {### Undefined Marker Syntax detected in Template ###}")
		} //end if
		if(StrContains(template, "[@@@")) {
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
	template = MarkersTplRender(template, arrobj, false, false, true, true) // escape remaining syntax + is main html
	//--
	template = PlaceholdersTplRender(template, arrpobj, false, false)
	//--
	return template
	//--
} //END FUNCTION


func RenderMarkersTpl(template string, arrobj map[string]string) string {
	//--
	return MarkersTplRender(template, arrobj, false, false, true, false) // escape remaining syntax + is not main html
	//--
} //END FUNCTION


//-----


// #END
