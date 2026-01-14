
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260114.2358 :: STABLE
// [ S-MARKDOWN ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"log"

	uid "github.com/unix-world/smartgo/crypto/uuid"
)

const(
	mkdwVersion string = "smart.markdown:parser@v.2.2.8-r.20251216"
)


//-----


func NewSMarkdown(sBreakEnabled bool, mediaExtraEnabled bool, sfiExtraEnabled bool, lazyLoadImgUnveil bool, lazyLoadImgDefault string, relativeUrlPrefix string) (*SMarkdownParser, error) {
	//--
	defer PanicHandler()
	//--
	if(!lazyLoadImgUnveil) {
		if(lazyLoadImgDefault != "") {
			return nil, NewError("Lazy Load Default Image can be used just when Lazy Load Unveil is Enabled")
		} //end if
	} //end if
	//--
	md := &SMarkdownParser{
		sBreakEnabled 		: sBreakEnabled,
		mediaExtraEnabled 	: mediaExtraEnabled,
		sfiExtraEnabled 	: sfiExtraEnabled,
		lazyLoadImgUnveil 	: lazyLoadImgUnveil,
		lazyLoadImgDefault 	: lazyLoadImgDefault,
		relativeUrlPrefix 	: relativeUrlPrefix,
	}
	//--
	return md, nil
	//--
} //END FUNCTION


//-----


type SMarkdownParser struct {
	//-- external: settings
	sBreakEnabled bool 			// if enabled will convert backslash \ into <br>
	mediaExtraEnabled bool 		// if enabled can use: Video, Audio
	sfiExtraEnabled bool 		// if enabled can use: SFI Iconic Font
	lazyLoadImgUnveil bool 		// if enabled, will use lazyload:unveil ; otherwise will use loading:lazy
	lazyLoadImgDefault string 	// just for lazyload:unveil ; if set can use a loader image ; SMART_MARKDOWN_LAZYLOAD_DEFAULT_IMG ; ex: "lib/framework/img/loading-bars.svg"
	relativeUrlPrefix string 	// relative url prefix ; ex: https://some.site/
	//-- internal: parsing helpers
	definitionData map[string]map[string]map[string]string
	documentParsed bool
	//-- #
}


//-----


//-- !!
// in Go, if a string is enclosed in `` no need to double escape \\, only it needs so, if the string is enclosed in ""
//--
// @see: UNSYNC !!! GoLang vs. PHP
//-- #


//-----


func (m *SMarkdownParser) Parse(mkdw string) string {
	//-- panic handler
	defer PanicHandler()
	//-- check: avoid parse twice
	if(m.documentParsed != false) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Re-using the markdown renderer instance is not supported ... use a new instance")
		return `<!-- Markdown parser re-used, skip parsing -->`
	} //end if
	//-- size control
	if(uint64(len(mkdw)) > SIZE_BYTES_16M) { // {{{SYNC-MARKDOWN-MAX-SIZE}}}
		return `<!-- Markdown is OverSized, skip parsing -->`
	} //end if
	if(StrTrimWhitespaces(mkdw) == "") { // DO NOT TRIM OUTSIDE, NEEDS TO PRESERVE SPACES !
		return `<!-- Markdown is Empty, skip parsing -->`
	} //end if
	//-- pre-fix charset, it is mandatory to be converted to UTF-8
	mkdw = StrToValidUTF8Fix(mkdw)
	//-- substitute special reserved character as html entity ; this character is reserved (completely dissalowed), will be used for processing purposes only
	mkdw = StrReplaceAll(mkdw, mkdwSpecialCharEntryMark, mkdwSpecialCharEntryRepl)
	mkdw = StrReplaceAll(mkdw, mkdwSpecialCharTableSepMark, mkdwSpecialCharTableSepRepl)
	mkdw = StrReplaceAll(mkdw, "\r\n", "\n") // standardize line breaks
	mkdw = StrReplaceAll(mkdw, "\r",   "\n") // standardize line breaks
	//-- remove surrounding line breaks
	mkdw = StrTrim(mkdw, "\n")
	//-- parse markdown
	var markup string = m.renderDocument(mkdw) // !!!!!!! MAXIMUM ATENTION WHAT CHARACTERS ARE REPLACED BEFORE THIS TO AVOID CHANGE THE CODE BLOCKS WHICH NEED TO BE PRESERVED AS THEY ARE !!!!!!!
	mkdw = "" // free mem
	//-- trim line breaks
	markup = StrTrim(markup, "\n")
	//-- prepare the HTML
	markup = m.prepareHTML(markup)
	//-- fix charset
	markup = StrToValidUTF8Fix(markup) // fix by unixman (in case that broken UTF-8 characters are detected just try to fix them to avoid break JSON)
	//-- Replace backslashes with the equivalent html entity
	markup = StrReplaceAll(markup, "\\", "&#092;")
	//--
	m.documentParsed = true
	//--
	if(StrContains(markup, mkdwSpecialCharEntryMark)) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Markdown Rendering Issues: The special placeholders markup has been found in the rendered code and should not be there ... some placeholder failed to be replaced perhaps ...")
	} //end if
	//--
	return markup
	//--
} //END FUNCTION


//-----


const (

	//-- extra, by unixman: attributes can optional start with a type prefix to know which attributes to assign to nested elements (ex: media in a link, or link in a table cell, or media in a link in a table cell)
	mkdwRegexHeadingAttribute string 	= `[\t ]*\{(H\:[\t ]*)((?:[\#\.@%][_a-zA-Z0-9,%\-\=\$\:;\!\/]+[\t ]*)+)\}`  // Header 					- optional, starts with {H:
	mkdwRegexMediaAttribute string 		= `[\t ]*\{(I\:[\t ]*)((?:[\#\.@%][_a-zA-Z0-9,%\-\=\$\:;\!\/]+[\t ]*)+)\}`  // Media 					- optional, starts with {I:
	mkdwRegexLinkAttribute string 		= `[\t ]*\{(L\:[\t ]*)((?:[\#\.@%][_a-zA-Z0-9,%\-\=\$\:;\!\/]+[\t ]*)+)\}`  // Links 					- optional, starts with {L:
	mkdwRegexTableCellAttribute string 	= `[\t ]*\{(T\:[\t ]*)((?:[\#\.@%][_a-zA-Z0-9,%\-\=\$\:;\!\/]+[\t ]*)+)\}`  // Table Cell Attributes 	- optional, starts with {T:
	mkdwRegexTableDefinition string 	= `[\t ]*(\{\!DEF\!\=([_A-Za-z0-9\.\-\#;]+)\})[\t ]*` 						// Table Definition 		- optional, first head cell only, starts with: {!DEF!=
	//--

	//--
	mkdwPatternLinkAndMedia string 		= `\!?\[(.*)\]\((.+)\)(\s?\{.+\})?` 	// general: links and/or media ; PATTERN_LINK_AND_MEDIA
	mkdwPatternLinkOnly string 			= `\[(.*)\]\((.+)\)` 					// specific: link only ; PATTERN_LINK_ONLY
	mkdwPatternMediaOnly string 		= `\!\[([^\]]+)\]\(([^\)]+)\)` 			// specific: media only ; PATTERN_MEDIA_ONLY
	//--
	mkdwPatternBlockQuoted string 		= `(?s)(\n[\>]+[^\n]*)+\n` 				// Compatibility Mode Quoted Block ; must use double \n to separe two blocks ; PATTERN_BLOCK_QUOTED
	//--
	mkdwPatternBlockCode string			= `(?s)\n[`+"`"+`]{3}[\t a-z0-9\-]{0,255}\n([^\n]*?\n)*?[`+"`"+`]{3}\n` 	// Fenced Code Blocks ; PATTERN_BLOCK_CODE
	mkdwPatternInlineCode string 		= `(?s)[`+"`"+`]{3}.*?[`+"`"+`]{3}` 										// Inline Code ; PATTERN_INLINE_CODE
	mkdwPatternBlockPre string 			= `(?s)\n[~]{3}\n([^\n]*?\n)*?[~]{3}\n` 									// Fenced Preformat Blocks ; PATTERN_BLOCK_PRE
	mkdwPatternBlockMPre string 		= `(?s)\n[~]{4}\n([^\n]*?\n)*?[~]{4}\n` 									// Fenced Preformat Blocks, Mono ; PATTERN_BLOCK_MPRE
	//--
	mkdwPatternListUL string 			= `^([\t ]*)[\*\-\+]{1}[\t ]+` 												// UL list ; PATTERN_LIST_UL
	mkdwPatternListOL string 			= `^([\t ]*)[0-9]+[\.\)]{1}[\t ]+` 											// OL List ; PATTERN_LIST_OL
	//--

	//--
	mkdwSpecialCharEntryMark string 	= "\u2042" 	// unicode character &#8258; (unicode): ⁂ "\u{2042}" ; SPECIAL_CHAR_ENTRY_MARK
	mkdwSpecialCharEntryRepl string 	= "&#8258;" // restore as html entity "&#8258;" ; SPECIAL_CHAR_ENTRY_REPL
	mkdwSpecialCharConvRepl string 		= "&#8273;" // the special char used by converter converted to entity ; (unicode) ⁑ : "\u2051" : "&#8273;" ; SPECIAL_CHAR_CONV_REPL
	//--
	mkdwSpecialCharTableSepMark string 	= "┆" 		// special character used for tables ; SPECIAL_CHAR_TBL_SEP_MARK
	mkdwSpecialCharTableSepRepl string 	= "&#9478;" // restore as html entity "&#9478;"  ; SPECIAL_CHAR_TBL_SEP_REPL
	//--

)


//-----


func (m *SMarkdownParser) mkdwHtmlEntitiesReplacements() map[string]string {
	//--
	return map[string]string{ // supported html entities (the most usual) ; HTML_ENTITIES_REPLACEMENTS
		"&BREAK;" 	: mkdwSpecialCharEntryMark + "/%/special/BREAK/"  + mkdwSpecialCharEntryMark + "%.%", // non-standard, uppercase, used for substitutions, will be converted back to <br>
		//-- html
		"&nbsp;" 	: mkdwSpecialCharEntryMark + "/%/special/nbsp/"   + mkdwSpecialCharEntryMark + "%.%", // non breakable space
		"&amp;" 	: mkdwSpecialCharEntryMark + "/%/special/amp/"    + mkdwSpecialCharEntryMark + "%.%", // & ampersand
		"&quot;" 	: mkdwSpecialCharEntryMark + "/%/special/quot/"   + mkdwSpecialCharEntryMark + "%.%", // " double quote
		"&apos;" 	: mkdwSpecialCharEntryMark + "/%/special/apos/"   + mkdwSpecialCharEntryMark + "%.%", // ' html5 apos
		"&#039;" 	: mkdwSpecialCharEntryMark + "/%/special/039/"    + mkdwSpecialCharEntryMark + "%.%", // ' html4 apos
		"&#39;" 	: mkdwSpecialCharEntryMark + "/%/special/39/"     + mkdwSpecialCharEntryMark + "%.%", // ' html4 apos, short version of the above
		"&lt;" 		: mkdwSpecialCharEntryMark + "/%/special/lt/"     + mkdwSpecialCharEntryMark + "%.%", // < used for blockquotes
		"&gt;" 		: mkdwSpecialCharEntryMark + "/%/special/gt/"     + mkdwSpecialCharEntryMark + "%.%", // > used for blockquotes
		//-- specials
		"&sol;" 	: mkdwSpecialCharEntryMark + "/%/special/sol/"    + mkdwSpecialCharEntryMark + "%.%", // / slash
		"&#047;" 	: mkdwSpecialCharEntryMark + "/%/special/047/"    + mkdwSpecialCharEntryMark + "%.%", // / slash, alternative, better supported
		"&#47;" 	: mkdwSpecialCharEntryMark + "/%/special/47/"     + mkdwSpecialCharEntryMark + "%.%", // / slash, short version of the above
		"&bsol;" 	: mkdwSpecialCharEntryMark + "/%/special/bsol/"   + mkdwSpecialCharEntryMark + "%.%", // \ backslash
		"&#092;" 	: mkdwSpecialCharEntryMark + "/%/special/092/"    + mkdwSpecialCharEntryMark + "%.%", // \ backslash, alternative, better supported
		"&#92;" 	: mkdwSpecialCharEntryMark + "/%/special/92/"     + mkdwSpecialCharEntryMark + "%.%", // \ backslash, short version of the above
		//-- syntax
		"&ast;" 	: mkdwSpecialCharEntryMark + "/%/special/ast/"    + mkdwSpecialCharEntryMark + "%.%", // * used for lists or bold
		"&equals;" 	: mkdwSpecialCharEntryMark + "/%/special/equals/" + mkdwSpecialCharEntryMark + "%.%", // = used for italic
		"&tilde;" 	: mkdwSpecialCharEntryMark + "/%/special/tilde/"  + mkdwSpecialCharEntryMark + "%.%", // ~ used for strike or paragraphs
		"&lowbar;" 	: mkdwSpecialCharEntryMark + "/%/special/lowbar/" + mkdwSpecialCharEntryMark + "%.%", // _ used for underline
		"&dash;" 	: mkdwSpecialCharEntryMark + "/%/special/dash/"   + mkdwSpecialCharEntryMark + "%.%", // - used for lists or deletions or table align
		"&plus;" 	: mkdwSpecialCharEntryMark + "/%/special/plus/"   + mkdwSpecialCharEntryMark + "%.%", // + used for lists or inserts
		"&excl;" 	: mkdwSpecialCharEntryMark + "/%/special/excl/"   + mkdwSpecialCharEntryMark + "%.%", // ! used for subscript or media
		"&quest;" 	: mkdwSpecialCharEntryMark + "/%/special/quest/"  + mkdwSpecialCharEntryMark + "%.%", // ? used for dt
		"&Hat;" 	: mkdwSpecialCharEntryMark + "/%/special/Hat/"    + mkdwSpecialCharEntryMark + "%.%", // ^ used for superscript
		"&comma;" 	: mkdwSpecialCharEntryMark + "/%/special/comma/"  + mkdwSpecialCharEntryMark + "%.%", // , used for inline quote
		"&dollar;" 	: mkdwSpecialCharEntryMark + "/%/special/dollar/" + mkdwSpecialCharEntryMark + "%.%", // $ // used for var
		"&grave;" 	: mkdwSpecialCharEntryMark + "/%/special/grave/"  + mkdwSpecialCharEntryMark + "%.%", // ` used for code or inline code or highlights
		"&colon;" 	: mkdwSpecialCharEntryMark + "/%/special/colon/"  + mkdwSpecialCharEntryMark + "%.%", // : used for divs or table align
		"&verbar;" 	: mkdwSpecialCharEntryMark + "/%/special/verbar/" + mkdwSpecialCharEntryMark + "%.%", // | used for tables
		"&num;" 	: mkdwSpecialCharEntryMark + "/%/special/num/"    + mkdwSpecialCharEntryMark + "%.%", // # used for headings h1..h6
		"&period;" 	: mkdwSpecialCharEntryMark + "/%/special/period/" + mkdwSpecialCharEntryMark + "%.%", // . used for numeric lists
		"&rpar;" 	: mkdwSpecialCharEntryMark + "/%/special/rpar/"   + mkdwSpecialCharEntryMark + "%.%", // ) used for numeric lists
		"&lpar;" 	: mkdwSpecialCharEntryMark + "/%/special/lpar/"   + mkdwSpecialCharEntryMark + "%.%", // (
		"&rbrack;" 	: mkdwSpecialCharEntryMark + "/%/special/rbrack/" + mkdwSpecialCharEntryMark + "%.%", // ] used for links or media
		"&lbrack;" 	: mkdwSpecialCharEntryMark + "/%/special/lbrack/" + mkdwSpecialCharEntryMark + "%.%", // [ used for links or media
		"&rbrace;" 	: mkdwSpecialCharEntryMark + "/%/special/rbrace/" + mkdwSpecialCharEntryMark + "%.%", // } used for attributes
		"&lbrace;" 	: mkdwSpecialCharEntryMark + "/%/special/lbrace/" + mkdwSpecialCharEntryMark + "%.%", // { used for attributes
		"&percnt;" 	: mkdwSpecialCharEntryMark + "/%/special/percnt/" + mkdwSpecialCharEntryMark + "%.%", // %
		//--
		"&ndash;" 	: mkdwSpecialCharEntryMark + "/%/special/ndash/"  + mkdwSpecialCharEntryMark + "%.%", // –
		"&mdash;" 	: mkdwSpecialCharEntryMark + "/%/special/mdash/"  + mkdwSpecialCharEntryMark + "%.%", // —
		"&horbar;" 	: mkdwSpecialCharEntryMark + "/%/special/horbar/" + mkdwSpecialCharEntryMark + "%.%", // ―
		//--
		"&commat;" 	: mkdwSpecialCharEntryMark + "/%/special/commat/" + mkdwSpecialCharEntryMark + "%.%", // @
		"&#064;" 	: mkdwSpecialCharEntryMark + "/%/special/064/"    + mkdwSpecialCharEntryMark + "%.%", // alternate @ ; this should be supported as numeric too because it may be a trick to write an email address to hide it from some robots
		"&#64;" 	: mkdwSpecialCharEntryMark + "/%/special/64/"     + mkdwSpecialCharEntryMark + "%.%", // alternative, short version of the above
		"&copy;" 	: mkdwSpecialCharEntryMark + "/%/special/copy/"   + mkdwSpecialCharEntryMark + "%.%", // (c)
		"&#169;" 	: mkdwSpecialCharEntryMark + "/%/special/169/"    + mkdwSpecialCharEntryMark + "%.%", // (c), alternative
		"&reg;" 	: mkdwSpecialCharEntryMark + "/%/special/reg/"    + mkdwSpecialCharEntryMark + "%.%", // (R)
		"&#174;" 	: mkdwSpecialCharEntryMark + "/%/special/174/"    + mkdwSpecialCharEntryMark + "%.%", // (R), alternative
		"&trade;" 	: mkdwSpecialCharEntryMark + "/%/special/trade/"  + mkdwSpecialCharEntryMark + "%.%", // (TM)
		"&middot;" 	: mkdwSpecialCharEntryMark + "/%/special/middot/" + mkdwSpecialCharEntryMark + "%.%", // &middot;
		"&nldr;" 	: mkdwSpecialCharEntryMark + "/%/special/nldr/"   + mkdwSpecialCharEntryMark + "%.%", // ‥
		"&hellip;" 	: mkdwSpecialCharEntryMark + "/%/special/hellip/" + mkdwSpecialCharEntryMark + "%.%", // …
		//--
		"&lsaquo;" 	: mkdwSpecialCharEntryMark + "/%/special/lsaquo/" + mkdwSpecialCharEntryMark + "%.%", // ‹
		"&rsaquo;" 	: mkdwSpecialCharEntryMark + "/%/special/rsaquo/" + mkdwSpecialCharEntryMark + "%.%", // ›
		"&laquo;" 	: mkdwSpecialCharEntryMark + "/%/special/laquo/"  + mkdwSpecialCharEntryMark + "%.%", // «
		"&raquo;" 	: mkdwSpecialCharEntryMark + "/%/special/raquo/"  + mkdwSpecialCharEntryMark + "%.%", // »
		"&ldquo;" 	: mkdwSpecialCharEntryMark + "/%/special/ldquo/"  + mkdwSpecialCharEntryMark + "%.%", // “
		"&rdquo;" 	: mkdwSpecialCharEntryMark + "/%/special/rdquo/"  + mkdwSpecialCharEntryMark + "%.%", // ”
		"&bdquo;" 	: mkdwSpecialCharEntryMark + "/%/special/bdquo/"  + mkdwSpecialCharEntryMark + "%.%", // „
		//--
		"&spades;" 	: mkdwSpecialCharEntryMark + "/%/special/spades/" + mkdwSpecialCharEntryMark + "%.%", // ♠
		"&clubs;" 	: mkdwSpecialCharEntryMark + "/%/special/clubs/"  + mkdwSpecialCharEntryMark + "%.%", // ♣
		"&hearts;" 	: mkdwSpecialCharEntryMark + "/%/special/hearts/" + mkdwSpecialCharEntryMark + "%.%", // ♥
		"&diams;" 	: mkdwSpecialCharEntryMark + "/%/special/diams/"  + mkdwSpecialCharEntryMark + "%.%", // ♦
		//--
		"&sung;" 	: mkdwSpecialCharEntryMark + "/%/special/sung/"   + mkdwSpecialCharEntryMark + "%.%", // ♪
		"&flat;" 	: mkdwSpecialCharEntryMark + "/%/special/flat/"   + mkdwSpecialCharEntryMark + "%.%", // ♭
		"&natur;" 	: mkdwSpecialCharEntryMark + "/%/special/natur/"  + mkdwSpecialCharEntryMark + "%.%", // ♮
		"&sharp;" 	: mkdwSpecialCharEntryMark + "/%/special/sharp/"  + mkdwSpecialCharEntryMark + "%.%", // ♯
		//--
		"&check;" 	: mkdwSpecialCharEntryMark + "/%/special/check/"  + mkdwSpecialCharEntryMark + "%.%", // ✓
		"&cross;" 	: mkdwSpecialCharEntryMark + "/%/special/cross/"  + mkdwSpecialCharEntryMark + "%.%", // ✗
		"&sext;" 	: mkdwSpecialCharEntryMark + "/%/special/sext/"   + mkdwSpecialCharEntryMark + "%.%", // ✶
		//-- {{{SYNC-SPECIAL-CHARACTER-MKDW-CONVERTER}}}
		mkdwSpecialCharConvRepl : mkdwSpecialCharEntryMark  + "/%/special/convmkdwsf/" + mkdwSpecialCharEntryMark + "%.%", // the special mark used by Html2Markdown convertor: ⁑
		//-- {{{SYNC-SPECIAL-CHARACTER-MKDW-PARSER}}}
		mkdwSpecialCharEntryRepl : mkdwSpecialCharEntryMark + "/%/special/specmkdwsf/" + mkdwSpecialCharEntryMark + "%.%", // the special mark itself: ⁂
		//-- {{{SYNC-SPECIAL-CHARACTER-MKDW-TABLE-SEP}}}
		mkdwSpecialCharTableSepRepl : mkdwSpecialCharEntryMark + "/%/special/tblsepmkdwsf/" + mkdwSpecialCharEntryMark + "%.%", // the special table separator mark ┆
		//--
	}
	//--
} //END FUNCTION


//-----


func (m *SMarkdownParser) prepareHTML(markup string) string {
	//--
	var infSBreaks string = "B:0"
	if(m.sBreakEnabled) {
		infSBreaks = "B:1"
	} //end if
	//--
	var infExtraMedia string = "M:0"
	if(m.mediaExtraEnabled) {
		infExtraMedia = "M:1"
	} //end if
	//--
	var infSfiEnabled string = "S:0"
	if(m.sfiExtraEnabled) {
		infSfiEnabled = "S:1"
	} //end if
	//--
	var infLazyUnveil string = "U:0"
	if(m.lazyLoadImgUnveil) {
		infLazyUnveil = "U:1"
	} //end if
	//--
	var infLazyImgDef string = "I:0"
	if(m.lazyLoadImgDefault != "") {
		infLazyImgDef = "I:1"
	} //end if
	//--
	var infRelativeUrlPrefx string = "R:0"
	if(m.relativeUrlPrefix != "") {
		infRelativeUrlPrefx = "R:1"
	} //end if
	//--
	var infDTime string = DateNowIsoUtc()
	infDTime = StrTr(infDTime, map[string]string{ // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
		"-" : "",
		":" : "",
		" " : "",
	})
	//--
	var infSign string = infSBreaks + " " + infExtraMedia + " " + infSfiEnabled + " " + infLazyUnveil + " " + infLazyImgDef + " " + infRelativeUrlPrefx + " " + "T:" + infDTime
	//--
	markup = StrReplaceAll(markup, "&BREAK;", `<br>`)
	//--
	return "\n" + `<!-- HTML/Markdown :: ( ` + EscapeHtml(infSign) + ` ) -->` + "\n" + `<div id="markdown-` + EscapeHtml(Crc32b(markup)) + `-` + EscapeHtml(uid.Uuid10Num()) + `" class="markdown">` + "\n" + markup + "\n" + `</div>` + "\n" + `<!-- # HTML/Markdown # ` + EscapeHtml(mkdwVersion) + ` -->` + "\n" // if parsed and contain HTML Tags, add div and comments
	//--
} //END FUNCTION


//-----


func (m *SMarkdownParser) regexFindMatch(mode string, rexp string, txt string) []string {
	//--
	defer PanicHandler()
	//--
	mode = StrToUpper(StrTrimWhitespaces(mode))
	//--
	var noMatches []string = []string{}
	//--
	if(txt == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "# Empty String", rexp, mode)
		return noMatches
	} //end if
	//--
	var matches []string
	var err error
	switch(mode) {
		case "GO":
			matches, err = StrRegexFindFirstMatch(rexp, txt)
			break
		case "RE2": fallthrough
		case "ECMA": fallthrough
		case "PERL":
			matches, err =StrRegex2FindFirstMatch(mode, rexp, txt, 0)
			break
		default:
			log.Println("[WARNING]", CurrentFunctionName(), "# Invalid Regex Mode:", mode, rexp)
			return noMatches
	} //end switch
	//--
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Regex [" + mode + "] Errors:", rexp, err)
		return noMatches
	} //end if
	if(matches == nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Regex [" + mode + "] Matches are Null", rexp)
		return noMatches
	} //end if
	//--
	return matches
	//--
} //END FUNCTION



func (m *SMarkdownParser) regexFindAllGroupZeroMatches(mode string, rexp string, txt string) []string {
	//--
	defer PanicHandler()
	//--
	mode = StrToUpper(StrTrimWhitespaces(mode))
	//--
	var noMatches []string = []string{}
	//--
	if(txt == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "# Empty String", rexp, mode)
		return noMatches
	} //end if
	//--
	var matches [][]string
	var err error
	switch(mode) {
		case "GO":
			matches, err = StrRegexFindAllMatches(rexp, txt, 0)
			break
		case "RE2": fallthrough
		case "ECMA": fallthrough
		case "PERL":
			matches, err = StrRegex2FindAllMatches(mode, rexp, txt, 0, 0)
			break
		default:
			log.Println("[WARNING]", CurrentFunctionName(), "# Invalid Regex Mode:", mode, rexp)
			return noMatches
	} //end switch
	//--
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Regex [" + mode + "] Errors:", rexp, err)
		return noMatches
	} //end if
	if(matches == nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Regex [" + mode + "] Matches are Null", rexp)
		return noMatches
	} //end if
	//--
	zeroMatches, errZero := m.extractAllRegexPregPatternOrderDataGroupZero(matches)
	if(errZero != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Conversion (Regex [" + mode + "]) Errors:", rexp, errZero)
		return noMatches
	} //end if
	if(zeroMatches == nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Conversion (Regex [" + mode + "]) Matches are Null", rexp)
		return noMatches
	} //end if
	//--
	return zeroMatches
	//--
} //END FUNCTION


func (m *SMarkdownParser) extractAllRegexPregPatternOrderDataGroupZero(matches [][]string) ([]string, error) {
	//--
	defer PanicHandler()
	//--
	// extracts data[0] from a Regex matches[][] as PREG_PATTERN_ORDER in PHP
	//--
	var noMatches []string = []string{}
	//--
	if(matches == nil) {
		return noMatches, NewError("Matches are Null")
	} //end if
	//--
	if(len(matches) <= 0) {
		return noMatches, nil // no error
	} //end if
	//--
	var foundMatches []string = []string{}
	var numMatches int = -1
	for i:=0; i<len(matches); i++ {
		if(numMatches >= 0) {
			if(len(matches[i]) != numMatches) {
				return noMatches, NewError("Matches have Length Variations") // all the matches should have the same number of elements
			} //end if
		} //end if
		numMatches = len(matches[i])
		if(numMatches < 1) {
			return noMatches, NewError("Matches are Invalid") // should be at least matches[0] for a valid regex pattern
		} //end if
		if(matches[i][0] == "") {
			return noMatches, NewError("Some of the Matches are Empty") // this cannot happen, a match should always contains a non-empty string from a real match result
		} //end if
		foundMatches = append(foundMatches, matches[i][0])
	} //end for
	//--
	return foundMatches, nil
	//--
} //END FUNCTION


//-----


func (m *SMarkdownParser) initDefinitionData(clear bool) bool {
	//--
	defer PanicHandler()
	//--
	if(clear == true) {
		m.definitionData = map[string]map[string]map[string]string{}
	} //end if
	//--
	if(m.definitionData == nil) {
		m.definitionData = map[string]map[string]map[string]string{}
	} //end if
	//--
	val, keyExists := m.definitionData["extracted"]
	if((keyExists != true) || (val == nil)) {
		m.definitionData["extracted"] = map[string]map[string]string{}
	} //end if
	//--
	return true
	//--
} //END FUNCTION


func (m *SMarkdownParser) fixEscapings(txt string) string { // this is an extra feature, inspired from turndown.js ; some character sequences cannot be used without being escaped in markdown ... revert them here (except the code which has a special revert only ...)
	//-- {{{SYNC-MKDW-EXTERNAL-CONVERT-ESCAPINGS}}}
	var escapingsReplacements map[string]string = map[string]string{ // ESCAPINGS_REPLACEMENTS
		`\_` 	 : `_`,
		`\*` 	 : `*`,
		`\-` 	 : `-`,
		`\+` 	 : `+`,
		`\=` 	 : `=`,
		`\`+"`"  : "`",
		`\~` 	 : `~`,
		`\!` 	 : `!`,
		`\?` 	 : `?`,
		`\#` 	 : `#`,
		`\$` 	 : `$`,
		`\@` 	 : `@`,
		`\%` 	 : `%`,
		`\^` 	 : `^`,
		`\(` 	 : `(`,
		`\)` 	 : `)`,
		`\[` 	 : `[`,
		`\]` 	 : `]`,
		`\{` 	 : `{`,
		`\}` 	 : `}`,
		`\.` 	 : `.`,
		`\,` 	 : `,`,
		`\:` 	 : `:`,
		`\;` 	 : `;`,
		`\<\<\<` : `<<<`, // do not replace just single < or > ; they may collide with html tags
	//	`\|` 	 : `|`, // {{{SYNC-FIX-ESCAPED-|-}}} ; this is done above by using a circular replacement (before vs after rendering ...)
	//	`\\` 	 : `\`, // replaced below because needs to be last in golang, there are no ordered maps
	}
	//--
	txt = StrTr(txt, escapingsReplacements) // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
	//-- interesting: in golang this have to be after the above replacements, not first :-))) ; also fixed in PHP ; the initial PHP version had this 1st but perhaps PHP internally does some tricks to keep logic order ?
	txt = StrReplaceAll(txt, `\\`, `\`) // golang have no ordered maps ; except this, below the order does not matter
	//--
	return txt
	//--
} //END FUNCTION


func (m *SMarkdownParser) escapeValidHtmlTagName(tag string) string { // escape and validate a html tag ; if invalid tag name will return 'invalid'
	//--
	defer PanicHandler()
	//--
	tag = StrToLower(StrTrimWhitespaces(tag))
	//--
	if((tag == "") || (!StrRegexMatch(`^[a-z]+`, tag)) || (!StrRegexMatch(`^[a-z0-9]+$`, tag))) { // must start with a-z ; can contain 0-9 (ex: h1..h6)
		tag = "invalidtag" // {{{SYNC-MKDW-HTML-TAG-INVALID}}}
	} //end if
	//--
	return tag
	//--
} //END FUNCTION


// some syntax as inline code and similar elements contained in links or media can't be rendered because some characters conflicts ... this is a solution !
func (m *SMarkdownParser) fixDecodeUrlEncSyntax(txt string) string { // this will postfix special situations with weird characters in links and media
	//--
	defer PanicHandler()
	//--
	var replFx = func(matches []string) string {
		if(len(matches) < 3) {
			return ""
		} //end if
		return EscapeHtml(RawUrlDecode(matches[2])) // must use a version of url decode that will decode also + as spaces
	} //end fx
	//--
	return StrRegexCallbackReplaceAll(`(?U)(\?URL@ENC\:)(.*)(\:URL@ENC\?)`, txt, replFx)
	//--
} //END FUNCTION


func (m *SMarkdownParser) arrStringDataToMap(data []string) map[string]string {
	//--
	defer PanicHandler()
	//--
	var mapData map[string]string = map[string]string{}
	//--
	if(len(data) <= 0) {
		return mapData
	} //end if
	//--
	for i:=0; i<len(data); i++ {
		mapData[ConvertIntToStr(i)] = data[i]
	} //end if
	//--
	if(len(data) != len(mapData)) {
		log.Println("[WARNING]", CurrentFunctionName(), "Data is Not Equal with MapData", len(data), len(mapData))
	} //end if
	//--
	return mapData
	//--
} //END FUNCTION


func (m *SMarkdownParser) getDataBlockQuoteds(txt string) []string { // Quoted Blocks
	//--
	defer PanicHandler()
	//--
	return m.regexFindAllGroupZeroMatches("GO", mkdwPatternBlockQuoted, txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getDataBlockCodes(txt string) []string { // Fenced Code Blocks
	//--
	defer PanicHandler()
	//--
	return m.regexFindAllGroupZeroMatches("GO", mkdwPatternBlockCode, txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getDataInlineCodes(txt string) []string { // Inline Code
	//--
	defer PanicHandler()
	//--
	return m.regexFindAllGroupZeroMatches("GO", mkdwPatternInlineCode, txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getDataInlineLinksAndMedia(txt string) []string { // Inline Links, Links with Media, Media
	//--
	defer PanicHandler()
	//--
	return m.regexFindAllGroupZeroMatches("GO", mkdwPatternLinkAndMedia, txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getInlineLink(txt string) []string { // Inline Links
	//--
	defer PanicHandler()
	//--
	return m.regexFindMatch("GO", mkdwPatternLinkOnly, txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getInlineMedia(txt string) []string { // Inline Media
	//--
	defer PanicHandler()
	//--
	return m.regexFindMatch("GO", mkdwPatternMediaOnly, txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getDataBlockPreformats(txt string) []string { // Fenced Preformat Blocks
	//--
	defer PanicHandler()
	//--
	return m.regexFindAllGroupZeroMatches("GO", mkdwPatternBlockPre, txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getDataBlockMPreformats(txt string) []string { // Fenced Preformat Blocks, Mono
	//--
	defer PanicHandler()
	//--
	return m.regexFindAllGroupZeroMatches("GO", mkdwPatternBlockMPre, txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getTextAsLinesArr(txt string) []string {
	//--
	return Explode("\n", StrTrimWhitespaces(txt)) // {{{SYNC-MKDW-TRIM-ELEMENT-PROC}}}
	//--
} //END FUNCTION


func (m *SMarkdownParser) getTextWithPlaceholders(txt string, element string, arr map[string]string) string {
	//--
	defer PanicHandler()
	//--
	m.initDefinitionData(false)
	//--
	var nl string = ""
	switch(element) {
		//--
		case "inline-links-and-media": fallthrough
		case "inline-code":
			nl = "" // skip newline in this context
			break
		//-- {{{SYNC-MKDW-SPECIAL-BLOCK-TYPES}}}
		case "code": fallthrough
		case "mpre": fallthrough
		case "pre": fallthrough
		case "blockquote":
		//-- #end sync
			nl = "\n" // use newline in this context
			break
		//--
		default:
			log.Println("[WARNING]", CurrentFunctionName(), "# Invalid element: `" + element + "`")
			return txt
	} //end switch
	//--
	val, keyExists := m.definitionData["extracted"][element + ":placeholders"]
	if((keyExists != true) || (val == nil)) {
		m.definitionData["extracted"][element + ":placeholders"] = map[string]string{}
	} //end if
	//--
	if(len(arr) > 0) {
		for key, val := range arr {
			var placeholder string = mkdwSpecialCharEntryMark + "/%/" + element + "/place/" + key + "/" + mkdwSpecialCharEntryMark + "%.%"
			txt = StrReplaceWithLimit(txt, val, nl + placeholder + nl, 1) // replace just first occurence
			if(element == "inline-links-and-media") {
				val = StrReplaceAll(val, "```", "``") // fix: links and media cannot contain inline code ; thus if inline code detected will be changed to highlight (mark) ; for links that contain in description 3 backticks sequence ; it is req. because links and media are extracted out before inline code ... it is a very specific situation !
			} //end if
			m.definitionData["extracted"][element + ":placeholders"][placeholder] = val
		} //end for
	} //end if
	//--
	return txt
	//--
} //END FUNCTION


func (m *SMarkdownParser) setBackTextWithPlaceholders(txt string, element string) string {
	//--
	defer PanicHandler()
	//--
	m.initDefinitionData(false) // init if req., no clear
	//--
	switch(element) {
		//--
		case "inline-links-and-media": fallthrough
		case "inline-code": fallthrough
		//-- {{{SYNC-MKDW-SPECIAL-BLOCK-TYPES}}}
		case "code": fallthrough
		case "mpre": fallthrough
		case "pre": fallthrough
		case "blockquote":
		//-- #end sync
			// ok
			break
		default:
			log.Println("[WARNING]", CurrentFunctionName(), " # Invalid element: `" + element + "`")
			return txt
	} //end switch
	//--
	valDef, keyExistsDef := m.definitionData["extracted"][element + ":placeholders"]
	if(!keyExistsDef) {
		m.definitionData["extracted"][element + ":placeholders"] = map[string]string{}
		return txt
	} //end if
	//--
	if(len(valDef) > 0) {
		for key, val := range valDef {
			if(StrTrimWhitespaces(key) != "") {
				if(element == "inline-links-and-media") { // links, links with media, media
					val = m.renderLinksAndMedia(val, false) // it returns html safe escaped code
					val = m.fixEscapings(val) // for links and media need to be fixed here ... cannot later !
					txt = StrReplaceWithLimit(txt, key, val, 1) // ! no new line here, it is inline syntax
				} else if(element == "inline-code") { // code
					if((StrLen(val) > 6) && StrStartsWith(val, "```") && StrEndsWith(val, "```")) {
						val = StrSubstr(val, 3, len(val)-3) // remove 1st ``` and last ```
					} //end if
					val = m.fixRenderCode(val) // {{{SYNC-MKDW-CODE-FIX-SPECIALS}}}
					txt = StrReplaceWithLimit(txt, key, `<code class="mkdw-inline-code">` + EscapeHtml(val) + `</code>`, 1) // ! no new line here, it is inline syntax
				} else {
					arr := m.getTextAsLinesArr(val)
					var max int = len(arr)
					if(max > 0) {
						for i:=0; i<max; i++ {
							if(element == "blockquote") { // compat blockquote pre-process
								arr[i] = StrTrimLeft(arr[i], ">") // first ltrim only the > characters
								tmpTestChar := StrSubstr(arr[i], 0, 1)
								if((tmpTestChar == " ") || (tmpTestChar == "\t")) {
									arr[i] = StrSubstr(arr[i], 1, 0) // eliminate only first space or tab, DO NOT ltrim() all spaces ; otherwise, the code or pre inside will loose the format
								} //end if
								tmpTestChar = ""
								arr[i] += "\n" // do not escape !! will be processed later as lines between a blockquote
								if(i <= 0) { // first
									arr[i] = "<<<" + "\n" + arr[i]
								} //end if
								if(i == (max - 1)) { // last
									arr[i] += "<<<" + "\n"
								} //end if
							} else if(element == "code") { // pre+code
								if(i == 0) {
									syntax := StrTrimWhitespaces(StrTrimLeft(arr[i], "`"))
									if(syntax == "") {
										syntax = "plaintext"
									} //end if
									arr[i] = `<pre><code class="mkdw-code syntax" data-syntax="` + EscapeHtml(syntax) + `">` // data syntax must not be parsed inline
								} else if(i == (max - 1)) { // last
									arr[i] = `</code></pre>` + "\n"
								} else {
									arr[i] = m.fixRenderCode(arr[i]) // {{{SYNC-MKDW-CODE-FIX-SPECIALS}}}
									arr[i] = EscapeHtml(arr[i]) + "\n" // do not parse inline, preserve code
								} //end if else
							} else { // pre
								if(i == 0) {
									if(element == "mpre") {
										arr[i] = `<pre class="mkdw-mono">`
									} else {
										arr[i] = `<pre>`
									} //end if else
								} else if(i == (max - 1)) { // last
									arr[i] = `</pre>` + "\n"
								} else {
									arr[i] = EscapeHtml(arr[i]) + "\n"; // this should not be parsed inline ! (ex: html comments are tranformed in del tag)
								} //end if else
							} //end if else
						} //end for
					} //end if
					txt = StrReplaceWithLimit(txt, key, Implode("", arr), 1)
				} //end if else
			} //end if
		} //end for
	} //end if
	//--
	return txt
	//--
} //END FUNCTION


func (m *SMarkdownParser) replaceInlineTextFormatting(txt string) string {
	//--
	defer PanicHandler()
	//--
	if(txt == "") {
		return ""
	} //end if
	//--
	var syntaxInlineFormatting map[string]string = map[string]string{ // SYNTAX_INLINE_FORMATTING
		"**" : "b", // strong
		"==" : "i", // em
		"~~" : "s", // strike
		"__" : "u", // underline
		"--" : "del",
		"++" : "ins",
		"!!" : "sub",
		"^^" : "sup",
		",," : "q", // inline quote
		"$$" : "var", // can be used for math
		"??" : "cite", // inline term def, ; cannot use dt/dd
		"``" : "mark", // ```inline code``` and block codes are handled elsewhere, there is no risk to collide with them, this is safe
	}
	//--
	for key, val := range syntaxInlineFormatting {
		//--
		if(StrContains(txt, key) == true) {
			//--
			var repls uint64 = 0
			var replt string = ""
			//--
			for {
				//--
				if(StrContains(txt, key) != true) {
					break
				} //end if
				//--
				replt = ""
				if((repls % 2) != 0) {
					replt = "</" + m.escapeValidHtmlTagName(val) + ">" // closing tag
				} else {
					replt = "<" + m.escapeValidHtmlTagName(val) + ">" // opening tag
				} //end if else
				//--
				txt = StrReplaceWithLimit(txt, key, replt, 1) // replace just 1st occurence
				//--
				repls++
				//--
				if(repls > 8192) { // {{{SYNC-MKDW-LOOP-INLINE-EVEN-TAGS}}} ; also this number must be even: 8192
					log.Println("[NOTICE]", CurrentFunctionName(), "Too many replacements in a single line, line is too long ...")
					break
				} //end if
				//--
			} //end for
			//-- fix: add closing tag if missing, otherwise need to run html validate as too many tags may remain unclosed ; tags on another line are not supported ... it is better this way to avoid running html validator as mandatory for safety
			if((repls % 2) != 0) { // {{{SYNC-MKDW-LOOP-INLINE-EVEN-TAGS}}} ; this condition works just if the above stop number is even: 8192
				txt += "</" + m.escapeValidHtmlTagName(val) + ">" // closing tag if not even ; if while loop breaks before end be sure close last line, also inline tags cannot spread on many lines !
			} //end if
			//-- fix: remove empty tags: if by example the strings ends with ** will replace it with <b> and will fix closing tag after with </b> resulting in string ending with an empty tag as <b></b> ; this also fixes the situation <b>[\t ]*</b> a tag with just spaces ; all need to be removed at the end after applying html escape
			if(StrContains(txt, "<") && StrContains(txt, ">")) {
				//-- emulate regex callback replace, cannot use it, need regex v2 because of modifier \1
				matches, err := StrRegex2FindAllMatches("PERL", `\<([a-z]+)\>([\t ]*)\<\/\1\>`, txt, 0, 0)
				if(err == nil) {
					if(len(matches) > 0) {
						for i:=0; i<len(matches); i++ {
							if(len(matches[i]) < 3) {
								log.Println("[WARNING]", CurrentFunctionName(), "Invalid Group Length:", len(matches[i]), "on cycle:", i)
								return "" // stop on first group that isnot compliant, should have 3 entries each !
							} //end if
							txt = StrReplaceWithLimit(txt, matches[i][0], matches[i][2], 1) // replace just 1st occurence (replace each empty tag, one by one)
						} //end for
					} //end if
				} else {
					log.Println("[WARNING]", CurrentFunctionName(), "ERR:", err)
					return "" // stop on first error
				} //end if else
				//--
			} //end if
			//--
		} //end if
		//--
	} //end for
	//--
	return txt
	//--
} //END FUNCTION


func (m *SMarkdownParser) fixRelativeURL(url string) string {
	//--
	defer PanicHandler()
	//--
	url = StrTrimWhitespaces(url)
	//--
	if(m.relativeUrlPrefix == "") {
		return url
	} //end if
	//--
	if(StrStartsWith(url, "#") || StrStartsWith(url, "mailto:")) { // anchor ; mail
		return url
	} //end if
	//--
	if(!StrStartsWith(url, "http://") && !StrStartsWith(url, "https://") && !StrStartsWith(url, "//")) { // http | https | http(s)
		return m.relativeUrlPrefix + url
	} //end if
	//--
	return url
	//--
} //END FUNCTION


func (m *SMarkdownParser) fixRenderCode(txt string) string {
	//-- {{{SYNC-MKDW-CODE-FIX-SPECIALS}}}
	txt = StrReplaceAll(txt, "\\`\\`\\`", "```")
	txt = StrReplaceAll(txt, "∖`∖`∖`", "\\`\\`\\`") // '∖' here is the utf-8 #8726 (a special backslash)
	//--
	return txt
	//--
} //END FUNCTION


// unixman, extra Attributes ($ is replaced with a space for @atr=)
// Examples:
//		[link](http://unix-world.org) {L:.primary9 #link .Upper-Case @data-smart=open.modal$700$300}
//		![alt text](https://www.gstatic.com/webp/gallery/1.sm.jpg "Logo Title Text 1") {I:@width=100 @style=box-shadow:$10px$10px$5px$#888888; %lazyload=unveil %alternate=https://www.gstatic.com/webp/gallery/1.sm.webp$image/webp}
//		![Sample Video OGG](https://www.w3schools.com/html/mov_bbb.ogg){I: #video-1 %video=ogg @width=320 @height=176 @controls=none}
//		![Sample Video Webm/MP4](https://www.w3schools.com/html/mov_bbb.webm$https://www.w3schools.com/html/mov_bbb.mp4){I: #video-2 %video=webm$mp4 @width=320 @height=176 @preload=none @poster=https://www.w3schools.com/images/w3html5.gif}
//		![Sample Audio OGG/MP3](https://www.w3schools.com/html/horse.ogg$https://www.w3schools.com/html/horse.mp3){I: #audio-1 %audio=ogg$mpeg}
// 		TABLE / TH / TD {T: @class=bordered}
func (m *SMarkdownParser) parseAttributeData(elType string, attributeStr string) map[string]string {
	//--
	defer PanicHandler()
	//--
	// TODO: use elType for a list of allowable attributes
	//--
	var arr map[string]string = map[string]string{}
	//--
	elType = StrToLower(StrTrimWhitespaces(elType))
	if(elType == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "# Element Type is Empty")
		return arr
	} //end if
	//--
	attributeStr = StrTrimWhitespaces(attributeStr)
	if(attributeStr == "") {
	//	log.Println("[WARNING]", CurrentFunctionName(), "# Attribute is Empty")
		return arr
	} //end if
	//--
	var attributes []string = Explode(" ", attributeStr)
	//--
	if(len(attributes) <= 0) {
		return arr
	} //end if
	//--
	var classes []string = []string{}
	for i:=0; i<len(attributes); i++ {
		//--
		var attribute string = StrTrimWhitespaces(attributes[i])
		//--
		if(StrStartsWith(attribute, "@")) { // @ html attr
			if(StrContains(attribute, "=")) { // ex: @style=box-shadow:$10px$10px$5px$#888888;filter:grayscale!!_80%_!!;
				tmpArr := Explode("=", attribute)
				if(len(tmpArr) < 1) {
					tmpArr = append(tmpArr, "")
				} //end if
				if(len(tmpArr) < 2) {
					tmpArr = append(tmpArr, "")
				} //end if
				tmpArr[0] = StrTrimWhitespaces(tmpArr[0])
				tmpArr[1] = StrTrimWhitespaces(tmpArr[1])
				arr[StrTrimWhitespaces(StrSubstr(tmpArr[0],1,0))] = StrTrimWhitespaces(StrTr(tmpArr[1],map[string]string{"$":" ","!!_":"(","_!!":")"})) // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
			} else { // ex: @article-div
				arr["id"] = StrSubstr(attribute, 1, 0)
			} //end if else
		} else if(StrStartsWith(attribute, "#")) { // # html id
			arr["id"] = StrSubstr(attribute, 1, 0)
		} else if(StrStartsWith(attribute, ".")) { // . html class name
			classes = append(classes, StrSubstr(attribute, 1, 0))
		} else if(StrStartsWith(attribute, "%")) { // % alternate media (used for images)
			if(elType == "a") {
				if(attribute == "%blank") {
					arr["target"] = "_blank"
				} //end if
			} else if(elType == "media") {
				if(StrStartsWith(attribute, "%video=")) {
					arr["video"] = StrSubstr(attribute, 7, 0)
				} else if(StrStartsWith(attribute, "%audio=")) {
					arr["audio"] = StrSubstr(attribute, 7, 0)
				} else if(StrStartsWith(attribute, "%lazyload=")) {
					arr["lazyload"] = StrSubstr(attribute, 10, 0)
				} else if(StrStartsWith(attribute, "%alternate=")) {
					tmpAttr := Explode("$", attribute)
					if(len(tmpAttr) < 1) {
						tmpAttr = append(tmpAttr, "")
					} //end if
					if(len(tmpAttr) < 2) {
						tmpAttr = append(tmpAttr, "")
					} //end if
					tmpAlternate := StrSubstr(tmpAttr[0], 11, 0)
					if(
						(StrContains(attribute, "$")) &&
						(len(tmpAttr) == 2) &&
						(StrTrimWhitespaces(tmpAttr[0]) != "") &&
						(StrTrimWhitespaces(tmpAttr[1]) != "") &&
						(StrTrimWhitespaces(tmpAlternate) != "")) {
						tmpAttr[0] = tmpAlternate
						arr["alternate"] = tmpAttr[0] + "$" + tmpAttr[1] // {{{SYNC-MARKDOWN-ATTR-ALTERNATE}}} ; in PHP was array: tmpAttr ; in GoLang is not possible
					} //end if
				} //end if
			} //end if
		} //end if
		//--
	} //end for
	//--
	if(len(classes) > 0) {
		var uniqueClasses []string = []string{}
		for i:=0; i<len(classes); i++ {
			classes[i] = StrTrimWhitespaces(classes[i])
			if(classes[i] != "") {
				if(!InListArr(classes[i], uniqueClasses)) {
					uniqueClasses = append(uniqueClasses, classes[i])
				} //end if
			} //end if
		} //end for
		classes = []string{}
		if(len(uniqueClasses) > 0) {
			for i:=0; i<len(uniqueClasses); i++ {
				if(!StrStartsWith(uniqueClasses[i], "mkdw-")) {
					classes = append(classes, uniqueClasses[i]) // allowed classes: must not start with 'mkdw-', the prefix is reserved for the main CSS of Markdown
				} //end if
			} //end for
		} //end if
		arr["class"] = Implode(" ", classes)
	} //end if
	//--
	return arr
	//--
} //END FUNCTION


func (m *SMarkdownParser) parseElementAttributes(txt string, typ string) (string, map[string]string) {
	//--
	defer PanicHandler()
	//--
	typ = StrToLower(StrTrimWhitespaces(typ))
	//--
	var atts map[string]string = map[string]string{}
	//--
	var rexp string = ""
	switch(typ) {
		case "media": // media
			rexp = mkdwRegexMediaAttribute
			break
		case "a": // link
			rexp = mkdwRegexLinkAttribute
			break
		case "h1": fallthrough
		case "h2": fallthrough
		case "h3": fallthrough
		case "h4": fallthrough
		case "h5": fallthrough
		case "h6": fallthrough
		case "span": fallthrough // h7
		case "dfn": // h8
			rexp = mkdwRegexHeadingAttribute
			break
		case "td":
			rexp = mkdwRegexTableCellAttribute
			break
		default:
			log.Println("[WARNING]", CurrentFunctionName(), "# Invalid Element Type:", typ)
			return txt, atts
	} //end switch
	if(rexp == "") {
		log.Println("[WARNING]", CurrentFunctionName(), "# Empty Regex for Element Type:", typ)
		return txt, atts
	} //end if
	//--
	if(txt == "") {
		return txt, atts
	} //end if
	//--
	matches, err := StrRegexFindFirstMatch(rexp, txt)
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Regex Failed for Element Type:", typ, "; ERR:", err)
		return txt, atts
	} //end if
	if(len(matches) >= 3) {
		var attributeRawString string = matches[0]
		var attributeString string    = matches[2]
		if(attributeString != "") {
			atts = m.parseAttributeData(typ, attributeString)
		} //end if
		if(attributeRawString != "") {
			txt = StrReplaceWithLimit(txt, attributeRawString, "", 1) // {{{SYNC-MKDW-REPL-ATTS-DEF}}}
		} //end if
	} //end if
	//--
	return txt, atts
	//--
} //END FUNCTION


func (m *SMarkdownParser) parseTableAttributes(firstTableHeaderCell string) (string, []string) {
	//--
	defer PanicHandler()
	//--
	var tableDefs []string = []string{}
	//--
	defsMatches, err := StrRegexFindFirstMatch(mkdwRegexTableDefinition, firstTableHeaderCell)
	if(err != nil) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Regex Find Match Failed:", err)
	} //end if
	if(len(defsMatches) >= 2) {
		firstTableHeaderCell = StrReplaceWithLimit(firstTableHeaderCell, defsMatches[0], "", 1) // {{{SYNC-MKDW-REPL-ATTS-DEF}}}
		if(len(defsMatches) >= 3) {
			if(StrTrimWhitespaces(defsMatches[2]) != "") {
				tmpTableDefs := Explode(";", defsMatches[2])
				for i:=0; i<len(tmpTableDefs); i++ {
					tmpTableDefs[i] = StrTrimWhitespaces(tmpTableDefs[i])
					if(tmpTableDefs[i] != "") {
						if(!InListArr(tmpTableDefs[i], tableDefs)) {
							tableDefs = append(tableDefs, tmpTableDefs[i])
						} //end if
					} //end if
				} //end for
			} //end if
		} //end if
	} //end if
	//--
	return firstTableHeaderCell, tableDefs
	//--
} //END FUNCTION


func (m *SMarkdownParser) buildAttributeData(arr map[string]string, exclusions map[string]bool) string {
	//--
	defer PanicHandler()
	//--
	if(len(arr) <= 0) {
		return ""
	} //end if
	//--
	var realAtts map[string]string = map[string]string{}
	for aKey, aVal := range arr {
		//--
		aKey = StrToLower(StrTrimWhitespaces(aKey)) // make all lower string
		//--
		if( // validate the HTML attribute
			(aKey != "") && // non-empty
			(StrRegexMatch(`^[a-z]+`, aKey) == true) && // must start with a-z
			(StrRegexMatch(`^[a-z0-9\-]+$`, aKey) == true)) { // may contain only a-z 0-9 -
			var ok bool = true
			if(len(exclusions) > 0) {
				if(ArrMapKeyExists(aKey, exclusions)) {
					ok = false
				} //end if
			} //end if
			if(ok == true) {
				realAtts[aKey] = aVal // UNSYNC ; in PHP was mixed ...
			} //end if
		} //end if
		//--
	} //end for
	//--
	var catt []string = []string{}
	for key, val := range realAtts {
		var prefix string = "" // UNSYNC: cannot use mixed types in golang ; prefix: "data-mkdw-" ; TODO: use later these kind of attributes for post rendering !
		val = EscapeHtml(prefix + key) + `="` + EscapeHtml(val) + `"` // attributes must not be parsed inline
		catt = append(catt, val)
	} //end for
	//--
	if(len(catt) > 0) {
		return " " + Implode(" ", catt)
	} //end if
	//--
	return ""
	//--
} //END FUNCTION


func (m *SMarkdownParser) createHtmlInline(txt string, typ string, headingsParsed bool) string {
	//--
	defer PanicHandler()
	//--
	// in PHP, the default value of headingsParsed is FALSE
	//--
	//--
	// Smart.Markdown inline syntax support:
	// 		IMPORTANT:
	// 			- do not use ## @@ %% here, they may collide with Marker Templating Syntax ; or {{: :}} which may collide with PageBuilder Syntax
	// 			- do not use << or >> here, they are already html escaped when the replacements need to occur
	//--
	//	**bold** ; here the __bold__ is no more supported, it is now __underline__, but at least this is compatible with commonmark as **bold**
	//	==italic== ; but support original compatible _italic_ as there is no other way to have compatibility with commonmark ; no support for *italic* because is redundant and if only can support one compatibility for bold will support also just one for italic
	//	~~strikethrough~~
	//	__underline__
	//	--delete--
	//	++insert++
	//	!!subscript!! ; but support original compatible ~subscript~ as there is no other way to have compatibility with commonmark
	//	^^superscript^^ ; but support original compatible ^supperscript^ as there is no other way to have compatibility with commonmark
	//	$$variable$$
	//	,,quote,,
	//	??definition term??
	// ``highlight``
	//--
	if(StrTrimWhitespaces(txt) == "") {
		return ""
	} //end if
	//--
	typ = StrToLower(StrTrimWhitespaces(typ))
	//--
	var tagStart string = ""
	var tagEnd   string = ""
	//--
	var atts map[string]string
	switch(typ) {
		case "p":
			if(StrStartsWith(txt, "####### ")) { // skip div and newline for (h7:span) ; add a space before
				tagStart = " " // preserve a space instead newline
				tagEnd   = ""
			} else if(StrStartsWith(txt, "######## ")) { // skip div and newline for (h8:dfn) ; add a newline before
				tagStart = "\n"
				tagEnd   = ""
			} else { // for all the rest, DEFAULT
				tagStart = `<div class="mkdw-line">`
				tagEnd   = `</div>` + "\n"
			} //end if
			break
		case "h1": fallthrough
		case "h2": fallthrough
		case "h3": fallthrough
		case "h4": fallthrough
		case "h5": fallthrough
		case "h6":
			headingsParsed = true // avoid re-parse headers in the same line if already there is one
			txt, atts = m.parseElementAttributes(txt, typ)
			tagStart  = "<"  + m.escapeValidHtmlTagName(typ) + m.buildAttributeData(atts, nil) + ">"
			tagEnd    = "</" + m.escapeValidHtmlTagName(typ) + ">" + "\n"
			break
		case "span": // h7
			headingsParsed = true // avoid re-parse headers in the same line if already there is one
			txt, atts = m.parseElementAttributes(txt, "span") // parse as h7
			tagStart  = "<span" + m.buildAttributeData(atts, nil) + ">"
			tagEnd    = "</span>" // no extra new line
			break
		case "dfn": // h8
			headingsParsed = true // avoid re-parse headers in the same line if already there is one
			txt, atts = m.parseElementAttributes(txt, "dfn") // parse as h7
			tagStart  = "<dfn" + m.buildAttributeData(atts, nil) + ">"
			tagEnd    = "</dfn>" // no extra new line
			break
		case "li": fallthrough
		case "td":
			// the tags and attributes are created in the main loop for these ... ; in this case(s) it is just the line content that must be processed inline and escaped, then return elsewhere to create the tags
			break
		default:
			log.Println("[WARNING]", CurrentFunctionName(), "# Invalid Element Type:", typ)
			return EscapeHtml(txt)
	} //end switch
	//--
	//== {{{SYNC-MKDW-RENDER-ENTITIES-AND-INLINE-FORMATTING}}}
	//-- replace html entities with placeholders
	txt = StrTr(txt, m.mkdwHtmlEntitiesReplacements()) // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
	//-- headings: h1..h6 (# style)
	var unparsed bool = true
	if(headingsParsed == false) {
		txt, unparsed = m.renderLineHeadings(txt)
	} //end if
	//-- apply default escaping, if not escaped elsewhere
	if(unparsed == true) {
		txt = EscapeHtml(txt) // line not parsed, escape html here ; if line was parsed, the escapes were made in renderLineHeadings
	} //end if
	//-- render back html entities
	txt = StrTr(txt, ArrMapStrFlip(m.mkdwHtmlEntitiesReplacements())) // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
	//-- text formatting syntax
	txt = m.replaceInlineTextFormatting(txt)
	//--
	//== #end sync
	//--
	return tagStart + txt + tagEnd
	//--
} //END FUNCTION


func (m *SMarkdownParser) renderAltOrTitle(txt string) string { // {{{SYNC-SMART-STRIP-TAGS-LOGIC}}}
	//--
	defer PanicHandler()
	//--
	txt = m.replaceInlineTextFormatting(txt) // render syntax (will be cleared below)
	txt = HTMLCodeStripTags(txt) // cleanup html tags ; it also restores html entities
	//--
	txt = StrRegexReplaceAll(REGEX_HTML_ANY_ENTITY, txt, " ") // clean any other remaining html entities
	txt = StrRegexReplaceAll(`[ \t]+`, txt, " ") // replace multiple tabs or spaces with one space
	//--
	txt = StrTr(txt, map[string]string{ // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
		"''" 	: 	"",
		"' '" 	: 	"",
		`""` 	: 	"",
		`" "` 	: 	"",
	})
	//--
	return EscapeHtml(txt)
	//--
} //END FUNCTION


func (m *SMarkdownParser) renderLineHeadings(lineCrr string) (string, bool) { // line, unparsed
	//--
	defer PanicHandler()
	//--
	if(!StrStartsWith(lineCrr, "#")) { // {{{SYNC-MKDW-HEADERS-LINE-DETECT}}}
		return lineCrr, true // not a heading line
	} //end if
	//--
	var isLineUnparsed bool = true // set to false if lineCrr was modified
	//--
	var level int = int(StrSpnChr(lineCrr, '#', 0, 10)) // fix by unixman ; find up to 10 levels of #, only need max 8 (h1..6 ; 7 span ; 8 dfn)
	if((level >= 1) && (level <= 6)) { // h1..h6
		if(StrPos(lineCrr, "# ", false) == (level-1)) { // h1..h6
			lineCrr = m.createHtmlInline(StrSubstr(lineCrr, (level+1), 0), "h" + ConvertIntToStr(level), true) // avoid circular reference between createHtmlInline and this (renderLineHeadings) as renderLineHeadings is called inside createHtmlInline thus must explicit set last param to true, just in case ... anyway there is a double control !
			isLineUnparsed = false
		} //end if
	} else if(level == 7) { // span
		if(StrPos(lineCrr, "# ", false) == (level-1)) { // h7:span
			lineCrr = m.createHtmlInline(StrSubstr(lineCrr, (level+1), 0), "span", true) // avoid circular reference between createHtmlInline and this (renderLineHeadings) as renderLineHeadings is called inside createHtmlInline thus must explicit set last param to true, just in case ... anyway there is a double control !
			isLineUnparsed = false;
		} //end if
	} else if(level == 8) { // dfn
		if(StrPos(lineCrr, "# ", false) == (level-1)) { // h8:dfn
			lineCrr = m.createHtmlInline(StrSubstr(lineCrr, (level+1), 0), "dfn", true) // avoid circular reference between createHtmlInline and this (renderLineHeadings) as renderLineHeadings is called inside createHtmlInline thus must explicit set last param to true, just in case ... anyway there is a double control !
			isLineUnparsed = false
		} //end if
	} //end if
	//--
	return lineCrr, isLineUnparsed
	//--
} //END FUNCTION


func (m *SMarkdownParser) renderLineDefault(lineCrr string, lineNext string) (string, bool) { // line, clear next line
	//--
	defer PanicHandler()
	//--
	var clearNext bool = false
	//--
	if(StrTrimWhitespaces(lineCrr) == "") {
		return lineCrr, clearNext // empty
	} //end if
	//-- check special markers
	if(StrStartsWith(lineCrr, mkdwSpecialCharEntryMark + "/%/")) {
		if( // {{{SYNC-MKDW-SPECIAL-BLOCK-TYPES}}}
			StrStartsWith(lineCrr, mkdwSpecialCharEntryMark + "/%/code/") ||
			StrStartsWith(lineCrr, mkdwSpecialCharEntryMark + "/%/pre/") ||
			StrStartsWith(lineCrr, mkdwSpecialCharEntryMark + "/%/blockquote/")) {
			return lineCrr, clearNext // skip these lines, they are post-render markers: code, pre, blockquote
	//	} else if(
	//		StrStartsWith(lineCrr, mkdwSpecialCharEntryMark + "/%/inline-links-and-media/") ||
	//		StrStartsWith(lineCrr, mkdwSpecialCharEntryMark + "/%/inline-code/")) {
	//		lineCrr = m.createHtmlInline(lineCrr, "p", false)
	//		return lineCrr, clearNext // skip these lines, they need to be rendered here: inline-links-and-media, inline-code
		} //end if else
	} //end if
	//-- Alternate Style Headings: h1, h2
	if(lineNext != "") {
		if(StrStartsWith(lineNext, "======") && (StrTrimRightWhitespaces(StrTrim(lineNext, "=")) == "")) { // at least 6 chars as =, but only these
			lineCrr = m.createHtmlInline(lineCrr, "h1", false) // no need for the 3rd param to explicit set to TRUE, here there is no circular reference since these are alt headers
			clearNext = true // clear next line
			return lineCrr, clearNext
		} else if(StrStartsWith(lineNext, "------") && (StrTrimRightWhitespaces(StrTrim(lineNext, "-")) == "")) { // at least 6 chars as -, but only these
			lineCrr = m.createHtmlInline(lineCrr, "h2", false) // no need for the 3rd param to explicit set to TRUE, here there is no circular reference since these are alt headers
			clearNext = true // clear next line
			return lineCrr, clearNext
		} //end if else
	} //end if else
	//--
	lineCrr = m.createHtmlInline(lineCrr, "p", false)
	//--
	return lineCrr, clearNext
	//--
} //END FUNCTION


func (m *SMarkdownParser) renderHtmlLinkOnly(extractedLinkOnlyArr []string, linkOrMediaMdPart string) string {
	//--
	defer PanicHandler()
	//--
	if(len(extractedLinkOnlyArr) < 3) { // it can contain a sub-media !
		return ""
	} //end if
	if(len(extractedLinkOnlyArr) < 4) {
		extractedLinkOnlyArr = append(extractedLinkOnlyArr, "") // {{{SYNC-MKDW-MEDIA-LINKS-TITLE-CAN-MISS}}} ; if no title text, there are only 3 elements in the array: 0, 1 and 2
	} //end if
	//--
	var linkTxt string   = StrTrimWhitespaces(extractedLinkOnlyArr[1])
	var linkHref string  = StrTrimWhitespaces(extractedLinkOnlyArr[2])
	var linkTitle string = StrTrimWhitespaces(extractedLinkOnlyArr[3])
	//--
	linkTitle = StrTrimWhitespaces(StrTrim(linkTitle, `"'`)) // remove trailing quotes and spaces
	//--
	_, atts := m.parseElementAttributes(linkOrMediaMdPart, "a") // txt, atts
	//--
	if(linkHref == "") {
		return "" // invalid link ; the link href is empty
	} //end if
	//--
	if(linkHref == "#") { // anchor
		if(linkTxt == "") {
			value, isSet := atts["id"]
			if(isSet) {
				linkTxt = StrTrimWhitespaces(value)
			} //end if
		} //end if
		if(linkTxt != "") {
			linkTxt = StrCreateHtmId(linkTxt)
			if(linkTxt != "") {
				return `<a href="#" id="` + EscapeHtml(linkTxt) + `" style="visibility:hidden;"></a>`
			} //end if
		} //end if
		return "" // invalid anchor ; the link id is empty
	} //end if
	//--
	if(linkTxt == "") {
		return "" // invalid link ; the link href is empty
	} //end if
	//--
	var linkHtmlTxt string = ""
	if(StrStartsWith(linkTxt, "![")) { // {{{SYNC-MKDW-DETECT-MEDIA-START}}}
		linkHtmlTxt = m.renderLinksAndMedia(linkTxt, true) // circular reference protection ; disable detect links inside links !
	} else {
		linkHtmlTxt = linkTxt
		//== {{{SYNC-MKDW-RENDER-ENTITIES-AND-INLINE-FORMATTING}}}
		linkHtmlTxt = StrTr(linkHtmlTxt, m.mkdwHtmlEntitiesReplacements()) // replace html entities with placeholders ; ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
		//- SKIP render line headings in this context
		linkHtmlTxt = EscapeHtml(linkHtmlTxt) // apply default escaping
		linkHtmlTxt = StrTr(linkHtmlTxt, ArrMapStrFlip(m.mkdwHtmlEntitiesReplacements())) // render back html entities ; ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
		linkHtmlTxt = m.replaceInlineTextFormatting(linkHtmlTxt) // text formatting syntax
		//== #end sync
	} //end if
	//--
	if(linkTitle == "=@.") {
		linkTitle = linkTxt // unixman fix: if title is "=@." make the same as alt to avoid duplicating the same text in the markdown code
	} //end if
	//--
	linkHref = m.fixRelativeURL(linkHref)
	//--
	return `<a href="` + EscapeHtml(linkHref) + `" title="` + m.renderAltOrTitle(linkTitle) + `"` + m.buildAttributeData(atts, nil) + `>` + linkHtmlTxt + `</a>`
	//--
} //END FUNCTION



func (m *SMarkdownParser) renderHtmlMediaOnly(extractedMediaOnlyArr []string, linkOrMediaMdPart string) string {
	//--
	defer PanicHandler()
	//--
	if(len(extractedMediaOnlyArr) < 3) { // it can contain a sub-media !
		return ""
	} //end if
	if(len(extractedMediaOnlyArr) < 4) {
		extractedMediaOnlyArr = append(extractedMediaOnlyArr, "") // {{{SYNC-MKDW-MEDIA-LINKS-TITLE-CAN-MISS}}} ; if no title text, there are only 3 elements in the array: 0, 1 and 2
	} //end if
	//--
	var mediaAltTxt string   = StrTrimWhitespaces(extractedMediaOnlyArr[1])
	var mediaSrc string      = StrTrimWhitespaces(extractedMediaOnlyArr[2])
	var mediaTitle string    = StrTrimWhitespaces(extractedMediaOnlyArr[3])
	//--
	mediaTitle = StrTrimWhitespaces(StrTrim(mediaTitle, `"'`)) // remove trailing quotes and spaces
	//--
	_, atts := m.parseElementAttributes(linkOrMediaMdPart, "media") // txt, atts ; TODO: identify media type here perhaps ...
	//--
	if(mediaSrc == "") {
		return "" // invalid media ; the media src is empty
	} //end if
	//--
	if(mediaSrc == "SFI-ICON") {
		//--
		if(!m.sfiExtraEnabled) {
			return "" // extra media disabled
		} //end if
		//--
		if(mediaTitle != "") {
			//--
			mediaTitle = StrReplaceAll(mediaTitle, "\t", " ")
			//--
			if(StrStartsWith(mediaTitle, "sfi sfi-")) {
				//--
				var theStyle string = ""
				value, isSet := atts["style"]
				if(isSet) {
					value = StrTrimWhitespaces(value)
					if(value != "") {
						theStyle = ` style="` + EscapeHtml(value) + `"`
					} //end if
				} //end if
				//--
				var theAltTxt string = ""
				if(mediaAltTxt != "") {
					theAltTxt = m.renderAltOrTitle(mediaAltTxt)
				} //end if
				//--
				return `<i class="sfi sfi-` + EscapeHtml(StrSubstr(mediaTitle, 8, 0)) + `"` + theStyle + `></i>&nbsp; ` + theAltTxt
				//--
			} //end if
			//--
		} //end if
		//--
	} //end if
	//--
	var mediaId string = ""
	valueId, isSetId := atts["id"]
	if(isSetId) {
		if(valueId != "") {
			mediaId = StrTrimWhitespaces(valueId)
		} //end if
		delete(atts, "id") // unset
	} //end if
	//--
	valueVideo, isSetVideo := atts["video"]
	valueAudio, isSetAudio := atts["audio"]
	//--
	if(isSetVideo && (valueVideo != "")) {
		//--
		if(!m.mediaExtraEnabled) {
			return "" // extra media disabled
		} //end if
		//--
		delete(atts, "video") // unset
		//--
		mediaTitle = mediaAltTxt // for video there is no alt attribute; to avoid duplicating, use for the title always the alt
		//--
		valueVideo = StrToLower(StrTrimWhitespaces(valueVideo))
		//--
		arrVideoSrcs  := Explode("$", mediaSrc)
		arrVideoTypes := Explode("$", valueVideo)
		//--
		if(len(arrVideoSrcs) != len(arrVideoTypes)) {
			return "" // important, avoid panic below: have to be equal in size, below i (iterator) will be used on both
		} //end if
		//--
		var htmlVideoSource string = ""
		for i:=0; i<len(arrVideoSrcs); i++ {
			//--
			var videoSrc string  = StrTrimWhitespaces(arrVideoSrcs[i])
			var videoType string = ""
			//--
			if(videoSrc != "") {
				videoType = StrToLower(StrTrimWhitespaces(arrVideoTypes[i]))
				switch(videoType) {
					case "ogg":  fallthrough
					case "webm": fallthrough
					case "mp4":
						videoType = "/" + videoType
						break
					case "": fallthrough
					default:
						videoType = "" // reset ; unrecognized
				} //end switch
			} //end if
			//--
			htmlVideoSource += `<source type="video` + EscapeHtml(videoType) + `" src="` + EscapeHtml(videoSrc) + `">`
			//--
		} //end for
		//--
		if(htmlVideoSource == "") {
			return "" // invalid video
		} //end if
		//--
		_, isSetPreload := atts["preload"]
		if(!isSetPreload) {
			atts["preload"] = "auto"
		} //end if
		//--
		_, isSetControls := atts["controls"]
		if(!isSetControls) {
			atts["controls"] = "true"
		} //end if
		if((atts["controls"] == "no") || (atts["controls"] == "none") || (atts["controls"] == "false")) {
			delete(atts, "controls") // unset
		} //end if
		//--
		var htmlAttrId string = ""
		if(mediaId != "") {
			htmlAttrId = ` id="` + EscapeHtml(mediaId) + `"`
		} //end if
		//--
		var htmlAttrTitle string = ""
		if(mediaTitle != "") {
			htmlAttrTitle = ` title="` + m.renderAltOrTitle(mediaTitle) + `"`
		} //end if
		//--
		return `<video` + htmlAttrId + htmlAttrTitle + m.buildAttributeData(atts, nil) + `>` + htmlVideoSource + `</video>`
		//--
	} else if(isSetAudio && (valueAudio != "")) {
		//--
		if(!m.mediaExtraEnabled) {
			return "" // extra media disabled
		} //end if
		//--
		delete(atts, "audio") // unset
		//--
		mediaTitle = mediaAltTxt // for audio there is no alt attribute; to avoid duplicating, use for the title always the alt
		//--
		valueAudio = StrToLower(StrTrimWhitespaces(valueAudio))
		//--
		arrAudioSrcs  := Explode("$", mediaSrc)
		arrAudioTypes := Explode("$", valueAudio)
		//--
		if(len(arrAudioSrcs) != len(arrAudioTypes)) {
			return "" // important, avoid panic below: have to be equal in size, below i (iterator) will be used on both
		} //end if
		//--
		var htmlAudioSource string = ""
		for i:=0; i<len(arrAudioSrcs); i++ {
			//--
			var audioSrc string  = StrTrimWhitespaces(arrAudioSrcs[i])
			var audioType string = ""
			//--
			if(audioSrc != "") {
				audioType = StrToLower(StrTrimWhitespaces(arrAudioTypes[i]))
				switch(audioType) { // https://en.wikipedia.org/wiki/HTML5_audio
					case "ogg":  fallthrough
					case "mpeg": fallthrough // mp3
					case "mp4":  fallthrough
					case "webm": fallthrough
					case "flac": fallthrough
					case "wav":
						audioType = "/" + audioType
						break
					case "":
					default:
						audioType = "" // reset ; unrecognized
				} //end switch
			} //end if
			//--
			htmlAudioSource += `<source type="audio` + EscapeHtml(audioType) + `" src="` + EscapeHtml(audioSrc) + `">`
			//--
		} //end for
		//--
		if(htmlAudioSource == "") {
			return "" // invalid audio
		} //end if
		//--
		_, isSetPreload := atts["preload"]
		if(!isSetPreload) {
			atts["preload"] = "auto"
		} //end if
		//--
		_, isSetControls := atts["controls"]
		if(!isSetControls) {
			atts["controls"] = "true"
		} //end if
		if((atts["controls"] == "no") || (atts["controls"] == "none") || (atts["controls"] == "false")) {
			delete(atts, "controls") // unset
		} //end if
		//--
		var htmlAttrId string = ""
		if(mediaId != "") {
			htmlAttrId = ` id="` + EscapeHtml(mediaId) + `"`
		} //end if
		//--
		var htmlAttrTitle string = ""
		if(mediaTitle != "") {
			htmlAttrTitle = ` title="` + m.renderAltOrTitle(mediaTitle) + `"`
		} //end if
		//--
		return `<audio` + htmlAttrId + htmlAttrTitle + m.buildAttributeData(atts, nil) + `>` + htmlAudioSource + `</audio>`
		//--
	} //end if else
	//--
	if(mediaTitle == "=@.") {
		mediaTitle = mediaAltTxt // unixman fix: if title is "=@." make the same as alt to avoid duplicating the same text in the markdown code
	} //end if
	//-- {{{SYNC-MARKDOWN-ATTR-ALTERNATE}}}
	var alternateImgSrc string = ""
	var alternateImgType string = ""
	valueAlternate, isSetAlternate := atts["alternate"]
	if(isSetAlternate) {
		valueAlternate = StrTrimWhitespaces(valueAlternate)
		if(valueAlternate != "") {
			arrAlternate := Explode("$", valueAlternate)
			if(len(arrAlternate) > 0) {
				alternateImgSrc = StrTrimWhitespaces(arrAlternate[0])
				if(len(arrAlternate) > 1) {
					alternateImgType = StrTrimWhitespaces(arrAlternate[1])
				} //end if
			} //end if
		} //end if
		delete(atts, "alternate") // unset
	} //end if
	//--
	var useLazyLoad bool = false
	var classLazyLoad string = ""
	valueLazyLoad, isSetLazyLoad := atts["lazyload"]
	valueLoading, isSetLoading := atts["loading"]
	if(isSetLazyLoad) {
		if(m.lazyLoadImgUnveil) {
			valueLazyLoad = StrTrimWhitespaces(valueLazyLoad)
			if(valueLazyLoad != "") {
				classLazyLoad = valueLazyLoad
			} //end if
			if(classLazyLoad != "") {
				useLazyLoad = true
			} //end if
			delete(atts, "lazyload") // unset
		} else {
			delete(atts, "lazyload") // do not set a lazyload="" attribute on img
			if(!isSetLoading) {
				isSetLoading = true
				atts["loading"] = "lazy" // export back to atts array
				valueLoading = atts["loading"]
			} //end if
		} //end if else
	} //end if
	//-- loading
	if(isSetLoading) {
		valueLoading = StrToLower(StrTrimWhitespaces(valueLoading))
		if(valueLoading == "lazy") {
			useLazyLoad = false // avoid mixing lazyload with loading lazy
		} else {
			delete(atts, "loading") // do not set a loading="" attribute on img
		} //end if else
	} //end if
	//--
	valueClass, isSetClass := atts["class"]
	if(useLazyLoad) {
		if(!isSetClass) {
			atts["class"] = classLazyLoad
		} else {
			atts["class"] = StrTrimWhitespaces(classLazyLoad + " " + StrTrimWhitespaces(valueClass))
		} //end if
	} //end if
	//--
	var htmlCode string = ""
	//--
	var src string = ""
	var srcSet string = ""
	var dataSrc string = ""
	//--
	if(alternateImgSrc != "") {
		//--
		var htmlAttrId string = ""
		if(mediaId != "") {
			htmlAttrId = ` id="` + EscapeHtml(mediaId) + `"`
		} //end if
		//--
		var htmlAttrTitle string = ""
		if(mediaTitle != "") {
			htmlAttrTitle = ` title="` + m.renderAltOrTitle(mediaTitle) + `"`
		} //end if
		//--
		htmlCode += `<picture` + htmlAttrId + htmlAttrTitle + m.buildAttributeData(atts, nil) + `>`
		//--
		if(useLazyLoad) {
			srcSet = ""
			dataSrc = alternateImgSrc
		} else {
			srcSet = alternateImgSrc
			dataSrc = ""
		} //end if else
		//--
		var htmlAttrType string = ""
		if(alternateImgType != "") {
			htmlAttrType = ` type="` + EscapeHtml(alternateImgType) + `"`
		} //end if
		//--
		var htmlAttrDataSrc string = ""
		if(dataSrc != "") {
			htmlAttrDataSrc = ` data-src="` + EscapeHtml(dataSrc) + `"`
		} //end if
		//--
		htmlCode += `<source` + m.buildAttributeData(atts, nil) + htmlAttrType + ` srcset="` + EscapeHtml(srcSet) + `"` + htmlAttrDataSrc + `>`
		//--
	} //end if else
	//--
	if(useLazyLoad) {
		if(m.lazyLoadImgDefault != "") {
			src = StrTrimWhitespaces(m.lazyLoadImgDefault)
		} else {
			src = ""
		} //end if
		dataSrc = mediaSrc
	} else {
		src = mediaSrc
		dataSrc = ""
	} //end if else
	//--
	var htmlAttrImgId string = ""
	if((mediaId != "") && (alternateImgSrc == "")) {
		htmlAttrImgId = ` id="` + EscapeHtml(mediaId) + `"`
	} //end if
	//--
	var htmlAttrImgAlt string = ""
	if(mediaAltTxt != "") {
		htmlAttrImgAlt = ` alt="` + m.renderAltOrTitle(mediaAltTxt) + `"`
	} //end if
	//--
	var htmlAttrImgTitle string = ""
	if(mediaTitle != "") {
		htmlAttrImgTitle = ` title="` + m.renderAltOrTitle(mediaTitle) + `"`
	} //end if
	//--
	var htmlAttrImgDataSrc string = ""
	if(dataSrc != "") {
		htmlAttrImgDataSrc = ` data-src="` + EscapeHtml(dataSrc) + `"`
	} //end if
	//--
	htmlCode += `<img` + htmlAttrImgId + htmlAttrImgAlt + htmlAttrImgTitle + m.buildAttributeData(atts, nil) + ` src="` + EscapeHtml(src) + `"` + htmlAttrImgDataSrc + `>`
	//--
	if(alternateImgSrc != "") {
		htmlCode += `</picture>`
	} //end if
	//--
	return htmlCode
	//--
} //END FUNCTION


func (m *SMarkdownParser) renderLinksAndMedia(txt string, noLinks bool) string {
	//--
	defer PanicHandler()
	//--
	// in PHP default value for noLinks is FALSE
	//--
	var trimmedTxt string = StrTrimWhitespaces(txt)
	if(trimmedTxt == "") {
		return EscapeHtml(txt) // empty string or just spaces ; escape for safety
	} //end if
	//--
	var isLink bool = false // circular reference protection
	if(noLinks != true) {
		if(StrStartsWith(trimmedTxt, "[")) { // {{{SYNC-MKDW-DETECT-LINK-START}}} ; expects: [anchor-id](#) ; [](#){L: #anchor-id} ; [](#){L: @id=anchor-id} ; [Text](http://url.link) ; [Text](http://url.link "Title goes here...") {L: .ux-button #the-id} ; [![Alternate Text](wpub/path-to/image.svg.gif.png.jpg.webp "Image Title")](http://url.link) {I:@width=256 @height=256} {L:@data-slimbox=slimbox} ; [![Alternate Text](wpub/path-to/image.svg.gif.png.jpg.webp "Image Title"){I:@width=256 @height=256}](http://url.link){L:@data-slimbox=slimbox}
			isLink = true
		} //end if
	} //end if else
	//--
	var isMedia bool = false
	if(StrStartsWith(trimmedTxt, "![")) { // {{{SYNC-MKDW-DETECT-MEDIA-START}}}  ; expects: ![Alternate Text](wpub/path-to/image.svg.gif.png.jpg.webp "Image Title") {I:@width=256 @height=256}
		isMedia = true
	} //end if
	//--
	trimmedTxt = "" // free mem
	//--
	var arr []string = []string{}
	//--
	if(isLink == true) { // is link or media
		//--
		arr = m.getInlineLink(txt)
		if(len(arr) != 3) {
			log.Println("[WARNING]", "Inline Link Regex Length must be 3", txt)
			return EscapeHtml(txt) // invalid media
		} //end if
		arx := ExplodeWithLimit(`"`, arr[2], 3)
		arr[2] = StrTrimWhitespaces(arx[0])
		var theTitle string = ""
		if(len(arx) > 1) {
			theTitle = StrTrimWhitespaces(arx[1])
		} //end if
		arr = append(arr, theTitle)
		//--
	} else if(isMedia == true) { // is media
		//--
		arr = m.getInlineMedia(txt)
		if(len(arr) != 3) {
			log.Println("[WARNING]", "Inline Media Regex Length must be 3", txt)
			return EscapeHtml(txt) // invalid media
		} //end if
		arx := ExplodeWithLimit(`"`, arr[2], 3)
		arr[2] = StrTrimWhitespaces(arx[0])
		var theTitle string = ""
		if(len(arx) > 1) {
			theTitle = StrTrimWhitespaces(arx[1])
		} //end if
		arr = append(arr, theTitle)
		//--
	} else {
		//--
		return EscapeHtml(txt) // not link, not media
		//--
	} //end if else
	//--
	if(len(arr) < 3) { // {{{SYNC-MKDW-MEDIA-LINKS-TITLE-CAN-MISS}}} ; if no title text, there are only 3 elements in the array: 0, 1 and 2
		return EscapeHtml(txt) // something wrong, regex did not found a valid structure ...
	} //end if
	//-- # end sync
	trimmedTxt = StrTrimWhitespaces(arr[0]) // UNSYNC: in PHP was [0][0]
	if(trimmedTxt == "") {
		return EscapeHtml(txt) // empty string or just spaces ; escape for safety
	} //end if
	//--
	isMedia = false
	isLink = false
	if(StrStartsWith(trimmedTxt, "![")) {
		isMedia = true
	} else if(StrStartsWith(trimmedTxt, "[")) {
		isLink = true
	} //end if
	//--
	trimmedTxt = "" // free mem
	//--
	if(isMedia == true) { // is media ; process first because links can also contain media
		//--
		renderedHtml := m.renderHtmlMediaOnly(arr, txt) // do not cast ; it is mixed ; can be null if the media was wrong or string if rendered
		if(renderedHtml == "") {
			return EscapeHtml(txt) // invalid media ; could not render the media html code
		} //end if
		//--
		return renderedHtml
		//--
	} else if(isLink == true) { // is link ; process second ; links can contain also media
		//--
		renderedHtml := m.renderHtmlLinkOnly(arr, txt) // do not cast ; it is mixed ; can be null if the media was wrong or string if rendered
		if(renderedHtml == "") {
			return EscapeHtml(txt) // invalid media ; could not render the media html code
		} //end if
		//--
		return renderedHtml
		//--
	} //end if
	//--
	return EscapeHtml(txt) // unknown error ; escape for safety
	//--
} //END FUNCTION


//-----


func (m *SMarkdownParser) getListEntryLevelByLeadingSpaces(leadingSpaces string) int {
	//--
	defer PanicHandler()
	//--
	if(leadingSpaces == "") {
		return 0
	} //end if
	//--
	if(len(leadingSpaces) == 1) {
		return 1
	} //end if
	//--
	leadingSpaces = StrReplaceAll(leadingSpaces, "    ", "\t") // replace 4 spaces with tab
	leadingSpaces = StrReplaceAll(leadingSpaces, "   ",  "\t") // replace 3 spaces with tab
	leadingSpaces = StrReplaceAll(leadingSpaces, "  ",   "\t") // replace 2 spaces with tab
	leadingSpaces = StrReplaceAll(leadingSpaces, " ",    "\t") // replace 1 space  with tab
	//--
	var leadingNumSpaces int = len(leadingSpaces)
	if(leadingNumSpaces < 0) {
		leadingNumSpaces = 0
	} else if(leadingNumSpaces > 7) { // {{{SYNC-MKDW-LISTS-MAX-LEVELS}}}
		leadingNumSpaces = 7 // max 8 levels
	} //end if
	//--
	return leadingNumSpaces
	//--
} //END FUNCTION


func (m *SMarkdownParser) convertDefListArrToNestedArr(defArrLists []mkdwDefListStruct, level int, position int) ([]mkdwDefListStruct, int) {
	//--
	defer PanicHandler()
	//--
	if((defArrLists == nil) || (len(defArrLists) <= 0)) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Def List is Null or Empty")
		return nil, 0
	} //end if
	if(level < 0) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Level is Negative")
		return nil, 0
	} //end if
	if(position < 0) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Position is Negative")
		return nil, 0
	} else if(position > len(defArrLists)) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Position is Higher than List Size")
		return nil, 0
	} //end if else
	//--
	var nestedList []mkdwDefListStruct = nil
	//--
	max := len(defArrLists)
	var delta int = 0
	for i:=position; i<max; i++ {
		//--
		listEntry := defArrLists[i]
		//--
		if(listEntry.Level == level) {
			nestedList = append(nestedList, listEntry)
		} else if(listEntry.Level == (level+1)) {
			if(i > 0) {
				if(len(nestedList) > 0) {
					prevIndex := len(nestedList) - 1
					childs, subDelta := m.convertDefListArrToNestedArr(defArrLists, listEntry.Level, i)
					nestedList[prevIndex].Childs = append(nestedList[prevIndex].Childs, childs)
					if(subDelta > 0) {
						i += subDelta
						delta += subDelta
					} //end if
				} //end if
			} //end if
		} else {
			if(level > 0) {
				break
			} //end if
		} //end if
		//--
		delta++
		//--
	} //end for
	//--
	return nestedList, delta-1
	//--
} //END FUNCTION



func (m *SMarkdownParser) renderListNode(nestedList []mkdwDefListStruct, level int) string {
	//--
	defer PanicHandler()
	//--
	if((nestedList == nil) || (len(nestedList) <= 0)) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Nested List is Null or Empty")
		return ""
	} //end if
	if(level < 0) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Level is Negative")
		return ""
	} //end if
	//--
	var htmlCode string = ""
	//--
	var listType string = ""
	var listEntry mkdwDefListStruct
	for i:=0; i<len(nestedList); i++ {
		//--
		listEntry = nestedList[i]
		//--
		if(listType == "") {
			listType = listEntry.Type
			htmlCode += "\n" + StrRepeat("\t", level) + `<` + m.escapeValidHtmlTagName(listEntry.Type) + `>` + "\n"
		} //end if
		//--
		htmlCode += StrRepeat("\t", level + 1) + `<li>`
		htmlCode += m.createHtmlInline(listEntry.Code, "li", false)
		if(len(listEntry.Extra) > 0) {
			htmlCode += Implode("\n", listEntry.Extra)
		} //end if
		//--
		if(len(listEntry.Childs) > 0) {
			var childs []mkdwDefListStruct
			var okChilds bool = false
			for j:=0; j<len(listEntry.Childs); j++ {
				childs, okChilds = listEntry.Childs[j].([]mkdwDefListStruct)
				if(okChilds) {
					htmlCode += m.renderListNode(childs, listEntry.Level+1)
				} else {
					log.Println("[WARNING]", CurrentFunctionName(), "Failed to Map Interface to Struct on object #", i, "@", j, "; level:", level)
				} //end if else
			} //end for
		} //end if
		//--
		htmlCode += StrRepeat("\t", level + 1) + `</li>` + "\n"
		//--
	} //end for
	//--
	if(htmlCode != "") {
		if(listType != "") {
			htmlCode += StrRepeat("\t", level) + `</` + m.escapeValidHtmlTagName(listType) + `>` + "\n"
		} //end if
	} //end if
	//--
	return htmlCode
	//--
} //END FUNCTION


func (m *SMarkdownParser) renderDefListArrToHtml(defArrLists []mkdwDefListStruct, level int) string {
	//--
	defer PanicHandler()
	//--
	if((defArrLists == nil) || (len(defArrLists) <= 0)) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Def List is Null or Empty")
		return ""
	} //end if
	if(level < 0) {
		log.Println("[WARNING]", CurrentFunctionName(), "# Level is Negative")
		return ""
	} //end if
	//--
	//log.Println("[DATA]", "defArrLists", defArrLists)
	nesterArrList, _ := m.convertDefListArrToNestedArr(defArrLists, 0, 0)
	//log.Println("[DATA]", "nesterArrList", nesterArrList)
	//--
	return m.renderListNode(nesterArrList, level)
	//--
} //END FUNCTION


func (m *SMarkdownParser) getListEntryArr(lineEntry string) (matchListUlEntry []string, matchListOlEntry []string) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(lineEntry) == "") {
		return
	} //end if
	//--
	var isUL bool = StrRegexMatch(mkdwPatternListUL, lineEntry)
	//--
	var isOL bool = false
	if(!isUL) {
		isOL = StrRegexMatch(mkdwPatternListOL, lineEntry)
	} //end if
	//--
	var err error
	if(isUL) {
		matchListUlEntry, err = StrRegexFindFirstMatch(mkdwPatternListUL, lineEntry)
		if(err != nil) {
			log.Println("[WARNING]", CurrentFunctionName(), "# (UL) ERR:", err)
			matchListUlEntry = []string{}
		} //end if
	} else if(isOL) {
		matchListOlEntry, err = StrRegexFindFirstMatch(mkdwPatternListOL, lineEntry)
		if(err != nil) {
			log.Println("[WARNING]", CurrentFunctionName(), "# (OL) ERR:", err)
			matchListUlEntry = []string{}
		} //end if
	} //end if
	//--
	return
	//--
} //END FUNCTION


//-----


type mkdwDefTableStruct struct {
	Line   int
	Cells  int
	Rows   int
	Aligns map[int]string
	Defs   map[string]string
}

type mkdwDefListStruct struct {
	Level  int
	Type   string
	Code   string
	Extra  []string
	Childs []interface{}
}

func (m *SMarkdownParser) renderDocument(txt string) string {
	//-- panic handler
	defer PanicHandler()
	//-- 0: init
	m.initDefinitionData(true) // init, clear
	//-- 1st annd surrounding LF
	txt = "\n" + txt + "\n" // required for pattern matching and flushing of last line data buffered previous
	//-- 2nd extract code blocks to be preserved and replace them with placeholders
	m.definitionData["extracted"]["code"] = m.arrStringDataToMap(m.getDataBlockCodes(txt))
	txt = m.getTextWithPlaceholders(txt, "code", m.definitionData["extracted"]["code"])
	//-- 3rd extract links, links with media, media ; after extract+convert code blocks, after extracting code blocks and inline code, but prior to extract pre-formats ; pre-formats may contain media
	// MUST BE BEFORE INLINE CODE to avoid rendering a portion of an media or link title that contains ```code``` as code {{{SYNC-MKDW-INLINE-CODE-VS-LINKS-MEDIA-ORDER}}}
	m.definitionData["extracted"]["inline-links-and-media"] = m.arrStringDataToMap(m.getDataInlineLinksAndMedia(txt))
	txt = m.getTextWithPlaceholders(txt, "inline-links-and-media", m.definitionData["extracted"]["inline-links-and-media"])
	//-- 4th extract inline code to be preserved and replace them with placeholders !!! keep before pre, pre may contain code !!!
	// MUST BE AFTER INLINE LINKS AND MEDIA to avoid rendering a portion of an media or link title that contains ```code``` as code {{{SYNC-MKDW-INLINE-CODE-VS-LINKS-MEDIA-ORDER}}}
	m.definitionData["extracted"]["inline-code"] = m.arrStringDataToMap(m.getDataInlineCodes(txt))
	txt = m.getTextWithPlaceholders(txt, "inline-code", m.definitionData["extracted"]["inline-code"])
	//-- 5th extract pre blocks to be preserved and replace them with placeholders
	m.definitionData["extracted"]["mpre"] = m.arrStringDataToMap(m.getDataBlockMPreformats(txt))
	txt = m.getTextWithPlaceholders(txt, "mpre", m.definitionData["extracted"]["mpre"])
	m.definitionData["extracted"]["pre"] = m.arrStringDataToMap(m.getDataBlockPreformats(txt))
	txt = m.getTextWithPlaceholders(txt, "pre", m.definitionData["extracted"]["pre"])
	//-- 6th process line by line
	arr := Explode("\n", txt)
	txt = "" // free mem
	//--
	var lineRenderCrr   bool = true // go: supply missing PHP feature to set arr[i]   to null in order to skip rendering on that cycle
	var lineRenderNext  bool = true // go: supply missing PHP feature to set arr[i]   to null in order to skip rendering on that cycle
	var lineNext string = ""
	var lineIsUnparsed bool = true
	var lineLast bool = false
	var isBlockquote bool = false
	var isDiv bool = false
	var isSDiv bool = false
	var isSection bool = false
	var isArticle bool = false
	var isList bool = false
	//--
	var defArrTable  *mkdwDefTableStruct = nil
	var defArrLists []mkdwDefListStruct  = nil
	//--
	var max int = len(arr)
	for i:=0; i<max; i++ {
		//--
		isList = false
		//--
		lineNext = ""
		lineLast = false // not last line
		lineIsUnparsed = true
		if(i == (max - 1)) { // last
			lineLast = true // it is the last line
		} else {
			lineNext = arr[i+1] // string
		} //end if else
		//--
		lineRenderCrr = true
		if(lineRenderNext != true) {
			//--
			// skip explicit non-render lines
			//--
			lineRenderNext = true // reset
			//--
		} else if(StrStartsWith(arr[i], "\\") && (StrTrimWhitespaces(arr[i]) == "\\")) {
			//--
			if(m.sBreakEnabled) {
				arr[i] = `<br>`
			} else {
				arr[i] = ""
			} //end if else
			//--
		} else {
		//======= Empty or Spaces Only Line: Render Lists / Reset Tables
			//--
			if((lineLast == true) || (StrTrimWhitespaces(arr[i]) == "")) { // last line or an empty line
				if(defArrLists != nil) {
					arr[i] = m.renderDefListArrToHtml(defArrLists, 0) + "\n" // close the list
					lineIsUnparsed = false
					defArrLists = nil // fix: reset it on each line that is not a list
				} //end if
			} //end if
			//--
			if(!StrStartsWith(arr[i], "|")) { // not table ; {{{SYNC-MKWD-CONDITION-TABLE-LINE}}}
				defArrTable = nil // fix: reset it on each line that is not a table
			} //end if
			//--
			if(lineIsUnparsed != true) {
				//--
				// skip, already rendered above
				//--
			} else if(StrTrimWhitespaces(arr[i]) == "") { // {{{SYNC-MKWD-EMPTY-LINE}}} empty or spaces only line ; used to reset some parsing data
				//-- br (must be at the end, it checks if the line is still empty after above flushes
				if((StrTrimWhitespaces(lineNext) == "") && (lineLast == false) && (StrTrimWhitespaces(arr[i]) == "")) {
					arr[i] = `<br>` + "\n"
					lineIsUnparsed = false
				} //end if
				//--
		//======= Blockquote
			} else if(StrStartsWith(arr[i], "<<<")) { // blockquote
				//--
				if(isBlockquote == true) { // close blockquote
					//--
					isBlockquote = false
					//--
				//	arr[i] = `</blockquote>` + `<br>` + "\n" // {{{SYNC-MKDW-ENDTAG-BLOCKQUOTE}}}
					arr[i] = `</blockquote>` + "\n" // {{{SYNC-MKDW-ENDTAG-BLOCKQUOTE}}}
					lineIsUnparsed = false
					//--
				} else { // open blockquote
					//--
					isBlockquote = true
					//--
					theAtts := m.parseAttributeData("blockquote", StrTrimLeft(arr[i], "<"))
					//--
					var htmlAttId string = ""
					valAttId, existsAttId := theAtts["id"]
					if(existsAttId && (valAttId != "")) {
						htmlAttId = ` id="` + EscapeHtml(valAttId) + `"`
					} //end if
					//--
					var htmlAttClass string = ""
					valAttClass, existsAttClass := theAtts["class"]
					if(existsAttClass && (valAttClass != "")) {
						htmlAttClass = ` class="` + EscapeHtml(valAttClass) + `"`
					} //end if
					//--
					arr[i] = `<blockquote` + htmlAttId + htmlAttClass + m.buildAttributeData(theAtts, map[string]bool{ "id" : false, "class" : false }) + `>` // do not parse inline: id, class
					lineIsUnparsed = false
					//--
					theAtts = nil
					//--
				} //end if else
				//--
		//======= Div
			} else if(StrStartsWith(arr[i], ":::") && !StrStartsWith(arr[i], "::::")) { // div
				//--
				if(isDiv == true) { // close div
					//--
					isDiv = false
					//--
					arr[i] = `</div>` + "\n" // {{{SYNC-MKDW-ENDTAG-DIV}}}
					lineIsUnparsed = false
					//--
				} else { // open div
					//--
					isDiv = true
					//--
					theAtts := m.parseAttributeData("div", StrTrimLeft(arr[i], ":"))
					//--
					var htmlAttId string = ""
					valAttId, existsAttId := theAtts["id"]
					if(existsAttId && (valAttId != "")) {
						htmlAttId = ` id="` + EscapeHtml(valAttId) + `"`
					} //end if
					//--
					var htmlAttClass string = ""
					valAttClass, existsAttClass := theAtts["class"]
					if(existsAttClass && (valAttClass != "")) {
						htmlAttClass = ` class="` + EscapeHtml(valAttClass) + `"`
					} //end if
					//--
					arr[i] = `<div` + htmlAttId + htmlAttClass + m.buildAttributeData(theAtts, map[string]bool{ "id" : false, "class" : false }) + `>` // do not parse inline: id, class
					lineIsUnparsed = false
					//--
					theAtts = nil
					//--
				} //end if else
				//--
		//======= Sub-Div (it is needed to allow insert a div in another div because in markdown elements can't be nested if they are the same type)
			} else if(StrStartsWith(arr[i], "::::")) { // sub-div
				//--
				if(isSDiv == true) { // close sub-div
					//--
					isSDiv = false
					//--
					arr[i] = `</div><!-- /sdiv -->` + "\n" // {{{SYNC-MKDW-ENDTAG-SUBDIV}}}
					lineIsUnparsed = false
					//--
				} else { // open sub-div
					//--
					isSDiv = true
					//--
					theAtts := m.parseAttributeData("div", StrTrimLeft(arr[i], ":"))
					//--
					var htmlAttId string = ""
					valAttId, existsAttId := theAtts["id"]
					if(existsAttId && (valAttId != "")) {
						htmlAttId = ` id="` + EscapeHtml(valAttId) + `"`
					} //end if
					//--
					var htmlAttClass string = ""
					valAttClass, existsAttClass := theAtts["class"]
					if(existsAttClass && (valAttClass != "")) {
						htmlAttClass = ` class="` + EscapeHtml(valAttClass) + `"`
					} //end if
					//--
					arr[i] = `<!-- sdiv --><div` + htmlAttId + htmlAttClass + m.buildAttributeData(theAtts, map[string]bool{ "id" : false, "class" : false }) + `>` // do not parse inline: id, class
					lineIsUnparsed = false
					//--
					theAtts = nil
					//--
				} //end if else
				//--
		//======= Section
			} else if(StrStartsWith(arr[i], ";;;") && !StrStartsWith(arr[i], ";;;;")) { // section
				//--
				if(isSection == true) { // close section
					//--
					isSection = false
					//--
					arr[i] = `</section>` + "\n" // {{{SYNC-MKDW-ENDTAG-SECTION}}}
					lineIsUnparsed = false
					//--
				} else { // open section
					//--
					isSection = true
					//--
					theAtts := m.parseAttributeData("section", StrTrimLeft(arr[i], ";"))
					//--
					var htmlAttId string = ""
					valAttId, existsAttId := theAtts["id"]
					if(existsAttId && (valAttId != "")) {
						htmlAttId = ` id="` + EscapeHtml(valAttId) + `"`
					} //end if
					//--
					var htmlAttClass string = ""
					valAttClass, existsAttClass := theAtts["class"]
					if(existsAttClass && (valAttClass != "")) {
						htmlAttClass = ` class="` + EscapeHtml(valAttClass) + `"`
					} //end if
					//--
					arr[i] = `<section` + htmlAttId + htmlAttClass + m.buildAttributeData(theAtts, map[string]bool{ "id" : false, "class" : false }) + `>` // do not parse inline: id, class
					lineIsUnparsed = false
					//--
					theAtts = nil
					//--
				} //end if else
				//--
		//======= Article
			} else if(StrStartsWith(arr[i], ";;;;")) { // article (sub-section)
				//--
				if(isArticle == true) { // close article
					//--
					isArticle = false
					//--
					arr[i] = `</article>` + "\n" // {{{SYNC-MKDW-ENDTAG-ARTICLE}}}
					lineIsUnparsed = false
					//--
				} else { // open article
					//--
					isArticle = true
					//--
					theAtts := m.parseAttributeData("article", StrTrimLeft(arr[i], ";"))
					//--
					var htmlAttId string = ""
					valAttId, existsAttId := theAtts["id"]
					if(existsAttId && (valAttId != "")) {
						htmlAttId = ` id="` + EscapeHtml(valAttId) + `"`
					} //end if
					//--
					var htmlAttClass string = ""
					valAttClass, existsAttClass := theAtts["class"]
					if(existsAttClass && (valAttClass != "")) {
						htmlAttClass = ` class="` + EscapeHtml(valAttClass) + `"`
					} //end if
					//--
					arr[i] = `<article` + htmlAttId + htmlAttClass + m.buildAttributeData(theAtts, map[string]bool{ "id" : false, "class" : false }) + `>` // do not parse inline: id, class
					lineIsUnparsed = false
					//--
					theAtts = nil
					//--
				} //end if else
				//--
		//======= Horizontal Rule # need to be detected before lists !!
			} else if(InListArr(StrSubstr(arr[i], 0, 5), []string{"- - -", "* * *"})) { // hr
				//--
				arr[i] = `<hr>` + "\n"
				lineIsUnparsed = false
				//--
		//======= Lists ul / ol
			} else if matchListUlEntry, matchListOlEntry := m.getListEntryArr(arr[i]); (len(matchListUlEntry) > 1 || len(matchListOlEntry) > 1) { // lists: ul / ol ; {{{SYNC-MKWD-CONDITION-LIST-LINE}}}
				//--
				var listType string = ""
				var listLevel int   = -1
				var listCode string = ""
				//-- max 8 levels // {{{SYNC-MKDW-LISTS-MAX-LEVELS}}}
				if(len(matchListUlEntry) > 1) { // is UL
					isList    = true
					listType  = "ul"
					listLevel = m.getListEntryLevelByLeadingSpaces(matchListUlEntry[1])
					listCode  = StrTrimLeftWhitespaces(StrSubstr(StrTrimLeftWhitespaces(arr[i]), 1, 0))
				} else if(len(matchListOlEntry) > 1) { // is OL
					isList    = true;
					listType  = "ol"
					listLevel = m.getListEntryLevelByLeadingSpaces(matchListOlEntry[1])
					listCode = StrTrimLeftWhitespaces(StrRegexReplaceFirst(`^[0-9]+[\.\)]{1}`, StrTrimLeftWhitespaces(arr[i]), ""))
				} //end if
				//--
				if((isList == true) && (listLevel >= 0) && (listType != "")) {
					//--
					defEntryArrList := mkdwDefListStruct {
						Level: listLevel,
						Type:  listType,
						Code:  listCode,
						Extra: []string{},
					}
					defArrLists = append(defArrLists, defEntryArrList)
					//--
					arr[i] = "" // avoid display now, will be done later
					lineIsUnparsed = false
					//--
				} // end if
				//--
		//======= Table
			} else if(StrStartsWith(arr[i], "|")) { // table ; {{{SYNC-MKWD-CONDITION-TABLE-LINE}}}
				//--
				arr[i] = StrReplaceAll(arr[i], "\\|", mkdwSpecialCharTableSepMark) // {{{SYNC-MKDW-TABLE-CELL-VBAR-FIX}}} ; fix: if a cell have to contain a vertical bar, make a special replacement
				//--
				cells := Explode("|", arr[i])
				var paligns map[int]string = map[int]string{}
				var aligns  []string = []string{}
				var mcells int = len(cells) - 2 // is is 1st line, use real
				var tblLineDiscarded bool = false
				//--
				if(defArrTable != nil) {
					if(defArrTable.Cells < mcells) {
						defArrTable.Cells = mcells // fix back, cells number is larger than previous
					} else {
						mcells = defArrTable.Cells // use the max cells from defs, 1st line
					} //end if else
				} //end if else
				if(mcells > 0) {
					if(defArrTable == nil) {
						if(lineLast == false) { // look ahead for table aligns
							if(StrStartsWith(lineNext, "|")) { // table align defs
								aligns = Explode("|", lineNext)
								if((len(aligns)-2) >= 0) {
									var pa int = 0
									for a:=1; a<len(aligns)-1; a++ {
										aligns[a] = StrTrimWhitespaces(aligns[a])
										if(StrTrim(aligns[a], ":-") == "") {
											paligns[pa] = ""
											if(StrStartsWith(aligns[a], ":-")) {
												if(paligns[pa] == "") {
													paligns[pa] = "left"
												} else {
													paligns[pa] = "center"
												} //end if else
											} //end if
											if(StrEndsWith(aligns[a], "-:")) {
												if(paligns[pa] == "") {
													paligns[pa] = "right"
												} else {
													paligns[pa] = "center"
												} //end if else
											} //end if
										} else if(StrTrim(aligns[a], "-") == "") {
											paligns[pa] = ""
										} else { // error, invalid aligns
											paligns = map[int]string{}
											break
										} //end if else
										pa++
									} //end for
								} //end if
							} //end if
							if(len(paligns) > 0) {
								if(lineLast != true) {
									arr[i+1] = "" // discard the 2nd table line with aligns ; it should be existing, above it is tested as should not be the last line
									lineNext = "" // bugfix: if the last table row is the one with aligns because this line was missing in the past it was not closing the table ! it is logic that if the above line is reset also this test line which is the reference of next line should reset as this is tested in a table before the alignements line and will not impact other things !
								} //end if
								lineRenderNext = false
								tblLineDiscarded = true // bugfix: {{{SYNC-MKWD-CONDITION-TABLE-LINE}}}
							} //end if
						} //end if
					} else {
						paligns = defArrTable.Aligns
						arr[i] = "\t" + `<tr>` + "\n"
						lineIsUnparsed = false
					} //end if
					var isTableInit bool = false
					if(defArrTable != nil) {
						isTableInit = true
					} //end if
					var isTableFullWidth bool = true
					var tblHeadAlign string = ""
					var tblHeadUseTd bool = false
					for c:=1; c<len(cells)-1; c++ {
						cells[c] = StrReplaceAll(cells[c], mkdwSpecialCharTableSepMark, "|") // {{{SYNC-MKDW-TABLE-CELL-VBAR-FIX}}} ; fix back
						if(defArrTable == nil) {
							if(c == 1) {
								//--
								isTableInit = true
								hcellTxt, tblDefs := m.parseTableAttributes(cells[c])
								cells[c] = hcellTxt
								var tblClasses []string = []string{}
								var tblId string = ""
								//--
								for hd:=0; hd<len(tblDefs); hd++ {
									var upperDefCrr string = StrToUpper(tblDefs[hd])
									if(StrStartsWith(tblDefs[hd], ".")) { // table classes
										var tmpTblClass string = StrTr(tblDefs[hd], map[string]string{ // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
											"." : "",
											"#" : "",
										})
										if(!InListArr(tmpTblClass, tblClasses)) {
											tblClasses = append(tblClasses, tmpTblClass)
										} //end if
									} else if(StrStartsWith(tblDefs[hd], "#")) { // table id
										tblId = StrTr(tblDefs[hd], map[string]string{ // ok: order does not matter ; {{{SYNC-GOLANG-UNORDERED-MAP}}}
											"." : "",
											"#" : "",
										})
									} else if(upperDefCrr == "AUTO-WIDTH") {
										isTableFullWidth = false
									} else if(upperDefCrr == "ALIGN-HEAD-LEFT") {
										tblHeadAlign = "left"
									} else if(upperDefCrr == "ALIGN-HEAD-CENTER") {
										tblHeadAlign = "center"
									} else if(upperDefCrr == "ALIGN-HEAD-RIGHT") {
										tblHeadAlign = "right"
									} else if(upperDefCrr == "ALIGN-HEAD-AUTO") { // if numeric, will align to right otherwise to left
										if(IsNumeric(StrTrimWhitespaces(hcellTxt), true)) {
											tblHeadAlign = "right"
										} else {
											tblHeadAlign = "center"
										} //end if else
									} else if(upperDefCrr == "NO-TABLE-HEAD") {
										tblHeadUseTd = true
									} //end if else
								} //end for
								//--
								if(isTableFullWidth != false) { // by default tables are full width
									if(!InListArr("full-width-table", tblClasses)) {
										tblClasses = append(tblClasses, "full-width-table")
									} //end if
								} //end if
								//--
								var htmlAttId string = ""
								if(tblId != "") {
									htmlAttId = ` id="` + EscapeHtml(tblId) + `"`
								} //end if
								//--
								var htmlAttClass string = ""
								if(len(tblClasses) > 0) {
									htmlAttClass = ` class="` + EscapeHtml(Implode(" ", tblClasses)) + `"`
								} //end if
								//--
								arr[i] = `<table` + htmlAttId + htmlAttClass + `>` + "\n" + "\t" + `<tr>` + "\n" // ids and classes must not be parsed inline
								lineIsUnparsed = false
								//--
								tblId = ""
								tblClasses = []string{}
								//--
							} //end if
						} //end if
						cellTxt, cellAtts := m.parseElementAttributes(cells[c], "td")
						var cellElem string = "td"
						if(defArrTable == nil) {
							if(tblHeadUseTd != true) {
								cellElem = "th"
							} //end if
						} //end if
						var cellAlign string = ""
						if(tblHeadAlign != "") {
							cellAlign = tblHeadAlign
						} else {
							if(len(paligns) > (c-1)) { // PHP condition was: isset($paligns[$c-1])
								if(paligns[c-1] != "") {
									cellAlign = paligns[c-1]
								} //end if
							} //end if
						} //end if else
					//	if(cells[c] != "") { // bugfix (realm=javascript&key=3) it appears that also with empty cell and colspans the cell must be rendered ...  ; previous assumption was: if cell is empty, that is intentional to solve the issue with collspans, so do not render that cell
						var htmlAttStyle string = ""
						if(cellAlign != "") {
							htmlAttStyle = ` style="text-align:` + EscapeHtml(cellAlign) + `;"`
						} //end if
						var htmlCellContent string = ""
						cellTxt = StrTrimWhitespaces(cellTxt)
						if(cellTxt != "") {
							htmlCellContent = m.createHtmlInline(cellTxt, "td", false)
						} //end if
						if(StrTrimWhitespaces(htmlCellContent) == "") {
							htmlCellContent = "&nbsp;"
						} //end if
						arr[i] += "\t" + "\t" + `<` + m.escapeValidHtmlTagName(cellElem) + m.buildAttributeData(cellAtts, nil) + htmlAttStyle + `>` + htmlCellContent + `</` + m.escapeValidHtmlTagName(cellElem) + `>` + "\n" // do not parse inline attributes
						lineIsUnparsed = false;
					//	} //end if
						cellTxt = ""
						cellAtts = nil
						cellAlign = ""
					} //end for
					tblHeadUseTd = false
					tblHeadAlign = ""
					//--
					if(isTableInit == true) {
						//--
						arr[i] += "\t" + `</tr>` + "\n"
						lineIsUnparsed = false
						//--
						if(defArrTable == nil) { // table can be init but def table null at this point, if first line, thus export settings for next loops
							//--
							defArrTable = &mkdwDefTableStruct{ // init here, above next if, and do not unify with an else, must go separately, with a separate condition
								Line 	: i,
								Cells	: mcells,
								Rows 	: 1,
								Aligns 	: paligns,
								Defs 	: map[string]string{},
							}
							//--
						} //end if
						//--
						defArrTable.Rows++
						//--
						if(((lineLast == true)) ||
							((tblLineDiscarded == true) && (i < max) && (!StrStartsWith(arr[i+2], "|"))) || // {{{SYNC-MKWD-CONDITION-TABLE-LINE}}}
							((tblLineDiscarded != true) && (!StrStartsWith(lineNext, "|")))) { // {{{SYNC-MKWD-CONDITION-TABLE-LINE}}}
							arr[i] += `</table>` + "\n" // must close table here if next line is not part of a table to avoid collide with other elements ex: blockquotes
							lineIsUnparsed = false
							defArrTable = nil // reset
						} //end if
						//--
					} //end if
					//--
					isTableInit = false
					isTableFullWidth = true
					//--
				} //end if else
				//--
				cells = nil
				mcells = 0
				paligns = nil
				aligns = nil
				tblLineDiscarded = false
				//--
			} //end if else (end table)
			//-- DEFAULT ; OTHER CASES: special markers: keep as they are ; parse alt headers and reset below line ; for the rest, apply html escape + parse inline
			if(lineIsUnparsed == true) {
				renderCrr, clearNext := m.renderLineDefault(arr[i], lineNext)
				arr[i] = renderCrr
				lineIsUnparsed = false
				if(lineLast == false) {
					if(clearNext != false) { // avoid rewrite next line if not modified
						arr[i+1] = ""
						lineRenderNext = false
					} //end if
				} //end if
				renderCrr = "" // free mem
				//--
			} //end if
			//--
		} //end if else
		//--
		if(lineRenderCrr == true) {
			if(defArrLists != nil) {
				if(isList != true) { // collect what's inside a list but non-list, for the case not a list but considered inside a list until first empty line
					if(StrTrimWhitespaces(arr[i]) != "") {
						var maxDefLists int = len(defArrLists)
						if(maxDefLists > 0) {
							maxDefLists -= 1 // get real index
							defArrLists[maxDefLists].Extra = append(defArrLists[maxDefLists].Extra, arr[i])
							arr[i] = "" // avoid display, it was collected as part of a list
							lineIsUnparsed = false
						} //end if
					} //end if else
				} //end if else
				arr[i] = "" // avoid display now, is part of a list
				lineIsUnparsed = false
			} //end if
		} //end if
		//--
		if(lineRenderCrr == true) { // must use a separate check for null than above !
			txt += arr[i] // add only non-null lines
		} //end if
		//--
	} //end for
	//-- close unclosed (by editor's omission) tags
	if(isBlockquote == true) {
		isBlockquote = false
		txt += `</blockquote>` + `<br>` + "\n" // {{{SYNC-MKDW-ENDTAG-BLOCKQUOTE}}}
		log.Println("[NOTICE]", CurrentFunctionName(), "# Unclosed tag found: BLOCKQUOTE <<<")
	} //end if
	if(isDiv == true) {
		isDiv = false
		txt += `</div>` + "\n" // {{{SYNC-MKDW-ENDTAG-DIV}}}
		log.Println("[NOTICE]", CurrentFunctionName(), "# Unclosed tag found: DIV :::")
	} //end if
	if(isSDiv == true) {
		isSDiv = false
		txt += `</div><!-- /sdiv -->` + "\n" // {{{SYNC-MKDW-ENDTAG-SUBDIV}}}
		log.Println("[NOTICE]", CurrentFunctionName(), "# Unclosed tag found: DIV.SUB ::::")
	} //end if
	if(isSection == true) {
		isSection = false
		txt += `</section>` + "\n" // {{{SYNC-MKDW-ENDTAG-SECTION}}}
		log.Println("[NOTICE]", CurrentFunctionName(), "# Unclosed tag found: SECTION ;;;")
	} //end if
	if(isArticle == true) {
		isArticle = false
		txt += `</article>` + "\n" // {{{SYNC-MKDW-ENDTAG-ARTICLE}}}
		log.Println("[NOTICE]", CurrentFunctionName(), "# Unclosed tag found: ARTICLE ;;;;")
	} //end if
	//--
	arr = nil // free mem
	//-- 7th fix escapings, before render blocks !
	txt = m.fixEscapings(txt)
	//-- 8th render back blocks
	txt = m.setBackTextWithPlaceholders(txt, "mpre")
	txt = m.setBackTextWithPlaceholders(txt, "pre")
	txt = m.setBackTextWithPlaceholders(txt, "inline-code") 			// {{{SYNC-MKDW-INLINE-CODE-VS-LINKS-MEDIA-ORDER}}}
	txt = m.setBackTextWithPlaceholders(txt, "inline-links-and-media") 	// {{{SYNC-MKDW-INLINE-CODE-VS-LINKS-MEDIA-ORDER}}}
	txt = m.fixDecodeUrlEncSyntax(txt)
	txt = m.setBackTextWithPlaceholders(txt, "code")
	//--
	if(StrIContains(txt, `<invalidtag`) || StrIContains(txt, `</invalidtag`)) { // {{{SYNC-MKDW-HTML-TAG-INVALID}}}
		log.Println("[NOTICE]", CurrentFunctionName(), "# Invalid tags found ...")
	} //end if
	//--
	m.initDefinitionData(true) // init, clear
	//--
	return txt
	//--
} //END FUNCTION


//-----


// #end
