
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-present unix-world.org
// r.20260915.2358 :: STABLE
// [ MARKUP ]

// REQUIRE: go 1.24 or later
package smartgo

import (
	"log"

	"bytes"
	"strings"
//	"strconv"
	"html"

	"io"

	uid "github.com/unix-world/smartgo/crypto/uuid"

//	xnethtml "golang.org/x/net/html"
	xnethtml "github.com/unix-world/smartgo/markup/html"

	"github.com/unix-world/smartgo/markup/htmlsanitizer"

	"github.com/unix-world/smartgo/markup/markdown"
	mkparser "github.com/unix-world/smartgo/markup/markdown/parser"
	mkhtml   "github.com/unix-world/smartgo/markup/markdown/html"
	mkast    "github.com/unix-world/smartgo/markup/markdown/ast"
)

const (
	MAX_DOC_SIZE_VALIDATE_HTML 	uint64 = SIZE_BYTES_16M * 4 	// {{{SYNC-HTML-VALIDATOR-MAX-SIZE}}} 	; 64MB
	MAX_DOC_SIZE_MARKDOWN 		uint64 = SIZE_BYTES_16M 		// {{{SYNC-MARKDOWN-MAX-SIZE}}} 		; 16MB
)


//-----


func MarkdownSmartToHTMLRender(mkdwDoc string, urlRelativePrefix string, useUnveil bool, unveilDefaultImage string) (string, error) {
	//--
	defer PanicHandler() // just in case
	//--
	if(mkdwDoc == "") {
		return "<!-- Markdown:empty -->", nil
	} //end if
	if(uint64(len(mkdwDoc)) > MAX_DOC_SIZE_MARKDOWN) { // {{{SYNC-MARKDOWN-MAX-SIZE}}}
		return "<!-- Markdown:oversized -->", nil
	} //end if
	//--
	md, err := NewSMarkdown(true, true, true, useUnveil, unveilDefaultImage, urlRelativePrefix) // ex: unveilDefaultImage: "lib/framework/img/loading-bars.svg"
	if(err != nil) {
		log.Println("[WARNING] Markdown Init Failed:", err)
		return "<!-- Markdown:init.failed.err -->", err
	} //end if
	if(md == nil) {
		log.Println("[WARNING] Markdown Init Failed")
		return "<!-- Markdown:init.failed.null -->", NewError("Markdown Init Failed: Null")
	} //end if
	//-- render
	htmlCode := md.Parse(mkdwDoc)
	//return htmlCode, nil
	//-- sanitizer
	htmlCode, errHtmlSanitizer := HTMLCodeFixSanitize(htmlCode)
	if(errHtmlSanitizer != nil) {
		log.Println("[WARNING] Markdown HTML Sanitized:", errHtmlSanitizer)
		return "<!-- Markdown:html.err-fix.sn -->", errHtmlSanitizer
	} //end if
	if(DEBUG == true) {
		log.Println("[DATA] Markdown HTML Sanitized: ========", htmlCode)
	} //end if
	//-- validator
	htmlCode, errFixHtml := HTMLCodeFixValidate(htmlCode)
	if(errFixHtml != nil) {
		log.Println("[WARNING] Markdown HTML ValidateFixed:", errHtmlSanitizer)
		return "<!-- Markdown:html.err-fix.vd -->", errHtmlSanitizer
	} //end if
	if(DEBUG == true) {
		log.Println("[DATA] Markdown HTML Fixed (Sanitized + Validated): ========", htmlCode)
	} //end if
	//--
	return htmlCode + "<!-- Markdown:html.safe -->", errHtmlSanitizer
	//--
} //END FUNCTION


func SafePathMarkdownSmartFileToHTMLRender(mdFilePath string, allowAbsolutePath bool, urlRelativePrefix string, useUnveil bool, unveilDefaultImage string) (string, error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(mdFilePath) == "") {
		return "<!-- # Markdown.Err:1 -->", NewError("Markdown File # File Path is Empty")
	} //end if
	//--
	mdFilePath = SafePathFixClean(mdFilePath)
	//--
	if(PathIsEmptyOrRoot(mdFilePath) == true) {
		return "<!-- # Markdown.Err:2 -->", NewError("Markdown File # File Path is Empty/Root")
	} //end if
	//--
	if(!StrEndsWith(mdFilePath, ".sf.md")) {
		return "<!-- # Markdown.Err:3 -->", NewError("Markdown File # Invalid File Extension, accepted: .sf.md # `" + mdFilePath + "`")
	} //end if
	//--
	fileSize, errSize := SafePathFileGetSize(mdFilePath, allowAbsolutePath)
	if(errSize != nil) {
		return "", errSize
	} //end if
	if(uint64(fileSize) > MAX_DOC_SIZE_MARKDOWN) { // {{{SYNC-MARKDOWN-MAX-SIZE}}}
		return "<!-- # Markdown.Err:4 -->", NewError("Markdown File # OverSized # `" + mdFilePath + "`")
	} //end if
	//--
	mdData, errRd := SafePathFileRead(mdFilePath, allowAbsolutePath)
	if(errRd != nil) {
		return "<!-- # Markdown.Err:5 -->", NewError("Markdown File # Read Failed `" + mdFilePath + "`: " + errRd.Error())
	} //end if
	if(StrTrimWhitespaces(mdData) == "") {
		return "<!-- # Markdown.Err:6 -->", NewError("Markdown File # Content is Empty `" + mdFilePath + "`")
	} //end if
	//--
	html, err := MarkdownSmartToHTMLRender(mdData, urlRelativePrefix, useUnveil, unveilDefaultImage)
	if(err != nil) {
		return "<!-- # Markdown.Err:7 -->", NewError("Markdown File # Parse ERR: " + err.Error() + " # `" + mdFilePath + "`")
	} //end if
	//--
	return html, nil
	//--
} //END FUNCTION


//-----



func MarkdownToHTMLRender(mkdwDoc string) (string, error) {
	//--
	defer PanicHandler() // just in case
	//--
	if(mkdwDoc == "") {
		return "<!-- Markdown:empty -->", nil
	} //end if
	if(uint64(len(mkdwDoc)) > MAX_DOC_SIZE_MARKDOWN) { // {{{SYNC-MARKDOWN-MAX-SIZE}}}
		return "<!-- Markdown:oversized -->", nil
	} //end if
	//--
	var md []byte = []byte(mkdwDoc)
	//--
//	CommonExtensions = NoIntraEmphasis | Tables | FencedCode | Autolink | Strikethrough | SpaceHeadings | HeadingIDs | BackslashLineBreak | DefinitionLists | MathJax
	//--
	extensions := mkparser.CommonExtensions | mkparser.SuperSubscript | mkparser.HardLineBreak | mkparser.Attributes | mkparser.HeadingIDs // | mkparser.AutoHeadingIDs | mkparser.NoEmptyLineBeforeBlock // create markdown parser with extensions
	p := mkparser.NewWithExtensions(extensions)
	nodes := p.Parse(md)
	//--
	if(DEBUG == true) {
		log.Println("[DEBUG] Markdown Render as HTML")
		log.Println("[DATA] Markdown DOC: ========", mkdwDoc)
		log.Println("[DATA] Markdown AST: ========", mkast.ToString(nodes))
	} //end if
	//--
	htmlFlags := mkhtml.SkipHTML | mkhtml.LazyLoadImages // create HTML renderer with extensions
	opts := mkhtml.RendererOptions{Flags: htmlFlags}
	renderer := mkhtml.NewRenderer(opts)
	//--
	if(renderer == nil) {
		log.Println("[WARNING] Markdown Init Failed")
		return "<!-- Markdown:init.failed -->", NewError("Markdown Init Failed")
	} //end if
	//--
	var htmlCode string = `<div class="markdown" data-type="default">` + "\n" + string(markdown.Render(nodes, renderer)) + "\n" + `</div>`
	//-- #
	if(DEBUG == true) {
		log.Println("[DATA] Markdown HTML: ========", htmlCode)
	} //end if
	//--
	htmlCode, errHtmlSanitizer := HTMLCodeFixSanitize(htmlCode)
	if(errHtmlSanitizer != nil) {
		log.Println("[WARNING] Markdown HTML Sanitized:", errHtmlSanitizer)
		return "<!-- Markdown:html.err-fix.sn -->", errHtmlSanitizer
	} //end if
	if(DEBUG == true) {
		log.Println("[DATA] Markdown HTML Sanitized: ========", htmlCode)
	} //end if
	//--
	htmlCode, errFixHtml := HTMLCodeFixValidate(htmlCode)
	if(errFixHtml != nil) {
		log.Println("[WARNING] Markdown HTML ValidateFixed:", errHtmlSanitizer)
		return "<!-- Markdown:html.err-fix.vd -->", errHtmlSanitizer
	} //end if
	if(DEBUG == true) {
		log.Println("[DATA] Markdown HTML Fixed (Sanitized + Validated): ========", htmlCode)
	} //end if
	//--
	return htmlCode + "<!-- Markdown:html.safe -->", errHtmlSanitizer
	//--
} //END FUNCTION


//-----


func SafePathMarkdownFileToHTMLRender(mdFilePath string, allowAbsolutePath bool) (string, error) {
	//--
	defer PanicHandler()
	//--
	if(StrTrimWhitespaces(mdFilePath) == "") {
		return "<!-- # Markdown.Err:1 -->", NewError("Markdown File # File Path is Empty")
	} //end if
	//--
	mdFilePath = SafePathFixClean(mdFilePath)
	//--
	if(PathIsEmptyOrRoot(mdFilePath) == true) {
		return "<!-- # Markdown.Err:2 -->", NewError("Markdown File # File Path is Empty/Root")
	} //end if
	//--
	if(!StrEndsWith(mdFilePath, ".md")) {
		return "<!-- # Markdown.Err:3 -->", NewError("Markdown File # Invalid File Extension, accepted: .md # `" + mdFilePath + "`")
	} //end if
	//--
	fileSize, errSize := SafePathFileGetSize(mdFilePath, allowAbsolutePath)
	if(errSize != nil) {
		return "", errSize
	} //end if
	if(uint64(fileSize) > MAX_DOC_SIZE_MARKDOWN) { // {{{SYNC-MARKDOWN-MAX-SIZE}}}
		return "<!-- # Markdown.Err:4 -->", NewError("Markdown File # OverSized # `" + mdFilePath + "`")
	} //end if
	//--
	mdData, errRd := SafePathFileRead(mdFilePath, allowAbsolutePath)
	if(errRd != nil) {
		return "<!-- # Markdown.Err:5 -->", NewError("Markdown File # Read Failed `" + mdFilePath + "`: " + errRd.Error())
	} //end if
	if(StrTrimWhitespaces(mdData) == "") {
		return "<!-- # Markdown.Err:6 -->", NewError("Markdown File # Content is Empty `" + mdFilePath + "`")
	} //end if
	//--
	html, err := MarkdownToHTMLRender(mdData)
	if(err != nil) {
		return "<!-- # Markdown.Err:7 -->", NewError("Markdown File # Parse ERR: " + err.Error() + " # `" + mdFilePath + "`")
	} //end if
	//--
	return html, nil
	//--
} //END FUNCTION


//-----


func HTMLCodeFixValidate(htmlCode string) (string, error) {
	//--
	defer PanicHandler()
	//--
	if(htmlCode == "") {
		return "<!-- Html:empty.vd -->", nil
	} //end if
	if(uint64(len(htmlCode)) > MAX_DOC_SIZE_VALIDATE_HTML) {
		return "<!-- Html:oversized.vd -->", nil
	} //end if
	//--
	var uuid string = StrToLower(uid.Uuid13Str() + "-" + uid.Uuid10Num() + "-fx." + ConvertUInt64ToStr(uid.UuidSessionSequence()))
	//--
	getBody := func(doc *xnethtml.Node) (*xnethtml.Node, error) {
		var body *xnethtml.Node
		var crawler func(*xnethtml.Node)
		crawler = func(node *xnethtml.Node) {
			if((node.Type == xnethtml.ElementNode) && (node.Data == "div")) {
				for i:=0; i<len(node.Attr); i++ {
					if((node.Attr[i].Key == "id") && (node.Attr[i].Val == "validate-" + uuid)) {
						body = node
						return
					} //end if
				} //end for
			} //end if
			for child := node.FirstChild; child != nil; child = child.NextSibling {
				crawler(child)
			} //end for
		} //end function
		crawler(doc)
		if(body == nil) {
			return nil, NewError("HTML Smart Fix / Validate: Body Tag is missing ...")
		} //end if
		return body, nil
	} //end function
	//--
	renderNode := func(n *xnethtml.Node) string {
		var buf bytes.Buffer
		w := io.Writer(&buf)
		xnethtml.Render(w, n)
		return buf.String()
	} //end if
	//--
	doc, err := xnethtml.Parse(strings.NewReader(`<!DOCTYPE html><html><head><meta charset="` + EscapeHtml(CHARSET) + `"></head><body><div id="validate-` + EscapeHtml(uuid) + `">` + htmlCode + `</div></body></html>`))
	if(err != nil) {
		return "<!-- Html:err-fix.vd.1 -->", err
	} //end if
	//--
	bn, err := getBody(doc)
	if(err != nil) {
		return "<!-- Html:err-fix.vd.2 -->", err
	} //end if
	//--
	var validHtml string = StrTr(renderNode(bn), map[string]string{
		" />" : ">", // fix html ending tags
		"/>"  : ">", // fix html ending tags
	})
	//--
	return validHtml, nil
	//--
} //END FUNCTION


func HTMLCodeFixSanitize(htmlCode string) (string, error) {
	//--
	defer PanicHandler() // just in case
	//--
	if(htmlCode == "") {
		return "<!-- Html:empty.sn -->", nil
	} //end if
	if(uint64(len(htmlCode)) > MAX_DOC_SIZE_VALIDATE_HTML) {
		return "<!-- Html:oversized.sn -->", nil
	} //end if
	//--
	sanitizer := htmlsanitizer.NewHTMLSanitizer()
	if(sanitizer == nil) {
		return "<!-- Html:err-init.sn -->", NewError("HTMLSanitizer Init Failed")
	} //end if
	//--
	sanitizedHtml, errSanitizer := sanitizer.SanitizeString(htmlCode)
	if(errSanitizer != nil) {
		return "<!-- Html:err-fix.sn -->", errSanitizer
	} //end if
	//--
	return sanitizedHtml, nil
	//--
} //END FUNCTION


//-----


func HTMLCodeStripTags(htmlCode string) string {
	//--
	defer PanicHandler() // just in case
	//-- it contains also HTMLDecodeEntities !
	if(htmlCode == "") {
		return ""
	} //end if
	//--
	sanitizer := htmlsanitizer.NewHTMLSanitizer()
	if(sanitizer == nil) {
		return ""
	} //end if
	//--
	htmlCode = StrNormalizeLineEndings(htmlCode)
	htmlCode = StrNormalizeOnlySpaces(htmlCode)
	//--
	sanitizer.AllowList = &htmlsanitizer.AllowList{
		Tags: []*htmlsanitizer.Tag{}, // no tags
		GlobalAttr: []string{}, // so attributes
		NonHTMLTags: []*htmlsanitizer.Tag{ // skip tags
			{Name: "script"},
			{Name: "style"},
			{Name: "object"},
		},
	}
	htmlCode, _ = sanitizer.SanitizeString(htmlCode)
	//--
	htmlCode = HTMLDecodeEntities(htmlCode)
	//-- fix below as in PHP SF
	htmlCode = StrRegexReplaceAll(REGEX_HTML_ANY_ENTITY, htmlCode, " ") // clean any other remaining html entities
	htmlCode = StrRegexReplaceAll(`[ \t]+`, htmlCode, " ") // replace multiple tabs or spaces with one space
	htmlCode = StrRegexReplaceAll(`(?m)^\s*[\n]{2,}`, htmlCode, "") // fix: replace multiple consecutive lines that may also contain before optional leading spaces
	htmlCode = StrRegexReplaceAll(`(?m)[^\S\r\n]+$`, htmlCode, "") // remove trailing spaces on each line
	//--
	return StrTrimWhitespaces(htmlCode)
	//--
} //END FUNCTION


func HTMLDecodeEntities(htmlCode string) string {
	//--
	defer PanicHandler() // just in case
	//--
	if(htmlCode == "") {
		return ""
	} //end if
	//--
	return html.UnescapeString(htmlCode) // much faster alternative than the commented code below
	//--
} //END FUNCTION


//-----


// #END
