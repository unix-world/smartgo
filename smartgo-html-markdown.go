
// GO Lang :: SmartGo :: Smart.Go.Framework
// (c) 2020-2023 unix-world.org
// r.20231205.2358 :: STABLE
// [ HTML / MARKDOWN ]

// REQUIRE: go 1.19 or later
package smartgo

import (
	"errors"
	"log"

	"strings"
	"bytes"

	"io"

	xnethtml "golang.org/x/net/html"
	"github.com/unix-world/smartgo/htmlsanitizer"

	"github.com/unix-world/smartgo/markdown"
	mkparser "github.com/unix-world/smartgo/markdown/parser"
	mkhtml   "github.com/unix-world/smartgo/markdown/html"
	mkast    "github.com/unix-world/smartgo/markdown/ast"

	uid "github.com/unix-world/smartgo/uuid"
)


//-----


func HTMLCodeFixValidate(htmlCode string) (string, error) {
	//--
	var uuid string = StrToLower(uid.Uuid1013Str(13) + "-" + uid.Uuid1013Str(10) + "-fx." + ConvertUInt64ToStr(uid.UuidSessionSequence()))
	var validHtml string = ""
	//--
	getBody := func(doc *xnethtml.Node) (*xnethtml.Node, error) {
		var body *xnethtml.Node
		var crawler func(*xnethtml.Node)
		crawler = func(node *xnethtml.Node) {
			if((node.Type == xnethtml.ElementNode) && (node.Data == "div")) {
				for i:=0; i<len(node.Attr); i++ {
					if((node.Attr[i].Key == "id") && (node.Attr[i].Val == "markdown-" + uuid)) {
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
			return nil, errors.New("HTML Smart Fix / Validate: Body Tag is missing ...")
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
	doc, err := xnethtml.Parse(strings.NewReader(`<!DOCTYPE html><html><head><meta charset="` + EscapeHtml(CHARSET) + `"></head><body><div id="markdown-` + EscapeHtml(uuid) + `" class="markdown">` + htmlCode + `</div></body></html>`))
	if(err != nil) {
		return "<!-- Html:err-fix.vd.1 -->", err
	} //end if
	//--
	bn, err := getBody(doc)
	if(err != nil) {
		return "<!-- Html:err-fix.vd.2 -->", err
	} //end if
	validHtml = renderNode(bn)
	validHtml = StrReplaceAll(validHtml, " />", ">") // fix html ending tags
	validHtml = StrReplaceAll(validHtml, "/>", ">") // fix html ending tags
	//--
	return validHtml, nil
	//--
} //END FUNCTION


func HTMLCodeFixSanitize(htmlCode string) (string, error) {
	//--
	defer PanicHandler() // just in case
	//--
	sanitizedHtml, errSanitizer := htmlsanitizer.SanitizeString(htmlCode)
	//--
	if(errSanitizer != nil) {
		return "<!-- Html:err-fix.sn -->", errSanitizer
	} //end if
	//--
	return sanitizedHtml, nil
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
	//--
	var md []byte = []byte(mkdwDoc)
	//--
	extensions := mkparser.CommonExtensions | mkparser.HardLineBreak | mkparser.Attributes | mkparser.SuperSubscript // | mkparser.AutoHeadingIDs | mkparser.NoEmptyLineBeforeBlock // create markdown parser with extensions
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
	var htmlCode string = string(markdown.Render(nodes, renderer))
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


// #END
