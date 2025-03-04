package htmlsanitizer

// modified by unixman

// r.20241212.2358

import (
	"bytes"
	"strings"
)

// Tag with its attributes.
type Tag struct {
	// Name for current tag, must be lowercase.
	Name string

	// Attr specifies the allowed attributes for current tag,
	// must be lowercase.
	//
	// e.g. colspan, rowspan
	Attr []string

	// URLAttr specifies the allowed, URL-relatedd attributes for current tag,
	// must be lowercase.
	//
	// e.g. src, href
	URLAttr []string
}

// attrExists checks whether attr exists. Case sensitive
func (t *Tag) attrExists(p []byte) (ok, urlAttr bool) {
	name := string(p)

	if t == nil {
		return
	}

	for _, attr := range t.URLAttr {
		if attr == name {
			ok, urlAttr = true, true
			return
		}
	}

	for _, attr := range t.Attr {
		if attr == name {
			ok = true
			return
		}
	}

	return
}

// AllowList speficies all the allowed HTML tags and its attributes for
// the filter.
type AllowList struct {
	// Tags specifies all the allow tags.
	Tags []*Tag

	// GlobalAttr specifies the allowed attributes for all the tag.
	// It's very useful for some common attributes, such as `class`, `id`.
	// For security reasons, it's not recommended to set a glboal attr for
	// any URL-related attribute.
	GlobalAttr []string

	// NonHTMLTags defines a set of special tags, such as <script> and <style>.
	// The content of these kind of tags is actually not a real HTML content.
	// So we should treat it as a single element, without any child elements.
	// TODO: rename this one
	NonHTMLTags []*Tag
}

// attrExists checks whether global attr exists. Case sensitive
func (l *AllowList) attrExists(p []byte) bool {
	if l == nil {
		return false
	}

	name := string(p)
	for _, attr := range l.GlobalAttr {
	//	if attr == name { // unixman: add support for wildcard attributes ; ex: data-* ; a wildcard attribute is only valid if ending with a wildcard
		if (!strings.Contains(attr, "*") && (attr == name)) || (strings.HasSuffix(attr, "*") && strings.HasPrefix(name, strings.TrimRight(attr, "*"))) { // unixman
			return true
		}
	}

	return false
}

// checkNonHTMLTag checks if the given tag name is a non-html tag,
// such as `script` and `style`. Return nil if it's not a non-html tag
func (l *AllowList) checkNonHTMLTag(p []byte) *Tag {
	if l == nil {
		return nil
	}

	name := string(bytes.ToLower(p))
	for _, tag := range l.NonHTMLTags {
		if name == tag.Name {
			return tag
		}
	}

	return nil
}

// RemoveTag removes all tags name `name`, must be lowercase
// It is not recommended to modify the default list directly, use .Clone() and
// then modify the new one instead.
func (l *AllowList) RemoveTag(name string) {
	if l == nil || l.Tags == nil {
		return
	}

	idx := -1
	for i := 0; i < len(l.Tags); i++ {
		if l.Tags[i].Name == name {
			idx = i
			break
		}
	}

	if idx >= 0 {
		l.Tags = append(l.Tags[:idx], l.Tags[idx+1:]...)
		l.RemoveTag(name)
	}
}

// FindTag finds and returns tag by its name, case insensitive.
func (l *AllowList) FindTag(p []byte) *Tag {
	if l == nil {
		return nil
	}

	name := string(bytes.ToLower(p))
	for _, tag := range l.Tags {
		if name == tag.Name {
			return tag
		}
	}

	return nil
}

// Clone a new AllowList.
func (l *AllowList) Clone() *AllowList {
	if l == nil {
		return l
	}

	newList := new(AllowList)
	newList.Tags = append(newList.Tags, l.Tags...)
	newList.GlobalAttr = append(newList.GlobalAttr, l.GlobalAttr...)
	newList.NonHTMLTags = append(newList.NonHTMLTags, l.NonHTMLTags...)

	return newList
}

// DefaultAllowList for HTML filter.
//
// The allowlist contains most tags listed in
// https://developer.mozilla.org/en-US/docs/Web/HTML/Element .
// It is not recommended to modify the default list directly, use .Clone() and
// then modify the new one instead.
var DefaultAllowList = &AllowList{
	Tags: []*Tag{
		{"address", []string{}, []string{}},
		{"article", []string{}, []string{}},
		{"aside", []string{}, []string{}},
		{"footer", []string{}, []string{}},
		{"header", []string{}, []string{}},
		{"h1", []string{}, []string{}},
		{"h2", []string{}, []string{}},
		{"h3", []string{}, []string{}},
		{"h4", []string{}, []string{}},
		{"h5", []string{}, []string{}},
		{"h6", []string{}, []string{}},
		{"hgroup", []string{}, []string{}},
		{"main", []string{}, []string{}},
		{"nav", []string{}, []string{}},
		{"section", []string{}, []string{}},
		{"blockquote", []string{}, []string{"cite"}},
		{"dd", []string{}, []string{}},
		{"div", []string{"align"}, []string{}},
		{"dl", []string{}, []string{}},
		{"dt", []string{}, []string{}},
		{"figcaption", []string{}, []string{}},
		{"figure", []string{}, []string{}},
		{"hr", []string{}, []string{}},
		{"li", []string{}, []string{}},
		{"main", []string{}, []string{}},
		{"ol", []string{}, []string{}},
		{"p", []string{}, []string{}},
		{"pre", []string{}, []string{}},
		{"ul", []string{}, []string{}},
		{"a", []string{"rel", "target", "referrerpolicy", "data-smart"}, []string{"href"}},
		{"abbr", []string{}, []string{}},
		{"b", []string{}, []string{}},
		{"bdi", []string{}, []string{}},
		{"bdo", []string{}, []string{}},
		{"br", []string{}, []string{}},
		{"cite", []string{}, []string{}},
		{"code", []string{}, []string{}},
		{"data", []string{"value"}, []string{}},
		{"em", []string{}, []string{}},
		{"i", []string{}, []string{}},
		{"kbd", []string{}, []string{}},
		{"mark", []string{}, []string{}},
		{"var", []string{}, []string{}},
		{"dfn", []string{}, []string{}},
		{"q", []string{}, []string{"cite"}},
		{"s", []string{}, []string{}},
		{"small", []string{}, []string{}},
		{"span", []string{}, []string{}},
		{"strong", []string{}, []string{}},
		{"sub", []string{}, []string{}},
		{"sup", []string{}, []string{}},
		{"time", []string{"datetime"}, []string{}},
		{"u", []string{}, []string{}},
		{"map", []string{"name"}, []string{}},
		{"area", []string{"alt", "coords", "shape", "target", "rel", "referrerpolicy"}, []string{"href"}},
		{"img", []string{"alt", "height", "width", "align", "loading", "crossorigin", "referrerpolicy", "longdesc", "srcset", "sizes", "ismap", "usemap"}, []string{"src"}},
		{"picture", []string{}, []string{}},
		{"source", []string{"type"}, []string{"src"}},
		{"video", []string{"autoplay", "buffered", "controls", "crossorigin", "duration", "loop", "muted", "preload", "height", "width"}, []string{"src", "poster"}},
		{"track", []string{"default", "kind", "label", "srclang"}, []string{"src"}},
		{"audio", []string{"autoplay", "controls", "crossorigin", "duration", "loop", "muted", "preload"}, []string{"src"}},
		// no embed
		// no iframe
		// no object
		// no param
		// no canvas
		// no script
		{"del", []string{}, []string{}},
		{"ins", []string{}, []string{}},
		{"caption", []string{}, []string{}},
		{"col", []string{"span"}, []string{}},
		{"colgroup", []string{}, []string{}},
		{"table", []string{}, []string{}},
		{"tbody", []string{}, []string{}},
		{"td", []string{"colspan", "rowspan"}, []string{}},
		{"tfoot", []string{}, []string{}},
		{"th", []string{"colspan", "rowspan", "scope"}, []string{}},
		{"thead", []string{}, []string{}},
		{"tr", []string{}, []string{}},
		{"details", []string{"open"}, []string{}},
		{"summary", []string{}, []string{}},
		// no web-components
		// no button
		{"input", []string{"type", "name", "value", "required", "readonly", "disabled", "autocomplete", "placeholder", "size", "minlength", "maxlength", "min", "max", "step", "pattern", "multiple", "checked", "autofocus", "list"}, []string{}},
		{"textarea", []string{"name", "maxlength", "cols", "rows", "wrap", "required", "readonly", "disabled", "autocomplete", "placeholder", "autofocus", "form"}, []string{}},
	},
	GlobalAttr: []string{
		"id",
		"title",
		"class",
		"style",
		"role",
		"itemscope",
		"itemtype",
		"itemprop",
		"data-*", // wildcard, allow all atributes that start with: "data-"
	},
	NonHTMLTags: []*Tag{
		{Name: "script"},
		{Name: "style"},
		{Name: "object"},
	},
}
