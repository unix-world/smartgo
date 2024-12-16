
// a simple and unsafe quote for mysql
// by unixman, v.20231231

// IMPORTANT: This is pretty unsafe, and only can work for very limited charset: ex: ASCII

package mysql

import (
	"strings"
)

func QuoteAsciiStr(name string) string { // SECURITY: DO NOT USE THIS METHOD WITH UNKNOWN (POSSIBLE UNSAFE) STRINGS !
	end := strings.IndexRune(name, 0)
	if end > -1 {
		name = name[:end]
	}
	return `'` + strings.Replace(name, `'`, `''`, -1) + `'`
}
