
// GoLang
// WebKit Util
// Requirements: go >= 1.13
// original code: github.com/sourcegraph/go-webkit2
// this is a modified version
// (c) 2020 unix-world.org
// License: BSD

package webkit2gtk3

// #include <glib.h>
import "C"

func gboolean(b bool) C.gboolean {
	if b {
		return C.gboolean(1)
	}
	return C.gboolean(0)
}

func gobool(b C.gboolean) bool {
	if b != 0 {
		return true
	}
	return false
}

// #END
