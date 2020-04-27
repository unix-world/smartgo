
// C
// WebKit GIO Async Ready CallBack
// Requirements: glib2 >= 2.60
// original code: github.com/sourcegraph/go-webkit2
// this is a modified version
// (c) 2020 unix-world.org
// License: BSD

#include <stdio.h>
#include <gio/gio.h>
#include "gasyncreadycallback.go.h"

void _gasyncreadycallback_call(GObject *source_object, GAsyncResult *res, gpointer user_data) {
  _go_gasyncreadycallback_call(user_data, res);
}

// #END
