
// C header
// WebKit GIO Async Ready CallBack
// Requirements: glib2 >= 2.60
// original code: github.com/sourcegraph/go-webkit2
// this is a modified version
// (c) 2020 unix-world.org
// License: BSD

#include <gio/gio.h>

/* Wrapper that runs the Go closure for a given context */
extern void _go_gasyncreadycallback_call(gpointer user_data, void *cresult);

void _gasyncreadycallback_call(GObject *source_object, GAsyncResult *res, gpointer user_data);

// #END
