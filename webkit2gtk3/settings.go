
// GoLang
// WebKit Settings
// Requirements: go >= 1.13 ; webkitgtk >= 2.22 ; gtk+3 >= 3.20 ; glib2 >= 2.60
// original code: github.com/sourcegraph/go-webkit2
// this is a modified version
// (c) 2020 unix-world.org
// License: BSD

package webkit2gtk3

// #include <webkit2/webkit2.h>
import "C"
import "unsafe"
import "github.com/gotk3/gotk3/glib"

type Settings struct {
	*glib.Object
	settings *C.WebKitSettings
}

// newSettings creates a new Settings with default values.
//
// See also: webkit_settings_new at
// http://webkitgtk.org/reference/webkit2gtk/stable/WebKitSettings.html#webkit-settings-new.
func newSettings(settings *C.WebKitSettings) *Settings {
	return &Settings{&glib.Object{glib.ToGObject(unsafe.Pointer(settings))}, settings}
}

// GetAutoLoadImages returns the "auto-load-images" property.
//
// See also: webkit_settings_get_auto_load_images at
// http://webkitgtk.org/reference/webkit2gtk/stable/WebKitSettings.html#webkit-settings-get-auto-load-images
func (s *Settings) GetAutoLoadImages() bool {
	return gobool(C.webkit_settings_get_auto_load_images(s.settings))
}

// SetAutoLoadImages sets the "auto-load-images" property.
//
// See also: webkit_settings_get_auto_load_images at
// http://webkitgtk.org/reference/webkit2gtk/stable/WebKitSettings.html#webkit-settings-set-auto-load-images
func (s *Settings) SetAutoLoadImages(autoLoad bool) {
	C.webkit_settings_set_auto_load_images(s.settings, gboolean(autoLoad))
}

// SetUserAgentWithApplicationDetails sets the "user-agent" property by
// appending the application details to the default user agent.
//
// See also: webkit_settings_set_user_agent_with_application_details at
// http://webkitgtk.org/reference/webkit2gtk/unstable/WebKitSettings.html#webkit-settings-set-user-agent-with-application-details
func (s *Settings) SetUserAgentWithApplicationDetails(appName string, appVersion string) {
	C.webkit_settings_set_user_agent_with_application_details(s.settings, (*C.gchar)(C.CString(appName)), (*C.gchar)(C.CString(appVersion)))
}

// implemented by unixman
func (s *Settings) EnableFullScreen(TrueOrFalse bool) {
	C.webkit_settings_set_enable_fullscreen(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) AllowDataUrls(TrueOrFalse bool) {
	C.webkit_settings_set_allow_top_navigation_to_data_urls(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) SetDefaultCharset(theCharset string) {
	C.webkit_settings_set_default_charset(s.settings, (*C.gchar)(C.CString(theCharset)));
}
func (s *Settings) SetCustomUserAgent(uaName string) { // completely changes the User Agent Signature
	C.webkit_settings_set_user_agent(s.settings, (*C.gchar)(C.CString(uaName)));
}
func (s *Settings) EnableJava(TrueOrFalse bool) {
	C.webkit_settings_set_enable_java(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnableJavascript(TrueOrFalse bool) {
	C.webkit_settings_set_enable_javascript(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) JavascriptCanAccessClipboard(TrueOrFalse bool) {
	C.webkit_settings_set_javascript_can_access_clipboard(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) JavascriptCanOpenWindowsAutomatically(TrueOrFalse bool) {
	C.webkit_settings_set_javascript_can_open_windows_automatically(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnableXssAuditor(TrueOrFalse bool) {
	C.webkit_settings_set_enable_xss_auditor(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnableDnsPrefetching(TrueOrFalse bool) {
	C.webkit_settings_set_enable_dns_prefetching(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnablePlugins(TrueOrFalse bool) {
	C.webkit_settings_set_enable_plugins(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnablePageCache(TrueOrFalse bool) {
	C.webkit_settings_set_enable_page_cache(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnableSmoothScrolling(TrueOrFalse bool) {
	C.webkit_settings_set_enable_smooth_scrolling(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnableWebAudio(TrueOrFalse bool) {
	C.webkit_settings_set_enable_webaudio(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnableMedia(TrueOrFalse bool) {
	C.webkit_settings_set_enable_media(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnableWebGl(TrueOrFalse bool) {
	C.webkit_settings_set_enable_webgl(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) EnableAccelerated2DCanvas(TrueOrFalse bool) {
	C.webkit_settings_set_enable_accelerated_2d_canvas(s.settings, gboolean(TrueOrFalse));
}
func (s *Settings) SetHardwareAccelerationPolicy(mode string) {
	switch(mode) {
		case "WEBKIT_HARDWARE_ACCELERATION_POLICY_NEVER":
			C.webkit_settings_set_hardware_acceleration_policy(s.settings, C.WEBKIT_HARDWARE_ACCELERATION_POLICY_NEVER);
			break;
		case "WEBKIT_HARDWARE_ACCELERATION_POLICY_ALWAYS":
			C.webkit_settings_set_hardware_acceleration_policy(s.settings, C.WEBKIT_HARDWARE_ACCELERATION_POLICY_ALWAYS);
			break;
		case "WEBKIT_HARDWARE_ACCELERATION_POLICY_ON_DEMAND":
			C.webkit_settings_set_hardware_acceleration_policy(s.settings, C.WEBKIT_HARDWARE_ACCELERATION_POLICY_ON_DEMAND);
		default:
			// nothing to set, wrong policy
	}
}

// GetEnableWriteConsoleMessagesToStdout returns the
// "enable-write-console-messages-to-stdout" property.
//
// See also: webkit_settings_get_enable_write_console_messages_to_stdout at
// http://webkitgtk.org/reference/webkit2gtk/stable/WebKitSettings.html#webkit-settings-get-enable-write-console-messages-to-stdout
func (s *Settings) GetEnableWriteConsoleMessagesToStdout() bool {
	return gobool(C.webkit_settings_get_enable_write_console_messages_to_stdout(s.settings))
}

//----- DEBUG

// SetEnableWriteConsoleMessagesToStdout sets the
// "enable-write-console-messages-to-stdout" property.
//
// See also: webkit_settings_set_enable_write_console_messages_to_stdout at
// http://webkitgtk.org/reference/webkit2gtk/stable/WebKitSettings.html#webkit-settings-set-enable-write-console-messages-to-stdout
func (s *Settings) SetEnableWriteConsoleMessagesToStdout(write bool) {
	C.webkit_settings_set_enable_write_console_messages_to_stdout(s.settings, gboolean(write))
}

// implemented by unixman
func (s *Settings) EnableDeveloperExtras(TrueOrFalse bool) {
	C.webkit_settings_set_enable_developer_extras(s.settings, gboolean(TrueOrFalse));
}

// #END
