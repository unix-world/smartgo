
// (c) 2014 Mitchell Hashimoto
// (c) 2021 unix-world.org

// colorstring provides functions for colorizing strings for terminal output.

// THIS IS A MODIFIED VERSION of github.com/mitchellh/colorstring to replace the github.com/fatih/color
// v.20210328.2317

//==== NOTICE
// GreyString is alias of fatih HiBlackString
//===

package colorstring

import (
	"bytes"
	"fmt"
	"regexp"
)

//==

func BlackString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[black]", str)
}

func WhiteString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[white]", str)
}

//==

func GreyString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[dark_gray]", str)
}

func RedString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[red]", str)
}

func GreenString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[green]", str)
}

func YellowString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[yellow]", str)
}

func BlueString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[blue]", str)
}

func MagentaString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[magenta]", str)
}

func CyanString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[cyan]", str)
}

//==

func HiGreyString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[light_gray]", str)
}

func HiRedString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[light_red]", str)
}

func HiGreenString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[light_green]", str)
}

func HiYellowString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[light_yellow]", str)
}

func HiBlueString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[light_blue]", str)
}

func HiMagentaString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[light_magenta]", str)
}

func HiCyanString(str string) string {
	if(str == "") {
		return ""
	}
	return def.color("[light_cyan]", str)
}

//=======

// Colorize colorizes your strings, giving you the ability to customize
// some of the colorization process.
//
// The options in Colorize can be set to customize colorization. If you're
// only interested in the defaults, just use the top Color function directly,
// which creates a default Colorize.
type Colorize struct {
	// Colors maps a color string to the code for that color. The code
	// is a string so that you can use more complex colors to set foreground,
	// background, attributes, etc. For example, "boldblue" might be
	// "1;34"
	Colors map[string]string

	// If true, color attributes will be ignored. This is useful if you're
	// outputting to a location that doesn't support colors and you just
	// want the strings returned.
	Disable bool

	// Reset, if true, will reset the color after each colorization by
	// adding a reset code at the end.
	Reset bool
}

// Color colorizes a string according to the settings setup in the struct.
//
// For more details on the syntax, see the top-level Color function.
func (c *Colorize) color(clr string, str string) string {
	var v string = clr + str
	matches := parseRe.FindAllStringIndex(clr, -1)
	if len(matches) == 0 {
		return v
	}

	result := new(bytes.Buffer)
	colored := false
	m := []int{0, 0}
	for _, nm := range matches {
		// Write the text in between this match and the last
		result.WriteString(v[m[1]:nm[0]])
		m = nm

		var replace string
		if code, ok := c.Colors[v[m[0]+1:m[1]-1]]; ok {
			colored = true

			if !c.Disable {
				replace = fmt.Sprintf("\033[%sm", code)
			}
		} else {
			replace = v[m[0]:m[1]]
		}

		result.WriteString(replace)
	}
	result.WriteString(v[m[1]:])

	if colored && c.Reset && !c.Disable {
		// Write the clear byte at the end
		result.WriteString("\033[0m")
	}

	return result.String()
}

// DefaultColors are the default colors used when colorizing.
//
// If the color is surrounded in underscores, such as "_blue_", then that
// color will be used for the background color.
var DefaultColors map[string]string

func init() {
	DefaultColors = map[string]string{
		// Default foreground/background colors
		"default":   "39",
		"_default_": "49",

		// Foreground colors
		"black":         "30",
		"red":           "31",
		"green":         "32",
		"yellow":        "33",
		"blue":          "34",
		"magenta":       "35",
		"cyan":          "36",
		"light_gray":    "37",
		"dark_gray":     "90",
		"light_red":     "91",
		"light_green":   "92",
		"light_yellow":  "93",
		"light_blue":    "94",
		"light_magenta": "95",
		"light_cyan":    "96",
		"white":         "97",

		// Background colors
		"_black_":         "40",
		"_red_":           "41",
		"_green_":         "42",
		"_yellow_":        "43",
		"_blue_":          "44",
		"_magenta_":       "45",
		"_cyan_":          "46",
		"_light_gray_":    "47",
		"_dark_gray_":     "100",
		"_light_red_":     "101",
		"_light_green_":   "102",
		"_light_yellow_":  "103",
		"_light_blue_":    "104",
		"_light_magenta_": "105",
		"_light_cyan_":    "106",
		"_white_":         "107",

		// Attributes
		"bold":       "1",
		"dim":        "2",
		"underline":  "4",
		"blink_slow": "5",
		"blink_fast": "6",
		"invert":     "7",
		"hidden":     "8",

		// Reset to reset everything to their defaults
		"reset":      "0",
		"reset_bold": "21",
	}

	def = Colorize{
		Colors: DefaultColors,
		Reset:  true,
	}
}

var def Colorize

var parseRe = regexp.MustCompile(`(?i)\[[a-z0-9_-]+\]`)

//#END
