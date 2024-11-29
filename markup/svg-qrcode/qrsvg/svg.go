package qrsvg

// based on: github.com/wamuir/svg-qr-code ; go 1.16 @ License: MIT # v.20231205

// QrSVG for GO # r.20241124.2358
// (c) 2023-2024 unix-world.org
// License: BSD
// custom modifications by unixman:
// 	* implement ellipse
//	* implement colors: FG / BG
//	* return flat not pointer
// 	* different optimizations

import (
	"fmt"
	"errors"

	"strings"
	"strconv"
	"encoding/xml"

	"image"
	"image/color"

	qrcode "github.com/unix-world/smartgo/markup/svg-qrcode"
)

// defaults
const (
	blocksize   uint8 = 3
	borderwidth uint8 = 1

	radiusRatio float32 = 1.85 // 1.95 was not readable by iOS BarCode Scanner
)

// QR holds a QR Code (from github.com/unix-world/smartgo/markup/svg-qrcode) and SVG settings.
type QR struct {
	Text        string         // text of the QR
	Blocksize   uint8          // size of each block in pixels, default = 16 pixels
	Borderwidth uint8          // size of the border in blocks, default = 4 blocks
	Borderfill  color.Color    // fill color for the border
	UseDots     bool           // draw using dots or squares
	Svg         string         // the SVG code
	qrcode      qrcode.QRCode  // underlying QR Code
}

// SVG is the vector representation of a QR code, as a Go struct.
type SVG struct {
	XMLName xml.Name `xml:"svg"`
	NS      string   `xml:"xmlns,attr"`
	Render  string   `xml:"shape-rendering,attr"`
	Width   uint     `xml:"width,attr"`
	Height  uint     `xml:"height,attr"`
	Style   string   `xml:"style,attr"`
	RBlocks []RBlock `xml:"rect"`
	EBlocks []EBlock `xml:"ellipse"`
}

// Block is a color block in the rendered QR code.
type RBlock struct { // rect
	X      int     `xml:"x,attr"`
	Y      int     `xml:"y,attr"`
	Width  int     `xml:"width,attr"`
	Height int     `xml:"height,attr"`
	Fill   string  `xml:"fill,attr"`
}
type EBlock struct { // ellipse
	X      int     `xml:"cx,attr"`
	Y      int     `xml:"cy,attr"`
	Width  float32 `xml:"rx,attr"`
	Height float32 `xml:"ry,attr"`
	Fill   string  `xml:"fill,attr"`
}


// SVG returns the vector representation of a QR code, as a Go struct.
// This could, for instance, be marshaled with encoding/xml.
func (q *QR) generateSVG(transparentBgColor string) *SVG {

	q.qrcode.DisableBorder = true
	var i image.Image = q.qrcode.Image(0)
	var w int = i.Bounds().Max.X

	var svg SVG
	svg.NS = "http://www.w3.org/2000/svg"
	if(!q.UseDots) {
		svg.Render = "crispEdges"
	} else {
		svg.Render = "geometricPrecision"
	}
	var width int = (w + 2 * int(q.Borderwidth)) * int(q.Blocksize)
	if(width < 1) {
		width = 1
	} else if(width > 65535) {
		width = 65535
	}
	svg.Width  = uint(width)
	svg.Height = uint(width)

	bgColor := hex(q.Borderfill)
	if(transparentBgColor != "") {
		bgColor = "none"
	}

	svg.RBlocks = append(svg.RBlocks, RBlock{0, 0, int(svg.Width), int(svg.Height), bgColor})
	for x := 0; x < w; x++ {
		for y := 0; y < w; y++ {
			theFill := hex(i.At(x, y))
			if(transparentBgColor != "") {
				if(strings.ToUpper(theFill) == transparentBgColor) { // {{{QR-SVG-SYNC-COLOR-NONE}}}
					theFill = "none"
				}
			}
			if(q.UseDots) {
				svg.EBlocks = append(svg.EBlocks, EBlock{
					X:      (x + int(q.Borderwidth)) * int(q.Blocksize),
					Y:      (y + int(q.Borderwidth)) * int(q.Blocksize),
					Width:  float32(q.Blocksize) / radiusRatio,
					Height: float32(q.Blocksize) / radiusRatio,
					Fill:   theFill,
				})
			} else {
				svg.RBlocks = append(svg.RBlocks, RBlock{
					X:      (x + int(q.Borderwidth)) * int(q.Blocksize),
					Y:      (y + int(q.Borderwidth)) * int(q.Blocksize),
					Width:  int(q.Blocksize),
					Height: int(q.Blocksize),
					Fill:   theFill,
				})
			}
		}
	}

	return &svg
}

// String() returns the SVG as a string and satisfies the fmt.Stringer interface.
func (s *SVG) getAsString() string {
	x, _ := xml.Marshal(s)
	return string(x)
}

func hex(c color.Color) string {
	rgba := color.RGBAModel.Convert(c).(color.RGBA)
	return fmt.Sprintf("#%.2x%.2x%.2x", rgba.R, rgba.G, rgba.B)
}

func parseHexColor(v string) (out color.RGBA, err error) {
	if len(v) != 7 {
		return out, errors.New("hex color must be 7 characters")
	}
	if v[0] != '#' {
		return out, errors.New("hex color must start with '#'")
	}
	var red, redError = strconv.ParseUint(v[1:3], 16, 8)
	if redError != nil {
		return out, errors.New("red component invalid")
	}
	out.R = uint8(red)
	var green, greenError = strconv.ParseUint(v[3:5], 16, 8)
	if greenError != nil {
		return out, errors.New("green component invalid")
	}
	out.G = uint8(green)
	var blue, blueError = strconv.ParseUint(v[5:7], 16, 8)
	if blueError != nil {
		return out, errors.New("blue component invalid")
	}
	out.B = uint8(blue)
	return
}


// New returns the QR for the provided string, with default settings for blocksize,
// borderwidth and background color.  Call .String() to obtain the SVG string.
func New(s string, level string, fgColor string, bgColor string, useDots bool, blockSize uint8, borderWidth uint8) (QR, error) {

	qerr := QR{}

	if(blockSize < blocksize) {
		blockSize = blocksize
	}
	if(borderWidth < borderwidth) {
		borderWidth = borderwidth
	}

	if(fgColor == "") {
		fgColor = "#777788"
	}
	fgClr, errFgClr := parseHexColor(fgColor)
	if(errFgClr != nil) {
		return qerr, errFgClr
	}

	var transparentBgColor string = ""
	var isTransparentBg bool = false
	if(bgColor == "none") {
		isTransparentBg = true
	}
	if((bgColor == "") || (bgColor == "none")) {
		if(fgColor == "#FFFFFF") {
			bgColor = "#000000"
		} else {
			bgColor = "#FFFFFF"
		} //end if else
		if(isTransparentBg) {
			transparentBgColor = bgColor // {{{QR-SVG-SYNC-COLOR-NONE}}}
		}
	}
	bgClr, errBgClr := parseHexColor(bgColor)
	if(errBgClr != nil) {
		return qerr, errBgClr
	}

	var qrlevel qrcode.RecoveryLevel = qrcode.Medium
	switch(level) {
		case "L":
			qrlevel = qrcode.Low
			break
		case "M":
			qrlevel = qrcode.Medium
			break
		case "H":
			qrlevel = qrcode.High
			break
		case "Q":
			qrlevel = qrcode.Highest
			break
		default:
			qrlevel = qrcode.Medium
	}

	code, err := qrcode.New(s, qrlevel)
	code.BackgroundColor = bgClr
	code.ForegroundColor = fgClr
	if err != nil {
		return qerr, err
	}

	q := QR{s, blockSize, borderWidth, code.BackgroundColor, useDots, "", code}
	q.Svg = q.generateSVG(transparentBgColor).getAsString()

	return q, nil
}

// #end
