
// based on: github.com/juliankoehn/barcode
// v.20260203.2358
// (c) unix-world.org

package barcodes

import (
	"errors"

	"bytes"
	"strings"
	"strconv"
	"encoding/xml"

	"image"
	"image/draw"
	clr "image/color"
	"image/png"
)


type barArray struct {
	Code  string
	MaxW  int
	MaxH  int
	BCode []bCode
}

type bCode struct {
	T bool
	W int
	H int
	P int
}

type SVG struct {
	Code        string
	Text        string
	Svg         string
	GeomPrecise bool
}

type PNG struct {
	Code string
	Text string
	Png  []byte
}

type BInfo struct {
	F bool
	Y int
	H int
}


// GetBarcodeSVG generates a SVG xml for given code
func GetBarcodeSVG(code string, variant string, w int, h int, color string, useGeometricPrecision bool) (SVG, error) {

	qerr := SVG{}

	if(code == "") {
		return qerr, errors.New("Code is Empty")
	}
	if(variant == "") {
		return qerr, errors.New("Variant is Empty")
	}
	if(w <= 0) {
		return qerr, errors.New("W is Zero or Negative")
	}
	if(h <= 0) {
		return qerr, errors.New("H is Zero or Negative")
	}

	barcodeArray, errVariant := setBarcode(code, variant)
	if(errVariant != nil) {
		return qerr, errVariant
	}
	if(barcodeArray == nil) {
		return qerr, errors.New("BarCode Array is Empty")
	}

	var shapeRendering string = "crispEdges"
	if(useGeometricPrecision == true) {
		shapeRendering = "geometricPrecision"
	}

	var svg string = ""

	svg += "<?xml version=\"1.0\" standalone=\"no\" ?>\n"
	svg += "<svg version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\" width=\"" + escapeXml(strconv.Itoa(barcodeArray.MaxW * w)) + "\" height=\"" + escapeXml(strconv.Itoa(h)) + "\" shape-rendering=\"" + escapeXml(shapeRendering) + "\">\n"
	svg += "\t<g id=\"bars\" fill=\"" + escapeXml(color) + "\" stroke=\"none\">\n"

	var x int = 0
	var bw int = 0
	var bh int = 0

	for _, value := range barcodeArray.BCode {
		bw = value.W * w
		bh = value.H * h / barcodeArray.MaxH
		if value.T {
			var y int = value.P * h / barcodeArray.MaxH
			svg += "\t\t<rect x=\"" + escapeXml(strconv.Itoa(x)) + "\" y=\"" + escapeXml(strconv.Itoa(y)) + "\" width=\"" + escapeXml(strconv.Itoa(bw)) + "\" height=\"" + escapeXml(strconv.Itoa(bh)) + "\" />\n"
		}
		x = (x + bw)
	}

	svg += "\t</g>\n</svg>\n"

	//println(svg)

	qsvg := SVG{}
	qsvg.Code = barcodeArray.Code // may be different than code, ex: EAN or I25 modifies
	qsvg.Text = code // preserve original code
	qsvg.Svg = svg
	qsvg.GeomPrecise = useGeometricPrecision

	return qsvg, nil
}


// GetBarcodeFile returns a Barcode as PNG representation
func GetBarcodePngImg(code string, variant string, w int, h int, color clr.Color, bgColor clr.Color, transparent bool) (PNG, error) {

	qerr := PNG{}

	if(code == "") {
		return qerr, errors.New("Code is Empty")
	}
	if(variant == "") {
		return qerr, errors.New("Variant is Empty")
	}
	if(w <= 0) {
		return qerr, errors.New("W is Zero or Negative")
	}
	if(h <= 0) {
		return qerr, errors.New("H is Zero or Negative")
	}

	barcodeArray, errVariant := setBarcode(code, variant)
	if(errVariant != nil) {
		return qerr, errVariant
	}
	if(barcodeArray == nil) {
		return qerr, errors.New("BarCode Array is Empty")
	}

	if(transparent == true) {
		bgColor = clr.Transparent
	} else {
		if(bgColor == nil) {
			bgColor = clr.White
		}
	}

	if(color == nil) {
		color = clr.Black
	}

	// calculate image size
	width := barcodeArray.MaxW * w
	height := h

	img := image.NewNRGBA(image.Rect(0, 0, width, height)) // NRGBA is better than RGBA for PNG (which store colors and masks separately for lossless compression)
	draw.Draw(img, img.Bounds(), &image.Uniform{C:bgColor}, image.Point{}, draw.Src)

	// print bars
	x := 0
	bw := 0
	bh := 0
	for _, value := range barcodeArray.BCode {
		bw = value.W * w
		bh = value.H * h / barcodeArray.MaxH
		if value.T {
			y := value.P * h / barcodeArray.MaxH
			draw.Draw(img, image.Rect(x, y, (x + bw), (y + bh)), &image.Uniform{C:color}, image.Point{}, draw.Over)
		}
		x = (x + bw)
	}

	buf := new(bytes.Buffer)
	enc := png.Encoder{
		CompressionLevel: png.BestCompression,
	}
	err := enc.Encode(buf, img)
	if(err != nil) {
		return qerr, err
	}
	out := buf.Bytes()
	if(out == nil) {
		return qerr, errors.New("PNG Data is Null")
	}

	qpng := PNG{}
	qpng.Code = barcodeArray.Code // may be different than code, ex: EAN or I25 modifies
	qpng.Text = code // preserve original code
	qpng.Png = out

	return qpng, nil
}


// for special usage only
func GetDimensionsAndFilledRegions(code string, variant string, w int, h int) (error, []BInfo, int, int) {

	if(code == "") {
		return errors.New("Code is Empty"), nil, 0, 0
	}
	if(variant == "") {
		return errors.New("Variant is Empty"), nil, 0, 0
	}
	if(w <= 0) {
		return errors.New("W is Zero or Negative"), nil, 0, 0
	}
	if(h <= 0) {
		return errors.New("H is Zero or Negative"), nil, 0, 0
	}

	barcodeArray, errVariant := setBarcode(code, variant)
	if(errVariant != nil) {
		return errVariant, nil, 0, 0
	}
	if(barcodeArray == nil) {
		return errors.New("BarCode Array is Empty"), nil, 0, 0
	}

	var width int = barcodeArray.MaxW * w * h
	var height int = 1

	var fillMap []BInfo = []BInfo{}
	for _, value := range barcodeArray.BCode {
		bInfo := BInfo{}
		if value.T {
			bInfo.F = true
			bInfo.Y = value.P * h / barcodeArray.MaxH
			bInfo.H = value.H * h / barcodeArray.MaxH
		}
		fillMap = append(fillMap, bInfo)
	}

	return nil, fillMap, width, height

}


func setBarcode(code, variant string) (*barArray, error) {

	variant = strings.ToUpper(variant)

	switch variant {
	case "C39": // standard ; uxm
		return barcodeCode39(code, false, false), nil
//	case "C39+": // standard + checksum
//		return barcodeCode39(code, false, true), nil
//	case "C39E": // full ascii
//		return barcodeCode39(code, true, false), nil
//	case "C39E+": // full ascii + checksum
//		return barcodeCode39(code, true, true), nil
	case "C93": // uxm
		return barcodeCode93(code), nil
//	case "C128":
//		return barcodeC128(code, ""), nil
//	case "C128A":
//		return barcodeC128(code, "A"), nil
	case "C128B": // full ascii ; uxm
		return barcodeC128(code, "B"), nil
//	case "C128C":
//		return barcodeC128(code, "C"), nil
	case "RMS4CC": // uxm
		return barcodeCBCKIX(code, false), nil
//	case "KIX":
//		return barcodeCBCKIX(code, true), nil
	case "MSI": // uxm ; numeric only, length variable
		return barcodeMSI(code, false), nil
	case "MSI+":
		return barcodeMSI(code, true), nil
//	case "EAN8":
//		return barcodeEANUPC(code, 8), nil
	case "EAN13": // uxm ; 13 digit
		return barcodeEANUPC(code, 13), nil
	case "UPCA": // 12 digit
		return barcodeEANUPC(code, 12), nil
//	case "UPCE":
//		return barcodeEANUPC(code, 6), nil
	default:
		return nil, errors.New("Invalid BarCode Variant: `" + variant + "`")
	}

}


func escapeXml(s string) string { // provides a Smart.Framework ~ EscapeXml
	//-- v.20241228 ; sync with SmartGo
	if(s == "") {
		return ""
	} //end if
	//--
	buf := bytes.Buffer{}
	err := xml.EscapeText(&buf, []byte(s)) // escapes all characters compliant with XML standard
	if(err != nil) {
		return ""
	} //end if
	//--
	s = buf.String()
	//--
	return s // exml
	//--
} //END FUNCTION


// #end
