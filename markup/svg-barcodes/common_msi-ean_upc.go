
// based on: github.com/juliankoehn/barcode
// v.20260203.2358
// (c) unix-world.org

package barcodes


func onlyDigits(code string) bool {
	b := true
	for _, c := range code {
		if c < '0' || c > '9' {
			b = false
			break
		}
	}
	return b
}


// #end
