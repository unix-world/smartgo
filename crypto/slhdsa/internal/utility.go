
package internal


// Algorithm 1
func GenLen2(n, lgw uint32) uint32 {
	w := uint32(1) << lgw
	len1 := ((n << 3) + lgw - 1) / lgw
	max_checksum := len1 * (w - 1)
	len2 := uint32(1)
	capacity := w
	for capacity <= max_checksum {
		len2++
		capacity *= w
	}
	return len2
}


// Algorithm 2
func ToInt(X []byte) uint32 {
	total := uint32(0)
	for i := range X {
		total = (total << 8) | uint32(X[i])
	}
	return total
}


// Algorithm 3
func ToByte(x uint32, n uint8) []byte {
	total := x
	S := make([]byte, n)
	for i := range n {
		S[n-1-i] = byte(total & 0xff)
		total >>= 8
	}
	return S
}


// Algorithm 4
func ToBase2b(X []byte, b, out_len uint32) []uint32 {
	in := uint32(0)
	bits := uint32(0)
	total := uint32(0)
	baseb := []uint32{}
	mask := uint32(1<<b) - 1
	for range out_len {
		for bits < b {
			total = (total << 8) + uint32(X[in])
			in++
			bits += 8
		}
		bits -= b
		tmp := (total >> bits) & mask
		baseb = append(baseb, tmp)
	}
	return baseb
}


// #end
