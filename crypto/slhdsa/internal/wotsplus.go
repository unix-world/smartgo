
package internal

import (
	"slices"
)

const (
	WOTS_HASH 	uint32 = 0
	WOTS_PK 	uint32 = 1
	TREE 		uint32 = 2
	FORS_TREE 	uint32 = 3
	FORS_ROOTS 	uint32 = 4
	WOTS_PRF 	uint32 = 5
	FORS_PRF 	uint32 = 6
)


// Algorithm 5
func Chain(params ParamSet, X []byte, i, s uint32, pkseed []byte, adrs Address) []byte {
	tmp := slices.Clone(X)
	blen := int(params.N)
	for j := i; j < i+s; j++ {
		adrs.SetHashAddress(j)
		tmp = params.Funcs.F(pkseed, adrs, tmp, blen)
	}
	return tmp[:]
}


// Algorithm 6
func WotsPkGen(params ParamSet, skseed, pkseed []byte, adrs Address) []byte {
	skADRS := adrs.Clone()
	skADRS.SetTypeAndClear(WOTS_PRF)
	skADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	length := params.GetWOTSLen()
	bytelen := int(params.N)
	tmp := make([][]byte, length)
	for i := range length {
		skADRS.SetChainAddress(i)
		sk := params.Funcs.PRF(pkseed, skseed, skADRS, bytelen)
		adrs.SetChainAddress(i)
		tmp[i] = Chain(params, sk, uint32(0), uint32(15), pkseed, adrs)
	}
	wotspkADRS := adrs.Clone()
	wotspkADRS.SetTypeAndClear(WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	return params.Funcs.Tl(pkseed, wotspkADRS, tmp, bytelen)
}


// Algorithm 7
func WotsSign(params ParamSet, M, skseed, pkseed []byte, adrs Address) [][]byte {
	length := params.GetWOTSLen()
	len1 := params.GetWOTSLen1()
	len2 := params.GetWOTSLen2()
	bytelen := int(params.N)

	csum := uint32(0)
	lgw := uint32(params.Lgw)
	msg := ToBase2b(M, lgw, len1)
	w := uint32(1 << lgw)
	for i := range len1 {
		csum += w - 1 - msg[i]
	}
	csum = csum << 4 // lg_w == 4 for all parameter sets
	n := uint8(((len2 * lgw) + 7) >> 3)
	msg = append(msg, ToBase2b(ToByte(csum, n), lgw, len2)...)
	skADRS := adrs.Clone()
	skADRS.SetTypeAndClear(WOTS_PRF)
	skADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	sig := make([][]byte, length)
	for i := range length {
		skADRS.SetChainAddress(i)
		sk := params.Funcs.PRF(pkseed, skseed, skADRS, bytelen)
		adrs.SetChainAddress(i)
		sig[i] = Chain(params, sk, 0, msg[i], pkseed, adrs)
	}
	return sig
}


// Algorithm 8
func WotsPkFromSig(params ParamSet, sig [][]byte, M, pkseed []byte, adrs Address) []byte {
	length := params.GetWOTSLen()
	len1 := params.GetWOTSLen1()
	len2 := params.GetWOTSLen2()
	bytelen := int(params.N)

	csum := uint32(0)
	lgw := uint32(params.Lgw)
	msg := ToBase2b(M, lgw, len1)
	w := uint32(1 << lgw)
	for i := range len1 {
		csum += w - 1 - msg[i]
	}
	csum = csum << 4 // lg_w == 4 for all parameter sets
	n := uint8(((len2 * lgw) + 7) >> 3)
	msg = append(msg, ToBase2b(ToByte(csum, n), lgw, len2)...)
	tmp := make([][]byte, length)
	for i := range length {
		adrs.SetChainAddress(i)
		tmp[i] = Chain(params, sig[i], msg[i], w-1-msg[i], pkseed, adrs)
	}
	wotspkADRS := adrs.Clone()
	wotspkADRS.SetTypeAndClear(WOTS_PK)
	wotspkADRS.SetKeyPairAddress(adrs.GetKeyPairAddress())
	return params.Funcs.Tl(pkseed, wotspkADRS, tmp, bytelen)
}


// #end
