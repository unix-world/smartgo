
package slh_dsa

// by unixman # r.20260915.2358
// SHA-3, similar with SHA-2 but replaced the sha256/sha512 hash methods with sha3-256/sha3-512
// (c) 2026-present unix-world.org

import (
	"crypto/hmac"
	"github.com/unix-world/smartgo/crypto/sha3"

	"github.com/unix-world/smartgo/crypto/slhdsa/internal"
)


type ParamSetSha3Cat1 struct{}
type ParamSetSha3Cat3 struct{}
type ParamSetSha3Cat5 struct{}


// SHA3 - Generic hash functions to reduce code duplication
func genericSh3a256(n uint8, cadrs internal.CompressedAddress, pkseed, M []byte, outlen int) []byte {
	i_64_n := uint8(64) - n
	h := sha3.New256()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(M)
	out := h.Sum(nil)
	return out[0:outlen]
}

func genericSh3a512(n uint8, cadrs internal.CompressedAddress, pkseed, M []byte, outlen int) []byte {
	h := sha3.New512()
	in := uint8(128) - n
	h.Write(pkseed)
	h.Write(internal.ToByte(0, in))
	h.Write(cadrs.Bytes())
	h.Write(M)
	out := h.Sum(nil)
	return out[0:outlen]
}


// SHA-3 for Category 1 (n = 16)
func (x ParamSetSha3Cat1) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha3.New256, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha3Cat1) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha3.New256()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha3.New256()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

func (x ParamSetSha3Cat1) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSh3a256(uint8(16), cadrs, pkseed, skseed, outlen)
}

func (x ParamSetSha3Cat1) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(48)
	h := sha3.New256()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha3Cat1) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSh3a256(16, cadrs, pkseed, M2, outlen)
}

func (x ParamSetSha3Cat1) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSh3a256(16, cadrs, pkseed, M1, outlen)
}


// SHA-3 for Category 3 (n = 24)
func (x ParamSetSha3Cat3) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha3.New512, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha3Cat3) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha3.New512()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha3.New512()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

func (x ParamSetSha3Cat3) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(40)
	h := sha3.New256()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(skseed)
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha3Cat3) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_128_n := uint8(104)
	h := sha3.New512()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_128_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha3Cat3) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	// 128 - 24 = 104
	return genericSh3a512(24, cadrs, pkseed, M2, outlen)
}

func (x ParamSetSha3Cat3) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	// 64 - 24 = 40
	return genericSh3a256(24, cadrs, pkseed, M1, outlen)
}


// SHA-3 for Category 5 (n = 32)
func (x ParamSetSha3Cat5) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha3.New512, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha3Cat5) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha3.New512()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha3.New512()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

func (x ParamSetSha3Cat5) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(32) // 64 - 32
	h := sha3.New256()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(skseed)
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha3Cat5) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_128_n := uint8(96) // 128 - 32
	h := sha3.New512()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_128_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha3Cat5) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	// 128 - 32 = 96
	return genericSh3a512(32, cadrs, pkseed, M2, outlen)
}

func (x ParamSetSha3Cat5) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSh3a256(32, cadrs, pkseed, M1, outlen)
}


func SlhDsaSha3_128s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha3Cat1{},
		N:     16,
		H:     63,
		D:     7,
		Hp:    9,
		A:     12,
		K:     14,
		Lgw:   4,
		M:     30,
	}
}

func SlhDsaSha3_128f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha3Cat1{},
		N:     16,
		H:     66,
		D:     22,
		Hp:    3,
		A:     6,
		K:     33,
		Lgw:   4,
		M:     34,
	}
}


func SlhDsaSha3_192s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha3Cat3{},
		N:     24,
		H:     63,
		D:     7,
		Hp:    9,
		A:     14,
		K:     17,
		Lgw:   4,
		M:     39,
	}
}

func SlhDsaSha3_192f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha3Cat3{},
		N:     24,
		H:     66,
		D:     22,
		Hp:    3,
		A:     8,
		K:     33,
		Lgw:   4,
		M:     42,
	}
}


func SlhDsaSha3_256s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha3Cat5{},
		N:     32,
		H:     64,
		D:     8,
		Hp:    8,
		A:     14,
		K:     22,
		Lgw:   4,
		M:     47,
	}
}

func SlhDsaSha3_256f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha3Cat5{},
		N:     32,
		H:     68,
		D:     17,
		Hp:    4,
		A:     9,
		K:     35,
		Lgw:   4,
		M:     49,
	}
}


// #end
