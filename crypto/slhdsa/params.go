
package slh_dsa

// modified by unixman, add switch options for SHA-3 in GetParamSet() method

import (
	"errors"
	"strings"

	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/unix-world/smartgo/crypto/sha3"

	"github.com/unix-world/smartgo/crypto/slhdsa/internal"
)

type ParamSetShake struct{}

type ParamSetSha2Cat1 struct{}
type ParamSetSha2Cat3 struct{}
type ParamSetSha2Cat5 struct{}


// SHAKE
func (x ParamSetShake) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(skprf)
	h.Write(opt_rand)
	h.Write(M)
	out := make([]byte, outlen)
	h.Read(out) //nolint:errcheck
	return out[:]
}

func (x ParamSetShake) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(R)
	h.Write(pkseed)
	h.Write(pkroot)
	h.Write(msg)
	out := make([]byte, outlen)
	h.Read(out) //nolint:errcheck
	return out[:]
}

func (x ParamSetShake) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(skseed)
	out := make([]byte, outlen)
	h.Read(out) //nolint:errcheck
	return out[:]
}

func (x ParamSetShake) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := make([]byte, outlen)
	h.Read(out) //nolint:errcheck
	return out[:]
}

func (x ParamSetShake) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(M2)
	out := make([]byte, outlen)
	h.Read(out) //nolint:errcheck
	return out[:]
}

func (x ParamSetShake) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	h := sha3.NewShake256()
	h.Write(pkseed)
	h.Write(adrs.Bytes())
	h.Write(M1)
	out := make([]byte, outlen)
	h.Read(out) //nolint:errcheck
	return out[:]
}


// SHA2 - Generic hash functions to reduce code duplication
func genericSha256(n uint8, cadrs internal.CompressedAddress, pkseed, M []byte, outlen int) []byte {
	i_64_n := uint8(64) - n
	h := sha256.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(M)
	out := h.Sum(nil)
	return out[0:outlen]
}

func genericSha512(n uint8, cadrs internal.CompressedAddress, pkseed, M []byte, outlen int) []byte {
	h := sha512.New()
	in := uint8(128) - n
	h.Write(pkseed)
	h.Write(internal.ToByte(0, in))
	h.Write(cadrs.Bytes())
	h.Write(M)
	out := h.Sum(nil)
	return out[0:outlen]
}


// SHA-2 for Category 1 (n = 16)
func (x ParamSetSha2Cat1) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha256.New, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha2Cat1) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha256.New()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha256.New()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

func (x ParamSetSha2Cat1) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(uint8(16), cadrs, pkseed, skseed, outlen)
}

func (x ParamSetSha2Cat1) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(48)
	h := sha256.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha2Cat1) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(16, cadrs, pkseed, M2, outlen)
}

func (x ParamSetSha2Cat1) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(16, cadrs, pkseed, M1, outlen)
}


// SHA-2 for Category 3 (n = 24)
func (x ParamSetSha2Cat3) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha512.New, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha2Cat3) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha512.New()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha512.New()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

func (x ParamSetSha2Cat3) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(40)
	h := sha256.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(skseed)
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha2Cat3) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_128_n := uint8(104)
	h := sha512.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_128_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha2Cat3) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	// 128 - 24 = 104
	return genericSha512(24, cadrs, pkseed, M2, outlen)
}

func (x ParamSetSha2Cat3) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	// 64 - 24 = 40
	return genericSha256(24, cadrs, pkseed, M1, outlen)
}


// SHA-2 for Category 5 (n = 32)
func (x ParamSetSha2Cat5) PrfMsg(skprf, opt_rand, M []byte, outlen int) []byte {
	raw := hmac.New(sha512.New, skprf)
	raw.Write(opt_rand)
	raw.Write(M)
	out := raw.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha2Cat5) Hmsg(R, pkseed, pkroot, msg []byte, outlen int) []byte {
	h := sha512.New()
	seed := []byte{}
	seed = append(seed, R...)
	seed = append(seed, pkseed...)
	inner := sha512.New()
	inner.Write(R)
	inner.Write(pkseed)
	inner.Write(pkroot)
	inner.Write(msg)
	innerhash := inner.Sum(nil)
	seed = append(seed, innerhash...)
	return internal.MGF1(seed, uint32(outlen), h)
}

func (x ParamSetSha2Cat5) PRF(pkseed, skseed []byte, adrs internal.Address, outlen int) []byte {
	cadrs := adrs.Compress()
	i_64_n := uint8(32) // 64 - 32
	h := sha256.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_64_n))
	h.Write(cadrs.Bytes())
	h.Write(skseed)
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha2Cat5) Tl(pkseed []byte, adrs internal.Address, Ml [][]byte, outlen int) []byte {
	cadrs := adrs.Compress()
	i_128_n := uint8(96) // 128 - 32
	h := sha512.New()
	h.Write(pkseed)
	h.Write(internal.ToByte(0, i_128_n))
	h.Write(cadrs.Bytes())
	for _, Mi := range Ml {
		h.Write(Mi)
	}
	out := h.Sum(nil)
	return out[0:outlen]
}

func (x ParamSetSha2Cat5) H(pkseed []byte, adrs internal.Address, M2 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	// 128 - 32 = 96
	return genericSha512(32, cadrs, pkseed, M2, outlen)
}

func (x ParamSetSha2Cat5) F(pkseed []byte, adrs internal.Address, M1 []byte, outlen int) []byte {
	cadrs := adrs.Compress()
	return genericSha256(32, cadrs, pkseed, M1, outlen)
}


// Parameter set instantations
func SlhDsaShake_128s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetShake{},
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

func SlhDsaShake_128f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetShake{},
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


func SlhDsaShake_192s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetShake{},
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

func SlhDsaShake_192f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetShake{},
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


func SlhDsaShake_256s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetShake{},
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

func SlhDsaShake_256f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetShake{},
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



func SlhDsaSha2_128s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha2Cat1{},
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

func SlhDsaSha2_128f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha2Cat1{},
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


func SlhDsaSha2_192s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha2Cat3{},
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

func SlhDsaSha2_192f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha2Cat3{},
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


func SlhDsaSha2_256s() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha2Cat5{},
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

func SlhDsaSha2_256f() internal.ParamSet {
	return internal.ParamSet{
		Funcs: ParamSetSha2Cat5{},
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


// Load a parameter set by name
func GetParamSet(name string) (internal.ParamSet, error) {
	paramSetName := strings.ToLower(strings.TrimSpace(name))
	switch paramSetName {
		//-- unixman
		case "slhdsa-sha3-128s":
			return SlhDsaSha3_128s(), nil
		case "slh-dsa-sha3-128s":
			return SlhDsaSha3_128s(), nil
		case "sha3-128s":
			return SlhDsaSha3_128s(), nil
		case "slhdsa-sha3-128f":
			return SlhDsaSha3_128f(), nil
		case "slh-dsa-sha3-128f":
			return SlhDsaSha3_128f(), nil
		case "sha3-128f":
			return SlhDsaSha3_128f(), nil
		case "slhdsa-sha3-192s":
			return SlhDsaSha3_192s(), nil
		case "slh-dsa-sha3-192s":
			return SlhDsaSha3_192s(), nil
		case "sha3-192s":
			return SlhDsaSha3_192s(), nil
		case "slhdsa-sha3-192f":
			return SlhDsaSha3_192f(), nil
		case "slh-dsa-sha3-192f":
			return SlhDsaSha3_192f(), nil
		case "sha3-192f":
			return SlhDsaSha3_192f(), nil
		case "slhdsa-sha3-256s":
			return SlhDsaSha3_256s(), nil
		case "slh-dsa-sha3-256s":
			return SlhDsaSha3_256s(), nil
		case "sha3-256s":
			return SlhDsaSha3_256s(), nil
		case "slhdsa-sha3-256f":
			return SlhDsaSha3_256f(), nil
		case "slh-dsa-sha3-256f":
			return SlhDsaSha3_256f(), nil
		case "sha3-256f":
			return SlhDsaSha3_256f(), nil
		//-- #
		case "slhdsa-sha2-128s":
			return SlhDsaSha2_128s(), nil
		case "slh-dsa-sha2-128s":
			return SlhDsaSha2_128s(), nil
		case "sha2-128s":
			return SlhDsaSha2_128s(), nil
		case "slhdsa-sha2-128f":
			return SlhDsaSha2_128f(), nil
		case "slh-dsa-sha2-128f":
			return SlhDsaSha2_128f(), nil
		case "sha2-128f":
			return SlhDsaSha2_128f(), nil
		case "slhdsa-sha2-192s":
			return SlhDsaSha2_192s(), nil
		case "slh-dsa-sha2-192s":
			return SlhDsaSha2_192s(), nil
		case "sha2-192s":
			return SlhDsaSha2_192s(), nil
		case "slhdsa-sha2-192f":
			return SlhDsaSha2_192f(), nil
		case "slh-dsa-sha2-192f":
			return SlhDsaSha2_192f(), nil
		case "sha2-192f":
			return SlhDsaSha2_192f(), nil
		case "slhdsa-sha2-256s":
			return SlhDsaSha2_256s(), nil
		case "slh-dsa-sha2-256s":
			return SlhDsaSha2_256s(), nil
		case "sha2-256s":
			return SlhDsaSha2_256s(), nil
		case "slhdsa-sha2-256f":
			return SlhDsaSha2_256f(), nil
		case "slh-dsa-sha2-256f":
			return SlhDsaSha2_256f(), nil
		case "sha2-256f":
			return SlhDsaSha2_256f(), nil
		case "slhdsa-shake128s":
			return SlhDsaShake_128s(), nil
		case "slh-dsa-shake128s":
			return SlhDsaShake_128s(), nil
		case "shake128s":
			return SlhDsaShake_128s(), nil
		case "slhdsa-shake128f":
			return SlhDsaShake_128f(), nil
		case "slh-dsa-shake128f":
			return SlhDsaShake_128f(), nil
		case "shake128f":
			return SlhDsaShake_128f(), nil
		case "slhdsa-shake192s":
			return SlhDsaShake_192s(), nil
		case "slh-dsa-shake192s":
			return SlhDsaShake_192s(), nil
		case "shake192s":
			return SlhDsaShake_192s(), nil
		case "slhdsa-shake192f":
			return SlhDsaShake_192f(), nil
		case "slh-dsa-shake192f":
			return SlhDsaShake_192f(), nil
		case "shake192f":
			return SlhDsaShake_192f(), nil
		case "slhdsa-shake256s":
			return SlhDsaShake_256s(), nil
		case "slh-dsa-shake256s":
			return SlhDsaShake_256s(), nil
		case "shake256s":
			return SlhDsaShake_256s(), nil
		case "slhdsa-shake256f":
			return SlhDsaShake_256f(), nil
		case "slh-dsa-shake256f":
			return SlhDsaShake_256f(), nil
		case "shake256f":
			return SlhDsaShake_256f(), nil
	}
	return internal.ParamSet{}, errors.New("unkown parameter set: " + name)
}


// #end
