
package internal

import (
	"crypto/subtle"
)


type HTSignature struct {
	xmss []XmssSignature
}

func (h HTSignature) Bytes() []byte {
	serialized := []byte{}
	for i := range h.xmss {
		serialized = append(serialized, h.xmss[i].Bytes()...)
	}
	return serialized
}


// Algorithm 12
func HTSign(params ParamSet, M, skseed, pkseed []byte, idxTree Index, idxLeaf uint32) HTSignature {
	d := uint32(params.D)
	adrs := NewAddress()
	adrs.SetTreeAddress(idxTree)
	sigTmp := XmssSign(params, M, skseed, idxLeaf, pkseed, adrs.Clone())
	sigHT := make([]XmssSignature, d)
	sigHT[0] = sigTmp.Clone()
	root := XmssPkFromSig(params, idxLeaf, sigTmp, M, pkseed, adrs.Clone())
	for j := uint32(1); j < d; j++ {
		idxLeaf = idxTree.Residue(params.Hp)
		idxTree = idxTree.RemoveBits(params.Hp)
		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(idxTree)
		sigTmp = XmssSign(params, root, skseed, idxLeaf, pkseed, adrs.Clone())
		sigHT[j] = sigTmp.Clone()
		if j < d-1 {
			root = XmssPkFromSig(params, idxLeaf, sigTmp, root, pkseed, adrs.Clone())
		}
	}
	return HTSignature{
		xmss: sigHT,
	}
}


// Algorithm 13
func HTVerify(params ParamSet, sig HTSignature, M, pkseed []byte, idxTree Index, idxLeaf uint32, pkroot []byte) bool {
	d := uint32(params.D)
	adrs := NewAddress()
	adrs.SetTreeAddress(idxTree)
	sigTmp := sig.xmss[0]
	node := XmssPkFromSig(params, idxLeaf, sigTmp, M, pkseed, adrs.Clone())
	for j := uint32(1); j < d; j++ {
		idxLeaf = idxTree.Residue(params.Hp)
		idxTree = idxTree.RemoveBits(params.Hp)
		adrs.SetLayerAddress(j)
		adrs.SetTreeAddress(idxTree)
		sigTmp = sig.xmss[j]
		node = XmssPkFromSig(params, idxLeaf, sigTmp, node, pkseed, adrs.Clone())
	}
	return subtle.ConstantTimeCompare(node, pkroot) == 1
}


func BytesToHTSignature(params ParamSet, buf []byte) (HTSignature, error) {
	d := uint32(params.D)
	n := uint32(params.N)
	chunkLen := (uint32(params.Hp) + params.GetWOTSLen()) * n
	start := uint32(0)
	xmss := make([]XmssSignature, d)
	for i := range d {
		stop := start + chunkLen
		chunk := buf[start:stop]
		x, err := BytesToXmssSignature(params, chunk)
		if err != nil {
			return HTSignature{}, err
		}
		xmss[i] = x
		start += chunkLen
	}
	return HTSignature{xmss: xmss}, nil
}


// #end
