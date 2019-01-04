package ige

import (
	"crypto/cipher"
)

// NewIGEDecrypter returns an IGE cipher.BlockMode which decrypts using IGE and
// the given cipher.Block.
//
// Note: iv must contain two iv values for IGE (concatenated), otherwise this
// function will panic. See ErrInvalidIV for more information.
func NewIGEDecrypter(b cipher.Block, iv []byte) IGE {
	if err := checkIV(b, iv); err != nil {
		panic(err.Error())
	}

	return (*igeDecrypter)(newIGE(b, iv))
}

type igeDecrypter ige

func (i *igeDecrypter) BlockSize() int {
	return i.block.BlockSize()
}

func (i *igeDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%i.block.BlockSize() != 0 {
		panic("src not full blocks")
	}
	if len(dst) < len(src) {
		panic("len(dst) < len(src)")
	}

	b := i.block.BlockSize()
	c := i.iv[:b]
	m := i.iv[b:]

	for o := 0; o < len(src); o += b {
		t := src[o : o+b]

		xor(dst[o:o+b], src[o:o+b], m)
		i.block.Decrypt(dst[o:o+b], dst[o:o+b])
		xor(dst[o:o+b], dst[o:o+b], c)

		m = dst[o : o+b]
		c = t
	}
}
