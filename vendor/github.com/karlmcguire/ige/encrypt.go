package ige

import (
	"crypto/cipher"
)

// NewIGEEncrypter returns an IGE cipher.BlockMode which encrypts using IGE and
// the given cipher.Block.
//
// Note: iv must contain two iv values for IGE (concatenated), otherwise this
// function will panic. See ErrInvalidIV for more information.
func NewIGEEncrypter(b cipher.Block, iv []byte) IGE {
	if err := checkIV(b, iv); err != nil {
		panic(err.Error())
	}

	return (*igeEncrypter)(newIGE(b, iv))
}

type igeEncrypter ige

func (i *igeEncrypter) BlockSize() int {
	return i.block.BlockSize()
}

func (i *igeEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%i.block.BlockSize() != 0 {
		panic("src not full blocks")
	}
	if len(dst) < len(src) {
		panic("len(dst) < len(src")
	}

	b := i.block.BlockSize()
	c := i.iv[:b]
	m := i.iv[b:]

	for o := 0; o < len(src); o += b {
		xor(dst[o:o+b], src[o:o+b], c)
		i.block.Encrypt(dst[o:o+b], dst[o:o+b])
		xor(dst[o:o+b], dst[o:o+b], m)

		c = dst[o : o+b]
		m = src[o : o+b]
	}
}
