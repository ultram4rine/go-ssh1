package ssh13des

import (
	"crypto/cipher"
	"crypto/des"
)

type encrypter struct {
	enc1, dec2, enc3 cipher.BlockMode
}

func NewEncrypter(c1, c2, c3 cipher.Block, iv []byte) cipher.BlockMode {
	return &encrypter{
		enc1: cipher.NewCBCEncrypter(c1, iv),
		dec2: cipher.NewCBCDecrypter(c2, iv),
		enc3: cipher.NewCBCEncrypter(c3, iv),
	}
}

func (c *encrypter) BlockSize() int { return des.BlockSize }

func (e *encrypter) CryptBlocks(dst, src []byte) {
	e.enc1.CryptBlocks(dst, src)
	e.dec2.CryptBlocks(dst, src)
	e.enc3.CryptBlocks(dst, src)
}

type decrypter struct {
	dec3, enc2, dec1 cipher.BlockMode
}

func NewDecrypter(c1, c2, c3 cipher.Block, iv []byte) cipher.BlockMode {
	return &decrypter{
		dec3: cipher.NewCBCDecrypter(c3, iv),
		enc2: cipher.NewCBCEncrypter(c2, iv),
		dec1: cipher.NewCBCDecrypter(c1, iv),
	}
}

func (c *decrypter) BlockSize() int { return des.BlockSize }

func (e *decrypter) CryptBlocks(dst, src []byte) {
	e.dec3.CryptBlocks(dst, src)
	e.enc2.CryptBlocks(dst, src)
	e.dec1.CryptBlocks(dst, src)
}
