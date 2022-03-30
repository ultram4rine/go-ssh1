package ssh1blowfish

import (
	"golang.org/x/crypto/blowfish"
)

// A Cipher is an instance of SSHv1 Blowfish encryption using a particular key.
type Cipher struct {
	blowfish.Cipher
}

// NewCipher creates and returns a Cipher.
// The key argument should be the Blowfish key, from 1 to 56 bytes.
func NewCipher(key []byte) (*Cipher, error) {
	c, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{*c}, nil
}

// BlockSize returns the Blowfish block size, 8 bytes.
// It is necessary to satisfy the Block interface in the
// package "crypto/cipher".
func (c *Cipher) BlockSize() int { return blowfish.BlockSize }

// SSH1 uses a variation on Blowfish, all bytes must be swapped before
// and after encryption/decryption. Thus, the swapBytes stuff.
func swapBytes(dst, src []byte) {
	var tmp [4]byte
	// Process 4 bytes every lap.
	for n := 0; n < len(src); n += 4 {
		tmp[3] = src[0+n]
		tmp[2] = src[1+n]
		tmp[1] = src[2+n]
		tmp[0] = src[3+n]

		dst[0+n] = tmp[0]
		dst[1+n] = tmp[1]
		dst[2+n] = tmp[2]
		dst[3+n] = tmp[3]
	}
}

// Encrypt encrypts the 8-byte buffer src using the key k
// and stores the result in dst.
// Note that for amounts of data larger than a block,
// it is not safe to just call Encrypt on successive blocks;
// instead, use an encryption mode like CBC (see crypto/cipher/cbc.go).
func (c *Cipher) Encrypt(dst, src []byte) {
	swapBytes(dst, src)
	c.Cipher.Encrypt(dst, src)
	swapBytes(dst, src)
}

// Decrypt decrypts the 8-byte buffer src using the key k
// and stores the result in dst.
func (c *Cipher) Decrypt(dst, src []byte) {
	swapBytes(dst, src)
	c.Cipher.Decrypt(dst, src)
	swapBytes(dst, src)
}
