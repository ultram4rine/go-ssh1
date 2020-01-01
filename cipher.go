package ssh1

import "errors"

const (
	// SSH_CIPHER_NONE is no encryption
	SSH_CIPHER_NONE = iota
	// SSH_CIPHER_IDEA is IDEA in CFB mode
	SSH_CIPHER_IDEA
	// SSH_CIPHER_DES is DES in CBC mode
	SSH_CIPHER_DES
	// SSH_CIPHER_3DES is 3DES in CBC mode
	SSH_CIPHER_3DES
	// SSH_CIPHER_TSS is not supported TRI's Simple Stream encryption in CBC mode
	_
	// SSH_CIPHER_RC4 is RC4
	SSH_CIPHER_RC4
	// SSH_CIPHER_BLOWFISH is Blowfish
	SSH_CIPHER_BLOWFISH
)

// CipherMask implements mask of supported ciphers
type CipherMask uint

// AddCiphers returns mask of choosen ciphers
func (mask CipherMask) AddCiphers(ciphers ...int) error {
	if len(ciphers) > SSH_CIPHER_BLOWFISH {
		return errors.New("ssh1: too many ciphers")
	}

	for _, c := range ciphers {
		mask |= 1 << c
	}
	return nil
}

type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}
