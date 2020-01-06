package ssh1

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

var cipherNames = map[int]string{
	SSH_CIPHER_IDEA:     "idea",
	SSH_CIPHER_DES:      "des",
	SSH_CIPHER_3DES:     "3des",
	SSH_CIPHER_RC4:      "rc4",
	SSH_CIPHER_BLOWFISH: "blowfish",
}

// CreateCipherMask returns a bitmask of choosen ciphers or panic
// if cipher not supported or length of choosen ciphers too small
// or too big
func CreateCipherMask(ciphers ...int) *Bitmask {
	var mask = new(Bitmask)

	if len(ciphers) <= 0 {
		panic("ssh1: too few ciphers")
	}
	if len(ciphers) > len(cipherNames) {
		panic("ssh1: too many ciphers")
	}

	for _, c := range ciphers {
		if _, ok := cipherNames[c]; !ok {
			panic("ssh1: choosen cipher doesn't supported")
		}
		mask.addFlag(c)
	}

	return mask
}

type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}
