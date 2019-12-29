package ssh1

const (
	cipherNone = iota
	cipherIDEA
	cipherDES
	cipher3DES
	_
	cipherRC4
	cipherBlowfish
)

type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}
