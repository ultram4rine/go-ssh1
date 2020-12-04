package ssh1

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"

	"github.com/dgryski/go-idea"
	"golang.org/x/crypto/blowfish"
)

const (
	// SSH_CIPHER_NONE is no encryption.
	SSH_CIPHER_NONE = iota
	// SSH_CIPHER_IDEA is IDEA in CFB mode.
	SSH_CIPHER_IDEA
	// SSH_CIPHER_DES is DES in CBC mode.
	SSH_CIPHER_DES
	// SSH_CIPHER_3DES is 3DES in CBC mode.
	SSH_CIPHER_3DES
	// SSH_CIPHER_TSS is not supported TRI's Simple Stream encryption in CBC mode.
	_
	// SSH_CIPHER_RC4 is RC4.
	SSH_CIPHER_RC4
	// SSH_CIPHER_BLOWFISH is Blowfish.
	SSH_CIPHER_BLOWFISH
)

var cipherNames = map[int]string{
	SSH_CIPHER_IDEA:     "idea",
	SSH_CIPHER_DES:      "des",
	SSH_CIPHER_3DES:     "3des",
	SSH_CIPHER_RC4:      "rc4",
	SSH_CIPHER_BLOWFISH: "blowfish",
}

// CreateCipherMask returns a bitmask of chosen ciphers or panic
// if cipher not supported or length of chosen ciphers too small
// or too big.
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
			panic("ssh1: chosen cipher doesn't supported")
		}
		mask.addFlag(c)
	}

	return mask
}

// checkLength checks length of package read.
func checkLength(length uint32) error {
	if length <= 5 {
		return errors.New("ssh1: invalid packet length, packet too small")
	}
	if length > maxPacket {
		return errors.New("ssh1: invalid packet length, packet too large")
	}
	return nil
}

// See RFC, section The Binary Packet Protocol.
const maxPacket = 262144

type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

func newRC4(key, iv []byte) (cipher.Stream, error) {
	return rc4.NewCipher(key)
}

// streamPacketCipher is a packetCipher using a stream cipher.
type streamPacketCipher struct {
	cipher cipher.Stream

	seqNumBytes [4]byte
	length      [4]byte
	padding     []byte
	packetType  [1]byte
	data        []byte
	check       [4]byte
}

// packetTypeForError used when readCipherPacket return error.
// RFC, section Detailed Description of Packet Types and Formats says that
// SSH_MSG_NONE is never sent, so we can use it.
var packetTypeForError = [1]byte{msgNone}

// readCipherPacket reads and decrypt a single packet from the reader argument.
func (c *streamPacketCipher) readCipherPacket(seqNum uint32, r io.Reader) ([1]byte, []byte, error) {
	if _, err := io.ReadFull(r, c.length[:]); err != nil {
		return packetTypeForError, nil, err
	}

	length := binary.BigEndian.Uint32(c.length[:])
	if err := checkLength(length); err != nil {
		return packetTypeForError, nil, err
	}

	paddingLength := 8 - (length % 8)
	if uint32(cap(c.padding)) < paddingLength {
		c.padding = make([]byte, paddingLength)
	} else {
		c.padding = c.padding[:paddingLength]
	}
	if _, err := io.ReadFull(r, c.padding); err != nil {
		return packetTypeForError, nil, err
	}

	data := make([]byte, length-5+paddingLength)
	data = append(data, c.padding...)

	if _, err := io.ReadFull(r, c.packetType[:]); err != nil {
		return packetTypeForError, nil, err
	}
	data = append(data, c.packetType[:]...)

	if uint32(cap(c.data)) < length-5 {
		c.data = make([]byte, length-5)
	} else {
		c.data = c.data[:length-5]
	}
	if _, err := io.ReadFull(r, c.data); err != nil {
		return packetTypeForError, nil, err
	}
	data = append(data, c.data...)

	c.cipher.XORKeyStream(data, data)

	if _, err := io.ReadFull(r, c.check[:]); err != nil {
		return packetTypeForError, nil, err
	}

	checksum := crc32.ChecksumIEEE(c.data)
	if checksum != binary.BigEndian.Uint32(c.check[:]) {
		return packetTypeForError, nil, errors.New("ssh1: CRC32 checksum failed")
	}

	return c.packetType, c.data, nil
}

// writeCipherPacket encrypts and writes a single packet to the writer argument.
func (c *streamPacketCipher) writeCipherPacket(seqNum uint32, w io.Writer, rand io.Reader, packetType [1]byte, packet []byte) error {
	length := len(packetType) + len(packet) + 4
	if length > maxPacket {
		return errors.New("ssh1: packet too large")
	}

	binary.BigEndian.PutUint32(c.length[:], uint32(length))

	paddingLength := 8 - (length % 8)
	padding := c.padding[:paddingLength]
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}

	data := padding
	data = append(data, packetType[:]...)
	data = append(data, packet[:]...)

	checksum := crc32.ChecksumIEEE(data)
	var checkBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(checkBytes[:], checksum)

	data = append(data, checkBytes[:]...)

	c.cipher.XORKeyStream(data, data)

	if _, err := w.Write(c.length[:]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

type cfbCipher struct {
	encrypter cipher.Stream
	decrypter cipher.Stream

	seqNumBytes [4]byte
	length      [4]byte
	padding     []byte
	packetType  [1]byte
	data        []byte
	check       [4]byte
}

func newCFBCipher(c cipher.Block, key, iv []byte) packetCipher {
	cfb := &cfbCipher{
		encrypter: cipher.NewCFBEncrypter(c, iv),
		decrypter: cipher.NewCFBDecrypter(c, iv),
	}
	return cfb
}

// readCipherPacket reads and decrypt a single packet from the reader argument.
func (c *cfbCipher) readCipherPacket(seqNum uint32, r io.Reader) ([1]byte, []byte, error) {
	if _, err := io.ReadFull(r, c.length[:]); err != nil {
		return packetTypeForError, nil, err
	}

	length := binary.BigEndian.Uint32(c.length[:])
	if err := checkLength(length); err != nil {
		return packetTypeForError, nil, err
	}

	paddingLength := 8 - (length % 8)
	if uint32(cap(c.padding)) < paddingLength {
		c.padding = make([]byte, paddingLength)
	} else {
		c.padding = c.padding[:paddingLength]
	}
	if _, err := io.ReadFull(r, c.padding); err != nil {
		return packetTypeForError, nil, err
	}

	data := make([]byte, length-5+paddingLength)
	data = append(data, c.padding...)

	if _, err := io.ReadFull(r, c.packetType[:]); err != nil {
		return packetTypeForError, nil, err
	}
	data = append(data, c.packetType[:]...)

	if uint32(cap(c.data)) < length-5 {
		c.data = make([]byte, length-5)
	} else {
		c.data = c.data[:length-5]
	}
	if _, err := io.ReadFull(r, c.data); err != nil {
		return packetTypeForError, nil, err
	}
	data = append(data, c.data...)

	c.decrypter.XORKeyStream(data, data)

	if _, err := io.ReadFull(r, c.check[:]); err != nil {
		return packetTypeForError, nil, err
	}

	checksum := crc32.ChecksumIEEE(c.data)
	if checksum != binary.BigEndian.Uint32(c.check[:]) {
		return packetTypeForError, nil, errors.New("ssh1: CRC32 checksum failed")
	}

	return c.packetType, c.data, nil
}

// writeCipherPacket encrypts and writes a single packet to the writer argument.
func (c *cfbCipher) writeCipherPacket(seqNum uint32, w io.Writer, rand io.Reader, packetType [1]byte, packet []byte) error {
	length := len(packetType) + len(packet) + 4
	if length > maxPacket {
		return errors.New("ssh1: packet too large")
	}

	binary.BigEndian.PutUint32(c.length[:], uint32(length))

	paddingLength := 8 - (length % 8)
	padding := c.padding[:paddingLength]
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}

	data := padding
	data = append(data, packetType[:]...)
	data = append(data, packet[:]...)

	checksum := crc32.ChecksumIEEE(data)
	var checkBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(checkBytes[:], checksum)

	data = append(data, checkBytes[:]...)

	c.encrypter.XORKeyStream(data, data)

	if _, err := w.Write(c.length[:]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

func newIDEACFBCipher(key, iv []byte) (packetCipher, error) {
	c, err := idea.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cfb := newCFBCipher(c, key, iv)

	return cfb, nil
}

type cbcCipher struct {
	encrypter cipher.BlockMode
	decrypter cipher.BlockMode

	seqNumBytes [4]byte
	length      [4]byte
	padding     []byte
	packetType  [1]byte
	data        []byte
	check       [4]byte

	oracleCamouflage uint32
}

func newCBCCipher(c cipher.Block, key, iv []byte) packetCipher {
	cbc := &cbcCipher{
		encrypter: cipher.NewCBCEncrypter(c, iv),
		decrypter: cipher.NewCBCDecrypter(c, iv),
	}
	return cbc
}

const (
	cbcMinPacketSizeMultiple = 8
	cbcMinPacketSize         = 16
	cbcMinPaddingSize        = 4
)

func maxUInt32(a, b int) uint32 {
	if a > b {
		return uint32(a)
	}
	return uint32(b)
}

// readCipherPacket reads and decrypt a single packet from the reader argument.
func (c *cbcCipher) readCipherPacket(seqNum uint32, r io.Reader) ([1]byte, []byte, error) {
	if _, err := io.ReadFull(r, c.length[:]); err != nil {
		return packetTypeForError, nil, err
	}

	length := binary.BigEndian.Uint32(c.length[:])
	if err := checkLength(length); err != nil {
		return packetTypeForError, nil, err
	}

	paddingLength := 8 - (length % 8)
	if uint32(cap(c.padding)) < paddingLength {
		c.padding = make([]byte, paddingLength)
	} else {
		c.padding = c.padding[:paddingLength]
	}
	if _, err := io.ReadFull(r, c.padding); err != nil {
		return packetTypeForError, nil, err
	}

	data := make([]byte, length-5+paddingLength)
	data = append(data, c.padding...)

	if _, err := io.ReadFull(r, c.packetType[:]); err != nil {
		return packetTypeForError, nil, err
	}
	data = append(data, c.packetType[:]...)

	if uint32(cap(c.data)) < length-5 {
		c.data = make([]byte, length-5)
	} else {
		c.data = c.data[:length-5]
	}
	if _, err := io.ReadFull(r, c.data); err != nil {
		return packetTypeForError, nil, err
	}
	data = append(data, c.data...)

	c.decrypter.CryptBlocks(data, data)

	if _, err := io.ReadFull(r, c.check[:]); err != nil {
		return packetTypeForError, nil, err
	}

	checksum := crc32.ChecksumIEEE(c.data)
	if checksum != binary.BigEndian.Uint32(c.check[:]) {
		return packetTypeForError, nil, errors.New("ssh1: CRC32 checksum failed")
	}

	return c.packetType, c.data, nil
}

// writeCipherPacket encrypts and writes a single packet to the writer argument.
func (c *cbcCipher) writeCipherPacket(seqNum uint32, w io.Writer, rand io.Reader, packetType [1]byte, packet []byte) error {
	length := len(packetType) + len(packet) + 4
	if length > maxPacket {
		return errors.New("ssh1: packet too large")
	}

	binary.BigEndian.PutUint32(c.length[:], uint32(length))

	paddingLength := 8 - (length % 8)
	padding := c.padding[:paddingLength]
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}

	data := padding
	data = append(data, packetType[:]...)
	data = append(data, packet[:]...)

	checksum := crc32.ChecksumIEEE(data)
	var checkBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(checkBytes[:], checksum)

	data = append(data, checkBytes[:]...)

	c.encrypter.CryptBlocks(data, data)

	if _, err := w.Write(c.length[:]); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}

	return nil
}

func newDESCBCCipher(key, iv []byte) (packetCipher, error) {
	c, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := newCBCCipher(c, key, iv)

	return cbc, nil
}

func newTripleDESCBCCipher(key, iv []byte) (packetCipher, error) {
	c, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := newCBCCipher(c, key, iv)

	return cbc, nil
}

func newBlowfishCBCCipher(key, iv []byte) (packetCipher, error) {
	c, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := newCBCCipher(c, key, iv)

	return cbc, nil
}
