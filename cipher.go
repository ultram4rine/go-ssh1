package ssh1

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"io"

	"github.com/dgryski/go-idea"
	"github.com/ultram4rine/go-ssh1/ssh13des"
	blowfish "github.com/ultram4rine/go-ssh1/ssh1blowfish"
)

const (
	// SSH_CIPHER_NONE is no encryption.
	SSH_CIPHER_NONE = iota
	// SSH_CIPHER_IDEA is IDEA in CFB mode.
	SSH_CIPHER_IDEA
	// SSH_CIPHER_DES is DES in CBC mode.
	SSH_CIPHER_DES
	// SSH_CIPHER_3DES is three independent DES-CBC ciphers used in EDE mode.
	SSH_CIPHER_3DES
	// SSH_CIPHER_TSS is not supported TRI's Simple Stream encryption in CBC mode.
	_
	// SSH_CIPHER_RC4 is RC4.
	SSH_CIPHER_RC4
	// SSH_CIPHER_BLOWFISH is Blowfish. It's not specified in RFC but used by OpenSSH.
	SSH_CIPHER_BLOWFISH
)

type cipherMode struct {
	keySize int
	ivSize  int
	create  func(key, iv []byte) (packetCipher, error)
}

// cipherModes documents properties of supported ciphers. Ciphers not included
// are not supported and will not be negotiated, even if explicitly requested in
// ClientConfig.Crypto.Ciphers.
var cipherModes = map[int]*cipherMode{
	SSH_CIPHER_IDEA:     {16, 8, newIDEACFBCipher},
	SSH_CIPHER_DES:      {8, 8, newDESCBCCipher},
	SSH_CIPHER_3DES:     {24, 8, newTripleDESCBCCipher},
	SSH_CIPHER_RC4:      {16, 0, newRC4},
	SSH_CIPHER_BLOWFISH: {32, 8, newBlowfishCBCCipher},
}

func chooseCipher(ciphersMask bitmask, ciphersOrder []int) (int, error) {
	for _, c := range ciphersOrder {
		if ciphersMask.hasFlag(c) {
			return c, nil
		}
	}
	return -1, errors.New("ssh1: no supported cipher was found")
}

const (
	// Packet length can't be lesser than 5 because
	// length of data is a 'length' - 5.
	minLength = 5

	// See RFC, section The Binary Packet Protocol.
	maxLength = 262144
)

// checkLength checks length of package read.
func checkLength(length uint32) error {
	if length < minLength {
		return errors.New("ssh1: invalid packet length, packet too small")
	}
	if length > maxLength {
		return errors.New("ssh1: invalid packet length, packet too large")
	}
	return nil
}

type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) {
	copy(dst, src)
}

func newRC4(key, iv []byte) (packetCipher, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &streamPacketCipher{cipher: cipher}, nil
}

// streamPacketCipher is a packetCipher using a stream cipher.
type streamPacketCipher struct {
	cipher cipher.Stream

	length     [4]byte
	padding    []byte
	packetType byte
	data       []byte
	check      [4]byte
}

// packetTypeForError used when readCipherPacket return error.
// RFC, section Detailed Description of Packet Types and Formats says that
// SSH_MSG_NONE is never sent, so we can use it.
var packetTypeForError = byte(msgNone)

// readCipherPacket reads and decrypt a single packet from the reader argument.
func (c *streamPacketCipher) readCipherPacket(r io.Reader) (byte, []byte, error) {
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

	// rest is all except 'length'.
	rest := make([]byte, 0, length+paddingLength)
	rest = append(rest, c.padding...)

	packetTypeBytes := make([]byte, 1)
	if _, err := io.ReadFull(r, packetTypeBytes); err != nil {
		return packetTypeForError, nil, err
	}
	c.packetType = packetTypeBytes[0]
	rest = append(rest, c.packetType)

	if uint32(cap(c.data)) < length-5 {
		c.data = make([]byte, length-5)
	} else {
		c.data = c.data[:length-5]
	}
	if _, err := io.ReadFull(r, c.data); err != nil {
		return packetTypeForError, nil, err
	}
	rest = append(rest, c.data...)

	if _, err := io.ReadFull(r, c.check[:]); err != nil {
		return packetTypeForError, nil, err
	}
	rest = append(rest, c.check[:]...)

	c.cipher.XORKeyStream(rest, rest)

	c.packetType = rest[paddingLength : paddingLength+1][0]
	c.data = rest[paddingLength+1 : len(rest)-4]

	checksum := ssh1CRC32(rest, len(rest)-4)
	if checksum != binary.BigEndian.Uint32(rest[len(rest)-4:]) {
		return packetTypeForError, nil, errors.New("ssh1: CRC32 checksum failed")
	}

	return c.packetType, c.data, nil
}

// writeCipherPacket encrypts and writes a single packet to the writer argument.
func (c *streamPacketCipher) writeCipherPacket(w io.Writer, rand io.Reader, packetType byte, packet []byte) error {
	// Packet type + data length + checksum.
	length := 1 + len(packet) + 4
	if err := checkLength(uint32(length)); err != nil {
		return err
	}

	binary.BigEndian.PutUint32(c.length[:], uint32(length))

	paddingLength := 8 - (length % 8)
	if cap(c.padding) < paddingLength {
		c.padding = make([]byte, paddingLength)
	} else {
		c.padding = c.padding[:paddingLength]
	}
	padding := c.padding
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}

	// rest is all except 'length'.
	rest := padding
	rest = append(rest, packetType)
	rest = append(rest, packet[:]...)

	checksum := ssh1CRC32(rest, len(rest))
	binary.BigEndian.PutUint32(c.check[:], checksum)

	rest = append(rest, c.check[:]...)

	c.cipher.XORKeyStream(rest, rest)

	if _, err := w.Write(append(c.length[:], rest...)); err != nil {
		return err
	}

	return nil
}

type cfbCipher struct {
	encrypter cipher.Stream
	decrypter cipher.Stream

	length     [4]byte
	padding    []byte
	packetType byte
	data       []byte
	check      [4]byte
}

func newCFBCipher(c cipher.Block, key, iv []byte) packetCipher {
	cfb := &cfbCipher{
		encrypter: cipher.NewCFBEncrypter(c, iv),
		decrypter: cipher.NewCFBDecrypter(c, iv),
	}
	return cfb
}

// readCipherPacket reads and decrypt a single packet from the reader argument.
func (c *cfbCipher) readCipherPacket(r io.Reader) (byte, []byte, error) {
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

	// rest is all except 'length'.
	rest := make([]byte, 0, length+paddingLength)
	rest = append(rest, c.padding...)

	packetTypeBytes := make([]byte, 1)
	if _, err := io.ReadFull(r, packetTypeBytes); err != nil {
		return packetTypeForError, nil, err
	}
	c.packetType = packetTypeBytes[0]
	rest = append(rest, c.packetType)

	if uint32(cap(c.data)) < length-5 {
		c.data = make([]byte, length-5)
	} else {
		c.data = c.data[:length-5]
	}
	if _, err := io.ReadFull(r, c.data); err != nil {
		return packetTypeForError, nil, err
	}
	rest = append(rest, c.data...)

	if _, err := io.ReadFull(r, c.check[:]); err != nil {
		return packetTypeForError, nil, err
	}
	rest = append(rest, c.check[:]...)

	c.decrypter.XORKeyStream(rest, rest)

	c.packetType = rest[paddingLength : paddingLength+1][0]
	c.data = rest[paddingLength+1 : len(rest)-4]

	checksum := ssh1CRC32(rest, len(rest)-4)
	if checksum != binary.BigEndian.Uint32(rest[len(rest)-4:]) {
		return packetTypeForError, nil, errors.New("ssh1: CRC32 checksum failed")
	}

	return c.packetType, c.data, nil
}

// writeCipherPacket encrypts and writes a single packet to the writer argument.
func (c *cfbCipher) writeCipherPacket(w io.Writer, rand io.Reader, packetType byte, packet []byte) error {
	// Packet type + data length + checksum.
	length := 1 + len(packet) + 4
	if err := checkLength(uint32(length)); err != nil {
		return err
	}

	binary.BigEndian.PutUint32(c.length[:], uint32(length))

	paddingLength := 8 - (length % 8)
	if cap(c.padding) < paddingLength {
		c.padding = make([]byte, paddingLength)
	} else {
		c.padding = c.padding[:paddingLength]
	}
	padding := c.padding[:paddingLength]
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}

	// rest is all except 'length'.
	rest := padding
	rest = append(rest, packetType)
	rest = append(rest, packet[:]...)

	checksum := ssh1CRC32(rest, len(rest))
	var checkBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(checkBytes[:], checksum)

	rest = append(rest, checkBytes[:]...)

	c.encrypter.XORKeyStream(rest, rest)

	if _, err := w.Write(c.length[:]); err != nil {
		return err
	}
	if _, err := w.Write(rest); err != nil {
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

	length     [4]byte
	padding    []byte
	packetType byte
	data       []byte
	check      [4]byte
}

func newCBCCipher(c cipher.Block, key, iv []byte) packetCipher {
	cbc := &cbcCipher{
		encrypter: cipher.NewCBCEncrypter(c, iv),
		decrypter: cipher.NewCBCDecrypter(c, iv),
	}
	return cbc
}

// readCipherPacket reads and decrypt a single packet from the reader argument.
func (c *cbcCipher) readCipherPacket(r io.Reader) (byte, []byte, error) {
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

	// rest is all except 'length'.
	rest := make([]byte, 0, length+paddingLength)
	rest = append(rest, c.padding...)

	packetTypeBytes := make([]byte, 1)
	if _, err := io.ReadFull(r, packetTypeBytes); err != nil {
		return packetTypeForError, nil, err
	}
	c.packetType = packetTypeBytes[0]
	rest = append(rest, c.packetType)

	if uint32(cap(c.data)) < length-5 {
		c.data = make([]byte, length-5)
	} else {
		c.data = c.data[:length-5]
	}
	if _, err := io.ReadFull(r, c.data); err != nil {
		return packetTypeForError, nil, err
	}
	rest = append(rest, c.data...)

	if _, err := io.ReadFull(r, c.check[:]); err != nil {
		return packetTypeForError, nil, err
	}
	rest = append(rest, c.check[:]...)

	c.decrypter.CryptBlocks(rest, rest)

	c.packetType = rest[paddingLength : paddingLength+1][0]
	c.data = rest[paddingLength+1 : len(rest)-4]

	checksum := ssh1CRC32(rest, len(rest)-4)
	if checksum != binary.BigEndian.Uint32(rest[len(rest)-4:]) {
		return packetTypeForError, nil, errors.New("ssh1: CRC32 checksum failed")
	}

	return c.packetType, c.data, nil
}

// writeCipherPacket encrypts and writes a single packet to the writer argument.
func (c *cbcCipher) writeCipherPacket(w io.Writer, rand io.Reader, packetType byte, packet []byte) error {
	// Packet type + data length + checksum.
	length := 1 + len(packet) + 4
	if err := checkLength(uint32(length)); err != nil {
		return err
	}

	binary.BigEndian.PutUint32(c.length[:], uint32(length))

	paddingLength := 8 - (length % 8)
	if cap(c.padding) < paddingLength {
		c.padding = make([]byte, paddingLength)
	} else {
		c.padding = c.padding[:paddingLength]
	}
	padding := c.padding[:paddingLength]
	if _, err := io.ReadFull(rand, padding); err != nil {
		return err
	}

	// rest is all except 'length'.
	rest := padding
	rest = append(rest, packetType)
	rest = append(rest, packet[:]...)

	checksum := ssh1CRC32(rest, len(rest))
	var checkBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(checkBytes[:], checksum)

	rest = append(rest, checkBytes[:]...)

	c.encrypter.CryptBlocks(rest, rest)

	if _, err := w.Write(c.length[:]); err != nil {
		return err
	}
	if _, err := w.Write(rest); err != nil {
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
	c1, err := des.NewCipher(key[:8])
	if err != nil {
		return nil, err
	}
	c2, err := des.NewCipher(key[8:16])
	if err != nil {
		return nil, err
	}
	c3, err := des.NewCipher(key[16:])
	if err != nil {
		return nil, err
	}

	enc := ssh13des.NewEncrypter(c1, c2, c3, iv)
	dec := ssh13des.NewDecrypter(c1, c2, c3, iv)

	cbc := &cbcCipher{
		encrypter: enc,
		decrypter: dec,
	}

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
