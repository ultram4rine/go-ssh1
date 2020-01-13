package ssh1

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
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

// CreateCipherMask returns a bitmask of choosen ciphers or panic
// if cipher not supported or length of choosen ciphers too small
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
			panic("ssh1: choosen cipher doesn't supported")
		}
		mask.addFlag(c)
	}

	return mask
}

// See RFC, section The Binary Packet Protocol.
const maxPacket = 262144

type noneCipher struct{}

func (c noneCipher) XORKeyStream(dst, src []byte) {
	copy(dst, src)
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
	if length <= 5 {
		return packetTypeForError, nil, errors.New("ssh1: invalid packet length, packet too small")
	}
	if length > maxPacket {
		return packetTypeForError, nil, errors.New("ssh1: invalid packet length, packet too large")
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
