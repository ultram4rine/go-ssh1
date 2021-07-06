package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"log"
	"math/big"
	"net"

	"github.com/ultram4rine/go-ssh1"
)

func main() {
	conn, err := net.Dial("tcp", "192.168.111.55:22")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// version exchange.
	version, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(version)

	if _, err := conn.Write([]byte("SSH-1.5-Go\n")); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Version sended")

	var reader = bufio.NewReader(conn)

	// read length.
	fmt.Println("Read length")
	var lenBytes = make([]byte, 4)
	_, err = reader.Read(lenBytes)
	if err != nil {
		log.Fatal(err)
	}

	for _, b := range lenBytes {
		fmt.Printf("%08b ", b)
	}
	var length = binary.BigEndian.Uint32(lenBytes)
	fmt.Printf("= %d\n", length)

	// read padding.
	fmt.Println("Read padding")
	var paddingBytes = make([]byte, (8 - (length % 8)))
	_, err = reader.Read(paddingBytes)
	if err != nil {
		log.Fatal(err)
	}

	for _, b := range paddingBytes {
		fmt.Printf("%08b ", b)
	}
	var padding = binary.BigEndian.Uint32(paddingBytes)
	fmt.Printf("= %d\n", padding)

	// read packet type.
	fmt.Println("Read packet type")
	var packetTypeBytes = make([]byte, 1)
	_, err = reader.Read(packetTypeBytes)
	if err != nil {
		log.Fatal(err)
	}

	for _, b := range packetTypeBytes {
		fmt.Printf("%08b ", b)
	}
	var packetType = uint8(packetTypeBytes[0])
	fmt.Printf("= %d\n", packetType)

	// read data.
	fmt.Println("Read data")
	var dataBytes = make([]byte, length-5)
	_, err = reader.Read(dataBytes)
	if err != nil {
		log.Fatal(err)
	}
	for _, b := range dataBytes {
		fmt.Printf("%08b ", b)
	}

	// decode data.
	fmt.Println("\nDecode data")
	var (
		ciphersBytes = dataBytes[length-5-4-4 : length-5-4]
		authBytes    = dataBytes[length-5-4 : length-5]
	)

	fmt.Println("Ciphers bitmask")
	for _, b := range ciphersBytes {
		fmt.Printf("%08b ", b)
	}
	var ciphers = binary.BigEndian.Uint32(ciphersBytes)
	fmt.Printf("= %d\n", ciphers)

	fmt.Println("Auth bitmask")
	for _, b := range authBytes {
		fmt.Printf("%08b ", b)
	}
	var auth = binary.BigEndian.Uint32(authBytes)
	fmt.Printf("= %d\n", auth)

	// read crc.
	fmt.Println("Read checksum")
	var crcBytes = make([]byte, 4)
	_, err = reader.Read(crcBytes)
	if err != nil {
		log.Fatal(err)
	}

	for _, b := range crcBytes {
		fmt.Printf("%08b ", b)
	}
	var crc = binary.BigEndian.Uint32(crcBytes)
	fmt.Printf("= %d\n", crc)

	data := make([]byte, 0, (8-(length%8))+1+length-5)
	data = append(data, paddingBytes...)
	data = append(data, packetTypeBytes...)
	data = append(data, dataBytes...)
	fmt.Println(len(data))

	checksum := ssh1CRC32(data, len(data))
	fmt.Printf("%d == %d ? %t\n", crc, checksum, checksum == crc)

	var pubKey pubKeySmsg
	err = ssh1.Unmarshal(packetTypeBytes[0], dataBytes, &pubKey)
	log.Println(err)

	fmt.Println(pubKey)

	sessionID := md5.Sum(
		bytes.Join(
			[][]byte{
				pubKey.HostKeyPubModulus.Bytes(),
				pubKey.ServerKeyPubModulus.Bytes(),
				pubKey.Cookie[:],
			},
			[]byte("")),
	)
	fmt.Println(sessionID)

	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	for i := 0; i < 16; i++ {
		sessionKey[i] ^= sessionID[i]
	}
	res := pubKey.ServerKeyPubModulus.Cmp(pubKey.HostKeyPubModulus)
	var (
		fst = new(rsa.PublicKey)
		snd = new(rsa.PublicKey)
	)
	if res == -1 {
		fst.N = pubKey.ServerKeyPubModulus
		fst.E = int(pubKey.ServerKeyPubExponent.Int64())
		snd.N = pubKey.HostKeyPubModulus
		snd.E = int(pubKey.HostKeyPubExponent.Int64())
	} else {
		fst.N = pubKey.HostKeyPubModulus
		snd.E = int(pubKey.HostKeyPubExponent.Int64())
		snd.N = pubKey.ServerKeyPubModulus
		fst.E = int(pubKey.ServerKeyPubExponent.Int64())
	}
	sessionKey, err = rsa.EncryptPKCS1v15(rand.Reader, fst, sessionKey)
	if err != nil {
		log.Fatal(err)
	}
	sessionKey, err = rsa.EncryptPKCS1v15(rand.Reader, snd, sessionKey)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(sessionKey))

	var sessionKeyMsg sessionKeyCmsg
	sessionKeyMsg.Cipher = ssh1.SSH_CIPHER_DES
	sessionKeyMsg.Cookie = pubKey.Cookie
	var key = new(big.Int)
	sessionKeyMsg.SessionKey = key.SetBytes(sessionKey)
	sessionKeyMsg.ProtocolFlags = 0
	pt, dataMsg := ssh1.Marshal(sessionKeyMsg)
	fmt.Println(pt, dataMsg)
}

// Return a 32-bit CRC of the data.
func ssh1CRC32(data []byte, len int) uint32 {
	var crc32val uint32
	for i := 0; i < len; i++ {
		crc32val = crc32.IEEETable[(crc32val^uint32(data[i]))&0xff] ^ (crc32val >> 8)
	}
	return crc32val
}

type pubKeySmsg struct {
	Cookie               [8]byte `ssh1type:"2"`
	ServerKey            uint32
	ServerKeyPubExponent *big.Int
	ServerKeyPubModulus  *big.Int
	HostKey              uint32
	HostKeyPubExponent   *big.Int
	HostKeyPubModulus    *big.Int
	ProtocolFlags        uint32
	CipherMask           uint32
	AuthMask             uint32
}

type sessionKeyCmsg struct {
	Cipher        byte `ssh1type:"3"`
	Cookie        [8]byte
	SessionKey    *big.Int
	ProtocolFlags uint32
}