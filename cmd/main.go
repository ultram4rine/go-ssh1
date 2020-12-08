package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"log"
	"net"
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

	if _, err := conn.Write([]byte(version)); err != nil {
		log.Fatal(err)
	}
	fmt.Println("version sended")

	var reader = bufio.NewReader(conn)

	// read length.
	fmt.Println("Read length")
	var lenBytes = make([]byte, 4)
	n, err := reader.Read(lenBytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("n must be 4: %d\n", n)

	for _, b := range lenBytes {
		fmt.Printf("%08b ", b)
	}
	var length = binary.BigEndian.Uint32(lenBytes)
	fmt.Printf("= %d\n", length)

	// read padding.
	fmt.Println("Read padding")
	var paddingBytes = make([]byte, (8 - (length % 8)))
	n, err = reader.Read(paddingBytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("n must be %d: %d\n", (8 - (length % 8)), n)

	for _, b := range paddingBytes {
		fmt.Printf("%08b ", b)
	}
	var padding = binary.BigEndian.Uint32(paddingBytes)
	fmt.Printf("= %d\n", padding)

	// read packet type.
	fmt.Println("Read packet type")
	var packetTypeBytes = make([]byte, 1)
	n, err = reader.Read(packetTypeBytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("n must be 1: %d\n", n)

	for _, b := range packetTypeBytes {
		fmt.Printf("%08b ", b)
	}
	var packetType = uint8(packetTypeBytes[0])
	fmt.Printf("= %d\n", packetType)

	// read data.
	fmt.Println("Read data")
	var dataBytes = make([]byte, length-5)
	n, err = reader.Read(dataBytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("n must be %d: %d\n", length-5, n)

	// decode data.
	fmt.Println("Decode data")
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
	n, err = reader.Read(crcBytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("n must be 4: %d\n", n)

	for _, b := range crcBytes {
		fmt.Printf("%08b ", b)
	}
	var crc = binary.BigEndian.Uint32(crcBytes)
	fmt.Printf("= %d\n", crc)

	data := make([]byte, length)
	data = append(data, paddingBytes...)
	data = append(data, packetTypeBytes...)
	data = append(data, dataBytes...)
	checksum := crc32.ChecksumIEEE(data)
	fmt.Printf("%d == %d ? %t", crc, checksum, checksum == crc)
}
