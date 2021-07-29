package main

import (
	"fmt"
	"log"
	"time"

	"github.com/ultram4rine/go-ssh1"
)

func main() {
	client, err := ssh1.Dial("localhost:2222", &ssh1.Config{
		CiphersOrder:    []int{ssh1.SSH_CIPHER_BLOWFISH, ssh1.SSH_CIPHER_3DES, ssh1.SSH_CIPHER_DES},
		User:            "test",
		AuthMethods:     []ssh1.AuthMethod{ssh1.Password("test")},
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh1.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatal(err)
	}

	str, err := client.ExecCmd("echo hello ssh1!")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(str)
}
