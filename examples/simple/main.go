package main

import (
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

	session, err := client.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	modes := ssh1.TerminalModes{
		ssh1.ECHO:          1,
		ssh1.TTY_OP_ISPEED: 14400,
		ssh1.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", 60, 80, modes); err != nil {
		log.Fatal(err)
	}

	session.Shell()

	_, res, err := session.Run("echo '1'")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("first", res)

	_, res, err = session.Run("echo '2'")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("second", res)

	_, res, err = session.Run("echo '3'")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("third", res)
}
