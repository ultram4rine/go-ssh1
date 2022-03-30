package main

import (
	"log"
	"time"

	"github.com/ultram4rine/go-ssh1"
)

func main() {
	client, err := ssh1.Dial("localhost:2222", &ssh1.Config{
		CiphersOrder:    []int{ssh1.SSH_CIPHER_BLOWFISH, ssh1.SSH_CIPHER_3DES, ssh1.SSH_CIPHER_DES},
		User:            "root",
		AuthMethods:     []ssh1.AuthMethod{ssh1.Password("alpine")},
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh1.InsecureIgnoreHostKey(),
	})
	if err != nil {
		log.Fatalf("error connecting to server: %v", err)
	}

	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("error creating session: %v", err)
	}
	defer session.Close()

	modes := ssh1.TerminalModes{
		ssh1.ECHO:          1,
		ssh1.TTY_OP_ISPEED: 14400,
		ssh1.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", 60, 80, modes); err != nil {
		log.Fatalf("error requesting pty: %v", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		log.Fatalf("error creating stdin pipe: %v", err)
	}

	if err := session.Shell(); err != nil {
		log.Fatalf("error starting shell: %v", err)
	}

	if _, err := stdin.Write([]byte("mkdir test\n")); err != nil {
		log.Fatalf("error creating directory: %v", err)
	}
	time.Sleep(time.Second / 2)

	if _, err := stdin.Write([]byte("cd test\n")); err != nil {
		log.Fatalf("error cding to directory: %v", err)
	}
	time.Sleep(time.Second / 2)

	if _, err := stdin.Write([]byte("touch file.txt\n")); err != nil {
		log.Fatalf("error creating file: %v", err)
	}
	time.Sleep(time.Second / 2)
}
