package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
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

	stdin, err := session.StdinPipe()
	if err != nil {
		log.Fatal("in pipe", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Fatal("out pipe", err)
	}

	go func(out io.Reader) {
		for {
			var buf = make([]byte, 500)
			if _, err := out.Read(buf); err != nil {
				log.Println(err)
			}
			fmt.Print(string(buf))
			buf = nil
		}
	}(stdout)

	session.Shell()

	_, err = stdin.Write([]byte("mkdir test\n"))
	if err != nil {
		log.Fatal("can't write 1", err)
	}
	_, err = stdin.Write([]byte("cd test\n"))
	if err != nil {
		log.Fatal("can't write 2", err)
	}
	_, err = stdin.Write([]byte("touch file.txt\n"))
	if err != nil {
		log.Fatal("can't write 3", err)
	}

	http.ListenAndServe(":8080", nil)
}
