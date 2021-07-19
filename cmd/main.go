package main

import (
	"fmt"
	"time"

	"github.com/ultram4rine/go-ssh1"
)

func main() {
	_, err := ssh1.Dial("localhost:2222", &ssh1.Config{
		CiphersOrder:    []int{ssh1.SSH_CIPHER_DES},
		User:            "test",
		Password:        "test",
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh1.InsecureIgnoreHostKey(),
	})
	if err != nil {
		fmt.Println(err)
	}
}
