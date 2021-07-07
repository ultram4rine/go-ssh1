package main

import (
	"fmt"
	"time"

	"github.com/ultram4rine/go-ssh1"
)

func main() {
	_, err := ssh1.Dial("192.168.111.55:22", &ssh1.Config{Timeout: 30 * time.Second, HostKeyCallback: ssh1.InsecureIgnoreHostKey()})
	fmt.Println(err)
}
