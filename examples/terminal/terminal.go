// This example based on https://gist.github.com/atotto/ba19155295d95c8d75881e145c751372.

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ultram4rine/go-ssh1"
	"golang.org/x/term"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := run(ctx); err != nil {
			log.Print(err)
		}
		cancel()
	}()

	select {
	case <-sig:
		cancel()
	case <-ctx.Done():
	}
}

func run(ctx context.Context) error {
	config := &ssh1.Config{
		CiphersOrder:    []int{ssh1.SSH_CIPHER_DES},
		User:            "test",
		AuthMethods:     []ssh1.AuthMethod{ssh1.Password("test")},
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh1.InsecureIgnoreHostKey(),
	}

	client, err := ssh1.Dial("localhost:2222", config)
	if err != nil {
		return fmt.Errorf("cannot connect: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open new session: %v", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	state, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("terminal make raw: %s", err)
	}
	defer term.Restore(fd, state)

	w, h, err := term.GetSize(fd)
	if err != nil {
		return fmt.Errorf("terminal get size: %s", err)
	}

	modes := ssh1.TerminalModes{
		ssh1.ECHO:          1,
		ssh1.TTY_OP_ISPEED: 14400,
		ssh1.TTY_OP_OSPEED: 14400,
	}

	terminal := os.Getenv("TERM")
	if terminal == "" {
		terminal = "xterm-256color"
	}
	if err := session.RequestPty(terminal, h, w, modes); err != nil {
		return fmt.Errorf("session xterm: %s", err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	if err := session.Shell(); err != nil {
		return fmt.Errorf("session shell: %s", err)
	}

	if err := session.Wait(); err != nil {
		if e, ok := err.(*ssh1.ExitError); ok {
			switch e.ExitStatus() {
			case 130:
				return nil
			}
		}
		return fmt.Errorf("ssh1: %s", err)
	}

	return nil
}
