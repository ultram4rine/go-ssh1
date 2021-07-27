// This example based on https://gist.github.com/atotto/ba19155295d95c8d75881e145c751372.

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ultram4rine/go-ssh1"
	terminal "golang.org/x/term"
)

var (
	user     = flag.String("l", "", "login_name")
	password = flag.String("pass", "", "password")
	port     = flag.Int("p", 22, "port")
)

func main() {
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

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
		Password:        "test",
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh1.InsecureIgnoreHostKey(),
	}

	hostport := fmt.Sprintf("%s:%d", flag.Arg(0), *port)
	client, err := ssh1.Dial(hostport, config)
	if err != nil {
		return fmt.Errorf("cannot connect %v: %v", hostport, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("cannot open new session: %v", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	state, err := terminal.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("terminal make raw: %s", err)
	}
	defer terminal.Restore(fd, state)

	w, h, err := terminal.GetSize(fd)
	if err != nil {
		return fmt.Errorf("terminal get size: %s", err)
	}

	modes := ssh1.TerminalModes{
		ssh1.ECHO:          1,
		ssh1.TTY_OP_ISPEED: 14400,
		ssh1.TTY_OP_OSPEED: 14400,
	}

	term := os.Getenv("TERM")
	if term == "" {
		term = "xterm-256color"
	}
	if err := session.RequestPty(term, h, w, modes); err != nil {
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
