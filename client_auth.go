package ssh1

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"net"
)

const (
	// SSH_AUTH_RHOSTS is auth using .rhosts file
	SSH_AUTH_RHOSTS = iota + 1
	// SSH_AUTH_RSA is RSA auth
	SSH_AUTH_RSA
	// SSH_AUTH_PASSWORD is auth using password
	SSH_AUTH_PASSWORD
	// SSH_AUTH_RHOSTS_RSA is auth using .rhosts file with RSA
	SSH_AUTH_RHOSTS_RSA
	SSH_AUTH_TIS
	SSH_AUTH_KERBEROS
	passKerberosTGT
	passAFSToken = 21
)

var authMethods = map[int]string{
	SSH_AUTH_RHOSTS:     "rhosts",
	SSH_AUTH_RSA:        "rsa",
	SSH_AUTH_PASSWORD:   "password",
	SSH_AUTH_RHOSTS_RSA: "rhosts_rsa",
}

// CreateAuthMask returns a bitmask of chosen auth methods or panic
// if auth method not supported or length of chosen methods too small
// or too big
func CreateAuthMask(methods ...int) *Bitmask {
	var mask = new(Bitmask)

	if len(methods) <= 0 {
		panic("ssh1: too few auth methods")
	}
	if len(methods) > len(authMethods) {
		panic("ssh1: too many auth methods")
	}

	for _, m := range methods {
		if _, ok := authMethods[m]; !ok {
			panic("ssh1: chosen auth method doesn't supported")
		}
		mask.addFlag(m)
	}

	return mask
}

func clientAuth(reader, writer connectionState, conn net.Conn, config *Config) error {
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	var pUser = userCmsg{
		UserName: config.User,
	}
	pt, p := Marshal(pUser)
	if pt != cmsgUser {
		return fmt.Errorf("SSH_CMSG_USER (%d) should be sended, found %d", cmsgUser, pt)
	}

	if err := writer.writePacket(w, rand.Reader, pt, p); err != nil {
		return err
	}

	pt, _, err := reader.readPacket(r)
	if err != nil {
		return err
	}
	if pt == smsgSuccess {
		return nil
	}
	if pt != smsgFailure {
		fmt.Println("there")
		return fmt.Errorf("SSH_SMSG_FAILURE (%d) expected, got %d", smsgFailure, pt)
	}

	var pPassword = authPasswordCmsg{
		Password: config.Password,
	}
	pt, p2 := Marshal(pPassword)
	if pt != cmsgAuthPassword {
		return fmt.Errorf("SSH_CMSG_AUTH_PASSWORD (%d) should be sended, found %d", cmsgAuthPassword, pt)
	}

	if err := writer.writePacket(w, rand.Reader, pt, p2); err != nil {
		return err
	}

	pt, _, err = reader.readPacket(r)
	if err != nil {
		return err
	}
	if pt != smsgSuccess {
		fmt.Println("here")
		return fmt.Errorf("SSH_SMSG_SUCCESS (%d) expected, got %d", smsgSuccess, pt)
	}

	return nil
}
