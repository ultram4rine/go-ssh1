package ssh1

import (
	"crypto/rand"
	"io"
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

type authResult int

const (
	authFailure authResult = iota
	authSuccess
)

// clientAuthenticate authenticates with the remote server.
// See RFC, sections Declaring the User Name and Authentication Phase.
func clientAuthenticate(t *transport, config *Config) error {
	if err := t.writePacket(Marshal(&userCmsg{UserName: config.User})); err != nil {
		return err
	}
	pt, _, err := t.readPacket()
	if err != nil {
		return err
	}

	switch pt {
	case smsgSuccess:
		return nil
	case smsgFailure:
		{
			for _, method := range config.AuthMethods {
				res, err := method.auth(nil, "", t, rand.Reader)
				if err != nil {
					return err
				}
				if res == authSuccess {
					break
				}
			}
			return nil
		}
	default:
		return unexpectedMessageError(smsgFailure, pt)
	}
}

// An AuthMethod represents an instance of an RFC 4252 authentication method.
type AuthMethod interface {
	// auth authenticates user over transport t.
	// Returns true if authentication is successful.
	// If authentication is not successful, a []string of alternative
	// method names is returned. If the slice is nil, it will be ignored
	// and the previous set of possible methods will be reused.
	auth(session []byte, user string, p packetConn, rand io.Reader) (authResult, error)

	// method returns the RFC 4252 method name.
	method() string
}

// passwordCallback is an AuthMethod that fetches the password through
// a function call, e.g. by prompting the user.
type passwordCallback func() (password string, err error)

func (cb passwordCallback) auth(session []byte, user string, c packetConn, rand io.Reader) (authResult, error) {
	pw, err := cb()
	if err != nil {
		return authFailure, err
	}

	if err := c.writePacket(Marshal(&authPasswordCmsg{
		Password: pw,
	})); err != nil {
		return authFailure, err
	}

	return handleAuthResponse(c)
}

func (cb passwordCallback) method() string {
	return "password"
}

// Password returns an AuthMethod using the given password.
func Password(secret string) AuthMethod {
	return passwordCallback(func() (string, error) { return secret, nil })
}

// PasswordCallback returns an AuthMethod that uses a callback for
// fetching a password.
func PasswordCallback(prompt func() (secret string, err error)) AuthMethod {
	return passwordCallback(prompt)
}

// handleAuthResponse returns whether the preceding authentication request succeeded
// along with a list of remaining authentication methods to try next and
// an error if an unexpected response was received.
func handleAuthResponse(c packetConn) (authResult, error) {
	for {
		pt, _, err := c.readPacket()
		if err != nil {
			return authFailure, err
		}

		switch pt {
		case smsgSuccess:
			return authSuccess, nil
		default:
			return authFailure, unexpectedMessageError(smsgSuccess, pt)
		}
	}
}
