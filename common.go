package ssh1

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"time"
)

const protocolMajor = 1
const protocolMinor = 5

var packageVersion = fmt.Sprintf("SSH-%d.%d-Go", protocolMajor, protocolMinor)

// unexpectedMessageError results when the SSH message that we received didn't
// match what we wanted.
func unexpectedMessageError(expected, got uint8) error {
	return fmt.Errorf("ssh: unexpected message type %d (expected %d)", got, expected)
}

// parseError results from a malformed SSH message.
func parseError(tag uint8) error {
	return fmt.Errorf("ssh: parse error in message type %d", tag)
}

// Return a 32-bit CRC of the data.
func ssh1CRC32(data []byte, len int) uint32 {
	var crc32val uint32
	for i := 0; i < len; i++ {
		crc32val = crc32.IEEETable[(crc32val^uint32(data[i]))&0xff] ^ (crc32val >> 8)
	}
	return crc32val
}

// createSessionKey.
func encryptSessionKey(sessionKey [32]byte, sessionID [16]byte, serverKey *rsa.PublicKey, hostKey *rsa.PublicKey) ([]byte, error) {
	var (
		smaller *rsa.PublicKey
		larger  *rsa.PublicKey
		res     = serverKey.N.Cmp(hostKey.N)
		err     error
	)
	if res == -1 {
		smaller = serverKey
		larger = hostKey
	} else {
		smaller = hostKey
		larger = serverKey
	}

	encryptedSessionKey := make([]byte, 32)
	copy(encryptedSessionKey, sessionKey[:])
	for i := 0; i < 16; i++ {
		encryptedSessionKey[i] ^= sessionID[i]
	}

	encryptedSessionKey, err = rsa.EncryptPKCS1v15(rand.Reader, smaller, encryptedSessionKey)
	if err != nil {
		return []byte{}, err
	}
	encryptedSessionKey, err = rsa.EncryptPKCS1v15(rand.Reader, larger, encryptedSessionKey)
	if err != nil {
		return []byte{}, err
	}

	return encryptedSessionKey, nil
}

// HostKeyCallback is the function type used for verifying server
// keys.  A HostKeyCallback must return nil if the host key is OK, or
// an error to reject it. It receives the hostname as passed to Dial
// or NewClientConn. The remote address is the RemoteAddr of the
// net.Conn underlying the SSH connection.
type HostKeyCallback func(hostname string, remote net.Addr, key *rsa.PublicKey) error

// BannerCallback is the function type used for treat the banner sent by
// the server. A BannerCallback receives the message sent by the remote server.
type BannerCallback func(message string) error

// Config contains configuration data common to both ServerConfig and
// ClientConfig.
type Config struct {
	// Rand provides the source of entropy for cryptographic
	// primitives. If Rand is nil, the cryptographic random reader
	// in package crypto/rand will be used.
	Rand io.Reader

	// The ciphers order to choose cipher. If unspecified then a sensible
	// default is used.
	CiphersOrder []int

	// User contains the username to authenticate as.
	User string

	// Password contains the password to authenticate.
	Password string

	// The auth methods order to choose. If unspecified then a sensible
	// default is used.
	AuthOrder []int

	// HostKeyCallback is called during the cryptographic
	// handshake to validate the server's host key. The client
	// configuration must supply this callback for the connection
	// to succeed. The functions InsecureIgnoreHostKey or
	// FixedHostKey can be used for simplistic host key checks.
	HostKeyCallback HostKeyCallback

	// BannerCallback is called during the SSH dance to display a custom
	// server's message. The client configuration can supply this callback to
	// handle it as wished. The function BannerDisplayStderr can be used for
	// simplistic display on Stderr.
	BannerCallback BannerCallback

	// ClientVersion contains the version identification string that will
	// be used for the connection. If empty, a reasonable default is used.
	Version string

	// Timeout is the maximum amount of time for the TCP connection to establish.
	//
	// A Timeout of zero means no timeout.
	Timeout time.Duration
}

// SetDefaults sets sensible values for unset fields in config. This is
// exported for testing: Configs passed to SSH functions are copied and have
// default values set automatically.
func (c *Config) SetDefaults() {
	if c.Rand == nil {
		c.Rand = rand.Reader
	}
	if len(c.CiphersOrder) == 0 {
		c.CiphersOrder = append(c.CiphersOrder, SSH_CIPHER_DES, SSH_CIPHER_3DES)
	}
	if len(c.AuthOrder) == 0 {
		c.AuthOrder = append(c.AuthOrder, SSH_AUTH_PASSWORD)
	}
	if c.Version == "" {
		c.Version = packageVersion
	}
}
