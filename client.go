package ssh1

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
)

// Client implements a traditional SSH client that supports shells,
// subprocesses, TCP port/streamlocal forwarding and tunneled dialing.
type Client struct {
	conn *sshConn
	t    *transport
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// NewClient creates a Client on top of the given connection.
/*func NewClient(c Conn, chans <-chan NewChannel, reqs <-chan *Request) *Client {
	conn := &Client{
		Conn:            c,
		channelHandlers: make(map[string]chan NewChannel, 1),
	}

	go conn.handleGlobalRequests(reqs)
	go conn.handleChannelOpens(chans)
	go func() {
		conn.Wait()
		conn.forwards.closeAll()
	}()
	return conn
}

func (c *Client) handleGlobalRequests(incoming <-chan *Request) {
	for r := range incoming {
		// This handles keepalive messages and matches
		// the behaviour of OpenSSH.
		r.Reply(false, nil)
	}
}

// handleChannelOpens channel open messages from the remote side.
func (c *Client) handleChannelOpens(in <-chan NewChannel) {
	for ch := range in {
		c.mu.Lock()
		handler := c.channelHandlers[ch.ChannelType()]
		c.mu.Unlock()

		if handler != nil {
			handler <- ch
		} else {
			ch.Reject(UnknownChannelType, fmt.Sprintf("unknown channel type: %v", ch.ChannelType()))
		}
	}

	c.mu.Lock()
	for _, ch := range c.channelHandlers {
		close(ch)
	}
	c.channelHandlers = nil
	c.mu.Unlock()
}*/

// NewClientConn establishes an authenticated SSH connection using c
// as the underlying transport.  The Request and NewChannel channels
// must be serviced or the connection will hang.
func NewClientConn(c net.Conn, addr string, config *Config) (*transport, *sshConn, error) {
	conf := *config
	conf.SetDefaults()
	if conf.HostKeyCallback == nil {
		c.Close()
		return nil, nil, errors.New("ssh1: must specify HostKeyCallback")
	}

	conn := &sshConn{conn: c, user: conf.User}

	t, err := conn.handshake(addr, &conf)
	if err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("ssh1: handshake failed: %v", err)
	}
	return t, conn, nil
}

// clientHandshake performs the client side key exchange. See RFC 4253 Section
// 7.
func (c *sshConn) handshake(dialAddress string, config *Config) (*transport, error) {
	if config.Version != "" {
		c.clientVersion = []byte(config.Version)
	} else {
		c.clientVersion = []byte(packageVersion)
	}

	var err error
	c.serverVersion, err = exchangeVersions(c.conn, c.clientVersion)
	if err != nil {
		return nil, err
	}

	t, err := keyExchange(c.conn, config)
	if err != nil {
		return nil, err
	}

	if err = clientAuthenticate(t, config); err != nil {
		return nil, err
	}

	return t, nil
}

// Dial starts a client connection to the given SSH server. It is a
// convenience function that connects to the given network address,
// initiates the SSH handshake, and then sets up a Client.  For access
// to incoming channels and requests, use net.Dial with NewClientConn
// instead.
func Dial(addr string, config *Config) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, config.Timeout)
	if err != nil {
		return nil, err
	}
	t, c, err := NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return &Client{conn: c, t: t}, err
}

// InsecureIgnoreHostKey returns a function that can be used for
// ClientConfig.HostKeyCallback to accept any host key. It should
// not be used for production code.
func InsecureIgnoreHostKey() HostKeyCallback {
	return func(hostname string, remote net.Addr, key *rsa.PublicKey) error {
		return nil
	}
}

// BannerDisplayStderr returns a function that can be used for
// ClientConfig.BannerCallback to display banners on os.Stderr.
func BannerDisplayStderr() BannerCallback {
	return func(banner string) error {
		_, err := os.Stderr.WriteString(banner)

		return err
	}
}

// keyExchange.
func keyExchange(conn net.Conn, config *Config) (t *transport, err error) {
	// Pass empty buffer for padding because it zeroes if not encrypting.
	t = newTransport(conn, bytes.NewBuffer(make([]byte, 8)))

	pt, p, err := t.readPacket()
	if err != nil {
		return
	}
	if pt != smsgPublicKey {
		// err = fmt.Errorf("first message should be SSH_SMSG_PUBLIC_KEY (%d), got %d", smsgPublicKey, pt)
		err = unexpectedMessageError(smsgPublicKey, pt)
		return
	}

	var pubKey pubKeySmsg
	if err = Unmarshal(pt, p, &pubKey); err != nil {
		return
	}

	sessionID := md5.Sum(
		bytes.Join(
			[][]byte{
				pubKey.HostKeyPubModulus.Bytes(),
				pubKey.ServerKeyPubModulus.Bytes(),
				pubKey.Cookie[:],
			},
			[]byte("")),
	)

	var (
		sessionKey      [32]byte
		sessionKeyBytes = make([]byte, 32)
	)
	rand.Read(sessionKeyBytes)
	copy(sessionKey[:], sessionKeyBytes)

	var (
		serverKey = &rsa.PublicKey{
			N: pubKey.ServerKeyPubModulus,
			E: int(pubKey.ServerKeyPubExponent.Int64()),
		}
		hostKey = &rsa.PublicKey{
			N: pubKey.HostKeyPubModulus,
			E: int(pubKey.HostKeyPubExponent.Int64()),
		}
	)
	encryptedSessionKey, err := encryptSessionKey(sessionKey, sessionID, serverKey, hostKey)
	if err != nil {
		return
	}

	cipherNumber, err := chooseCipher(pubKey.CipherMask, config.CiphersOrder)
	if err != nil {
		return
	}
	var (
		key = new(big.Int)
		msg = sessionKeyCmsg{
			Cipher:        byte(cipherNumber),
			Cookie:        pubKey.Cookie,
			SessionKey:    key.SetBytes(encryptedSessionKey),
			ProtocolFlags: 0,
		}
	)

	err = t.writePacket(Marshal(msg))
	if err != nil {
		return
	}

	// TODO: rc4: different keys for each direction.
	mode, ok := cipherModes[cipherNumber]
	if !ok {
		err = fmt.Errorf("ssh1: unsupported cipher (%d)", cipherNumber)
		return
	}

	t.reader.packetCipher, err = mode.create(sessionKey[:mode.keySize], make([]byte, mode.ivSize))
	if err != nil {
		return
	}
	t.writer.packetCipher, err = mode.create(sessionKey[:mode.keySize], make([]byte, mode.ivSize))
	if err != nil {
		return
	}
	t.rand = rand.Reader

	pt, _, err = t.readPacket()
	if err != nil {
		return
	}
	if pt != smsgSuccess {
		// err = fmt.Errorf("SSH_SMSG_SUCCESS (%d) expected, got %d", smsgSuccess, pt)
		err = unexpectedMessageError(smsgSuccess, pt)
		return
	}

	return
}

// Sends and receives a version line.  The versionLine string should
// be US ASCII, start with "SSH-2.0-", and should not include a
// newline. exchangeVersions returns the other side's version line.
func exchangeVersions(rw io.ReadWriter, versionLine []byte) (them []byte, err error) {
	// Contrary to the RFC, we do not ignore lines that don't
	// start with "SSH-2.0-" to make the library usable with
	// nonconforming servers.
	for _, c := range versionLine {
		// The spec disallows non US-ASCII chars, and
		// specifically forbids null chars.
		if c < 32 {
			return nil, errors.New("ssh1: junk character in version line")
		}
	}
	if _, err = rw.Write(append(versionLine, '\r', '\n')); err != nil {
		return
	}

	them, err = readVersion(rw)
	return them, err
}

// maxVersionStringBytes is the maximum number of bytes that we'll
// accept as a version string. RFC 4253 section 4.2 limits this at 255
// chars
const maxVersionStringBytes = 255

// Read version string as specified by RFC 4253, section 4.2.
func readVersion(r io.Reader) ([]byte, error) {
	versionString := make([]byte, 0, 64)
	var ok bool
	var buf [1]byte

	for length := 0; length < maxVersionStringBytes; length++ {
		_, err := io.ReadFull(r, buf[:])
		if err != nil {
			return nil, err
		}
		// The RFC says that the version should be terminated with \r\n
		// but several SSH servers actually only send a \n.
		if buf[0] == '\n' {
			if !bytes.HasPrefix(versionString, []byte("SSH-")) {
				// RFC 4253 says we need to ignore all version string lines
				// except the one containing the SSH version (provided that
				// all the lines do not exceed 255 bytes in total).
				versionString = versionString[:0]
				continue
			}
			ok = true
			break
		}

		// non ASCII chars are disallowed, but we are lenient,
		// since Go doesn't use null-terminated strings.

		// The RFC allows a comment after a space, however,
		// all of it (version and comments) goes into the
		// session hash.
		versionString = append(versionString, buf[0])
	}

	if !ok {
		return nil, errors.New("ssh1: overflow reading version string")
	}

	// There might be a '\r' on the end which we should remove.
	if len(versionString) > 0 && versionString[len(versionString)-1] == '\r' {
		versionString = versionString[:len(versionString)-1]
	}

	versionMajor := bytes.Split(bytes.Split(versionString, []byte("-"))[1], []byte("."))[0]
	// RFC 4253, section 5.1 says that version '1.99' used to
	// identify compatibility with older versions of protocol.
	if !bytes.Equal(versionMajor, []byte("1")) {
		return nil, fmt.Errorf("ssh1: incompatible versions (%s and 1)", versionMajor)
	}

	return versionString, nil
}

// NewSession opens a new Session for this client. (A session is a remote
// execution of a program.)
func (c *Client) NewSession() (*Session, error) {
	return newSession(c.t)
}
