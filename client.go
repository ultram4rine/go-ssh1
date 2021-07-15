package ssh1

import (
	"bufio"
	"bytes"
	"crypto/md5"
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
/*type Client struct {
	Conn

	handleForwardsOnce sync.Once // guards calling (*Client).handleForwards

	forwards        forwardList // forwarded tcpip connections from the remote side
	mu              sync.Mutex
	channelHandlers map[string]chan NewChannel
}

// NewClient creates a Client on top of the given connection.
func NewClient(c Conn, chans <-chan NewChannel, reqs <-chan *Request) *Client {
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
func NewClientConn(c net.Conn, addr string, config *Config) (*sshConn, error) {
	conf := *config
	conf.SetDefaults()
	if conf.HostKeyCallback == nil {
		c.Close()
		return nil, errors.New("ssh1: must specify HostKeyCallback")
	}

	conn := &sshConn{conn: c, user: conf.User}

	if err := conn.handshake(addr, &conf); err != nil {
		return nil, fmt.Errorf("ssh1: handshake failed: %v", err)
	}
	return conn, nil
}

// clientHandshake performs the client side key exchange. See RFC 4253 Section
// 7.
func (c *sshConn) handshake(dialAddress string, config *Config) error {
	if config.Version != "" {
		c.clientVersion = []byte(config.Version)
	} else {
		c.clientVersion = []byte(packageVersion)
	}

	var err error
	c.serverVersion, err = exchangeVersions(c.conn, c.clientVersion)
	if err != nil {
		return err
	}
	fmt.Println(string(c.serverVersion))

	c.sessionID, err = keyExchange(c.conn)
	if err != nil {
		return err
	}

	return nil
}

// Dial starts a client connection to the given SSH server. It is a
// convenience function that connects to the given network address,
// initiates the SSH handshake, and then sets up a Client.  For access
// to incoming channels and requests, use net.Dial with NewClientConn
// instead.
func Dial(addr string, config *Config) (*packetCipher, error) {
	conn, err := net.DialTimeout("tcp", addr, config.Timeout)
	if err != nil {
		return nil, err
	}
	_, err = NewClientConn(conn, addr, config)
	if err != nil {
		return nil, err
	}
	return nil, err
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
func keyExchange(conn net.Conn) (sessionID [16]byte, err error) {
	var (
		reader = connectionState{
			packetCipher: &streamPacketCipher{cipher: noneCipher{}},
		}
		writer = connectionState{
			packetCipher: &streamPacketCipher{cipher: noneCipher{}},
		}
	)

	r := bufio.NewReader(conn)
	pt, p, err := reader.readPacket(r)
	if err != nil {
		return
	}
	if pt != smsgPublicKey {
		err = fmt.Errorf("first message should be SSH_SMSG_PUBLIC_KEY (%d), got %d", smsgPublicKey, pt)
		return
	}

	var pubKey pubKeySmsg
	err = Unmarshal(pt, p, &pubKey)
	if err != nil {
		return
	}

	sessionID = md5.Sum(
		bytes.Join(
			[][]byte{
				pubKey.HostKeyPubModulus.Bytes(),
				pubKey.ServerKeyPubModulus.Bytes(),
				pubKey.Cookie[:],
			},
			[]byte("")),
	)

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
	sessionKey, sessionKeyEncrypted, err := createSessionKey(sessionID, serverKey, hostKey)
	if err != nil {
		return
	}

	c, err := chooseCipher(pubKey.CipherMask)
	if err != nil {
		return
	}
	var (
		key = new(big.Int)
		msg = sessionKeyCmsg{
			Cipher:        byte(c),
			Cookie:        pubKey.Cookie,
			SessionKey:    key.SetBytes(sessionKeyEncrypted),
			ProtocolFlags: 0,
		}
	)

	packetType, packet := Marshal(msg)
	if packetType != cmsgSessionKey {
		err = fmt.Errorf("SSH_CMSG_SESSION_KEY (%d) should be sended, found %d", cmsgSessionKey, packetType)
		return
	}
	w := bufio.NewWriter(conn)
	// Pass empty buffer for padding because it zeroes if not encrypting.
	err = writer.writePacket(w, bytes.NewBuffer(make([]byte, 8)), packetType, packet)
	if err != nil {
		return
	}

	switch c {
	case SSH_CIPHER_IDEA:
		{
			reader.packetCipher, err = newIDEACFBCipher(sessionKey[:16], make([]byte, 8))
			if err != nil {
				return
			}
		}
	case SSH_CIPHER_DES:
		{
			reader.packetCipher, err = newDESCBCCipher(sessionKey[:8], make([]byte, 8))
			if err != nil {
				return
			}
		}
	case SSH_CIPHER_3DES:
		{
			reader.packetCipher, err = newTripleDESCBCCipher(sessionKey[:24], make([]byte, 8))
			if err != nil {
				return
			}
		}
	case SSH_CIPHER_RC4:
		{
			// TODO: first 16 bytes server to client, remaining 16 bytes is client to server.
			reader.packetCipher, err = newRC4(sessionKey[16:], nil)
			if err != nil {
				return
			}
		}
	default:
		{
			err = fmt.Errorf("unsupported cipher (%d)", c)
			return
		}
	}

	pt, _, err = reader.readPacket(r)
	if err != nil {
		return
	}
	if pt != smsgSuccess {
		err = fmt.Errorf("SSH_SMSG_SUCCESS (%d) expected, got %d", smsgSuccess, pt)
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
			return nil, errors.New("ssh: junk character in version line")
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
		return nil, errors.New("ssh: overflow reading version string")
	}

	// There might be a '\r' on the end which we should remove.
	if len(versionString) > 0 && versionString[len(versionString)-1] == '\r' {
		versionString = versionString[:len(versionString)-1]
	}

	versionMajor := bytes.Split(bytes.Split(versionString, []byte("-"))[1], []byte("."))[0]
	// RFC 4253, section 5.1 says that version '1.99' used to
	// identify compability with older versions of protocol.
	if !bytes.Equal(versionMajor, []byte("1")) {
		return nil, fmt.Errorf("ssh: incompatible versions (%s and 1)", versionMajor)
	}

	return versionString, nil
}
