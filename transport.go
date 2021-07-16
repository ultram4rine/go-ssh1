package ssh1

import (
	"bufio"
	"io"
	"log"
)

// debugTransport if set, will print packet types as they go over the
// wire. No message decoding is done, to minimize the impact on timing.
const debugTransport = true

// packetConn represents a transport that implements packet based
// operations.
type packetConn interface {
	// Encrypt and send a packet of data to the remote peer.
	writePacket(packetType byte, packet []byte) error

	// Read a packet from the connection. The read is blocking,
	// i.e. if error is nil, then the returned byte slice is
	// always non-empty.
	readPacket() (byte, []byte, error)

	// Close closes the write-side of the connection.
	Close() error
}

// transport is the keyingTransport that implements the SSH packet
// protocol.
type transport struct {
	reader connectionState
	writer connectionState

	bufReader *bufio.Reader
	bufWriter *bufio.Writer
	rand      io.Reader
	isClient  bool
	io.Closer
}

// packetCipher represents a combination of SSH encryption/MAC
// protocol.  A single instance should be used for one direction only.
type packetCipher interface {
	// writeCipherPacket encrypts the packet and writes it to w. The
	// contents of the packet are generally scrambled.
	writeCipherPacket(seqnum uint32, w io.Writer, rand io.Reader, packetType byte, packet []byte) error

	// readCipherPacket reads and decrypts a packet of data. The
	// returned packet may be overwritten by future calls of
	// readPacket.
	readCipherPacket(seqnum uint32, r io.Reader) (byte, []byte, error)
}

// connectionState represents one side (read or write) of the
// connection. This is necessary because each direction has its own
// keys, and can even have its own algorithms
type connectionState struct {
	packetCipher
	seqNum uint32
	dir    direction
}

func (t *transport) printPacket(pt byte, write bool) {
	if pt == 0 {
		return
	}
	who := "server"
	if t.isClient {
		who = "client"
	}
	what := "read"
	if write {
		what = "write"
	}
	log.Println(what, who, pt)
}

// Read and decrypt next packet.
func (t *transport) readPacket() (pt byte, p []byte, err error) {
	for {
		pt, p, err = t.reader.readPacket(t.bufReader)
		if err != nil {
			break
		}
		if len(p) == 0 || (p[0] != msgIgnore && p[0] != msgDebug) {
			break
		}
	}
	if debugTransport {
		t.printPacket(pt, false)
	}

	return pt, p, err
}

func (s *connectionState) readPacket(r *bufio.Reader) (byte, []byte, error) {
	packetType, packet, err := s.packetCipher.readCipherPacket(s.seqNum, r)
	s.seqNum++
	if err != nil {
		return packetTypeForError, nil, err
	}

	switch packetType {
	case msgDisconnect:
		// Transform a disconnect message into an
		// error. Since this is lowest level at which
		// we interpret message types, doing it here
		// ensures that we don't have to handle it
		// elsewhere.
		var msg disconnectMsg
		if err := Unmarshal(packetType, packet, &msg); err != nil {
			return packetTypeForError, nil, err
		}
		return packetTypeForError, nil, &msg
	}

	// The packet may point to an internal buffer, so copy the
	// packet out here.
	fresh := make([]byte, len(packet))
	copy(fresh, packet)

	return packetType, fresh, nil
}

func (t *transport) writePacket(packetType byte, packet []byte) error {
	if debugTransport {
		t.printPacket(packetType, true)
	}
	return t.writer.writePacket(t.bufWriter, t.rand, packetType, packet)
}

func (s *connectionState) writePacket(w *bufio.Writer, rand io.Reader, packetType byte, packet []byte) error {
	err := s.packetCipher.writeCipherPacket(s.seqNum, w, rand, packetType, packet)
	if err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}
	s.seqNum++
	return err
}

func newTransport(rwc io.ReadWriteCloser, rand io.Reader, isClient bool) *transport {
	t := &transport{
		bufReader: bufio.NewReader(rwc),
		bufWriter: bufio.NewWriter(rwc),
		rand:      rand,
		reader: connectionState{
			packetCipher: &streamPacketCipher{cipher: noneCipher{}},
		},
		writer: connectionState{
			packetCipher: &streamPacketCipher{cipher: noneCipher{}},
		},
		Closer: rwc,
	}
	t.isClient = isClient

	if isClient {
		t.reader.dir = serverKeys
		t.writer.dir = clientKeys
	} else {
		t.reader.dir = clientKeys
		t.writer.dir = serverKeys
	}

	return t
}

type direction struct {
	ivTag  []byte
	keyTag []byte
}

var (
	serverKeys = direction{[]byte{'B'}, []byte{'D'}}
	clientKeys = direction{[]byte{'A'}, []byte{'C'}}
)
