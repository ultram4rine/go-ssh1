package ssh1

import (
	"bufio"
	"io"
	"log"
)

// debugTransport if set, will print packet types as they go over the
// wire. No message decoding is done, to minimize the impact on timing.
const debugTransport = false

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

// transport implements the SSH packet protocol.
type transport struct {
	reader connectionState
	writer connectionState

	bufReader *bufio.Reader
	bufWriter *bufio.Writer
	rand      io.Reader
	io.Closer
}

// packetCipher represents a combination of SSH encryption protocol.
// A single instance should be used for one direction only.
type packetCipher interface {
	// writeCipherPacket encrypts the packet and writes it to w. The
	// contents of the packet are generally scrambled.
	writeCipherPacket(w io.Writer, rand io.Reader, packetType byte, packet []byte) error

	// readCipherPacket reads and decrypts a packet of data. The
	// returned packet may be overwritten by future calls of
	// readPacket.
	readCipherPacket(r io.Reader) (byte, []byte, error)
}

// connectionState represents one side (read or write) of the
// connection.
type connectionState struct {
	packetCipher
}

func (t *transport) printPacket(pt byte, write bool) {
	if pt == 0 {
		return
	}
	who := "server"
	what := "read"
	if write {
		who = "client"
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
	packetType, packet, err := s.packetCipher.readCipherPacket(r)
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
	err := s.packetCipher.writeCipherPacket(w, rand, packetType, packet)
	if err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}
	return err
}

func newTransport(rwc io.ReadWriteCloser, rand io.Reader) *transport {
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

	return t
}
