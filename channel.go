package ssh1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	minPacketLength = 9
	// channelMaxPacket contains the maximum number of bytes that will be
	// sent in a single packet. As per RFC 4253, section 6.1, 32k is also
	// the minimum.
	channelMaxPacket = 1 << 15
	// We follow OpenSSH here.
	channelWindowSize = 64 * channelMaxPacket
)

// A Channel is an ordered, reliable, flow-controlled, duplex stream
// that is multiplexed over an SSH connection.
type Channel interface {
	// Read reads up to len(data) bytes from the channel.
	Read(data []byte) (int, error)

	// ReadStatus reads up to len(data) bytes from the channel.
	ReadStatus(data []byte) (int, error)

	// Write writes len(data) bytes to the channel.
	Write(data []byte) (int, error)

	// Close signals end of channel use. No data may be sent after this
	// call.
	Close() error

	// CloseWrite signals the end of sending in-band
	// data. Requests may still be sent, and the other side may
	// still send data
	CloseWrite() error

	// Stderr returns an io.ReadWriter that writes to this channel
	// with the extended data type set to stderr. Stderr may
	// safely be read and written from a different goroutine than
	// Read and Write respectively.
	Stderr() io.ReadWriter
}

// RejectionReason is an enumeration used when rejecting channel creation
// requests. See RFC 4254, section 5.1.
type RejectionReason uint32

const (
	Prohibited RejectionReason = iota + 1
	ConnectionFailed
	UnknownChannelType
	ResourceShortage
)

// String converts the rejection reason to human-readable form.
func (r RejectionReason) String() string {
	switch r {
	case Prohibited:
		return "administratively prohibited"
	case ConnectionFailed:
		return "connect failed"
	case UnknownChannelType:
		return "unknown channel type"
	case ResourceShortage:
		return "resource shortage"
	}
	return fmt.Sprintf("unknown reason %d", int(r))
}

func min(a uint32, b int) uint32 {
	if a < uint32(b) {
		return a
	}
	return uint32(b)
}

type channelDirection uint8

const (
	channelInbound channelDirection = iota
	channelOutbound
)

// channel is an implementation of the Channel interface that works
// with the mux class.
type channel struct {
	// R/O after creation
	chanType          string
	extraData         []byte
	localId, remoteId uint32

	// maxIncomingPayload and maxRemotePayload are the maximum
	// payload sizes of normal and extended data packets for
	// receiving and sending, respectively. The wire packet will
	// be 9 or 13 bytes larger (excluding encryption overhead).
	maxIncomingPayload uint32
	maxRemotePayload   uint32

	conn packetConn

	// direction contains either channelOutbound, for channels created
	// locally, or channelInbound, for channels created by the peer.
	direction channelDirection

	// Pending internal channel messages.
	msg chan interface{}

	// Since requests have no ID, there can be only one request
	// with WantReply=true outstanding.  This lock is held by a
	// goroutine that has such an outgoing request pending.
	sentRequestMu sync.Mutex

	sentEOF bool

	pending    *buffer
	exitStatus *buffer

	// writeMu serializes calls to mux.conn.writePacket() and
	// protects sentClose and packetPool. This mutex must be
	// different from windowMu, as writePacket can block if there
	// is a key exchange pending.
	writeMu   sync.Mutex
	sentClose bool

	// packetPool has a buffer for each extended channel ID to
	// save allocations during writes.
	packetPool map[uint32][]byte
}

// writePacket sends a packet. If the packet is a channel close, it updates
// sentClose. This method takes the lock c.writeMu.
func (ch *channel) writePacket(packetType byte, packet []byte) error {
	ch.writeMu.Lock()
	if ch.sentClose {
		ch.writeMu.Unlock()
		return io.EOF
	}
	ch.sentClose = (packetType == msgChannelClose)
	err := ch.conn.writePacket(packetType, packet)
	ch.writeMu.Unlock()
	return err
}

func (ch *channel) sendMessage(msg interface{}) error {
	pt, p := Marshal(msg)
	binary.BigEndian.PutUint32(p, ch.remoteId)
	return ch.writePacket(pt, p)
}

func (ch *channel) handleData(packetType byte, packet []byte) error {
	headerLen := 9
	if len(packet) < headerLen {
		// malformed data packet
		return parseError(packet[0])
	}

	length := binary.BigEndian.Uint32(packet[headerLen-4 : headerLen])
	if length == 0 {
		return nil
	}
	if length > ch.maxIncomingPayload {
		// TODO(hanwen): should send Disconnect?
		return errors.New("ssh: incoming packet exceeds maximum payload size")
	}

	data := packet[headerLen:]
	if length != uint32(len(data)) {
		return errors.New("ssh: wrong packet length")
	}

	ch.pending.write(data)
	return nil
}

func (ch *channel) close() {
	ch.pending.eof()
	close(ch.msg)
	ch.writeMu.Lock()
	// This is not necessary for a normal channel teardown, but if
	// there was another error, it is.
	ch.sentClose = true
	ch.writeMu.Unlock()
}

func (t *transport) newChannel(chanType string, direction channelDirection, extraData []byte) *channel {
	ch := &channel{
		conn:       t,
		pending:    newBuffer(),
		exitStatus: newBuffer(),
		direction:  direction,
		msg:        make(chan interface{}, 16),
		chanType:   chanType,
		extraData:  extraData,
		packetPool: make(map[uint32][]byte),
	}

	go func(conn packetConn) {
		for {
			pt, p, err := conn.readPacket()
			if err != nil {
				break
			}

			if pt == smsgStdoutData || pt == smsgStderrData {
				ch.pending.write(p)
			}

			if pt == smsgExitstatus {
				ch.exitStatus.write(p)
			}
		}
	}(ch.conn)

	return ch
}

var errUndecided = errors.New("ssh: must Accept or Reject channel")
var errDecidedAlready = errors.New("ssh: can call Accept or Reject only once")

func (ch *channel) Read(data []byte) (int, error) {
	return ch.pending.read(data)
}

func (ch *channel) ReadStatus(data []byte) (int, error) {
	return ch.exitStatus.read(data)
}

func (ch *channel) Write(data []byte) (n int, err error) {
	if ch.sentEOF {
		return 0, io.EOF
	}

	if err = ch.writePacket(Marshal(&stdinDataCmsg{Data: string(data)})); err != nil {
		return len(data), err
	}

	return len(data), err
}

func (ch *channel) CloseWrite() error {
	ch.sentEOF = true
	return ch.sendMessage(channelCloseMsg{
		Remote: ch.remoteId})
}

func (ch *channel) Close() error {
	return ch.sendMessage(channelCloseMsg{
		Remote: ch.remoteId})
}

func (ch *channel) Stderr() io.ReadWriter {
	return ch
}

func (ch *channel) ChannelType() string {
	return ch.chanType
}

func (ch *channel) ExtraData() []byte {
	return ch.extraData
}
