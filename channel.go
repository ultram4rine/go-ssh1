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

// String converts the rejection reason to human readable form.
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

	// decided is set to true if an accept or reject message has been sent
	// (for outbound channels) or received (for inbound channels).
	decided bool

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

	pending *buffer

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
	ch.sentClose = (packet[0] == msgChannelClose)
	err := ch.conn.writePacket(packetType, packet)
	ch.writeMu.Unlock()
	return err
}

func (ch *channel) sendMessage(msg interface{}) error {
	pt, p := Marshal(msg)
	binary.BigEndian.PutUint32(p, ch.remoteId)
	return ch.writePacket(pt, p)
}

// WriteExtended writes data to a specific extended stream. These streams are
// used, for example, for stderr.
func (ch *channel) WriteExtended(data []byte, extendedCode uint32) (n int, err error) {
	if ch.sentEOF {
		return 0, io.EOF
	}
	// 1 byte message type, 4 bytes remoteId, 4 bytes data length
	opCode := byte(msgChannelData)
	headerLength := uint32(9)

	ch.writeMu.Lock()
	packet := ch.packetPool[extendedCode]
	// We don't remove the buffer from packetPool, so
	// WriteExtended calls from different goroutines will be
	// flagged as errors by the race detector.
	ch.writeMu.Unlock()

	for len(data) > 0 {
		space := min(ch.maxRemotePayload, len(data))

		todo := data[:space]

		packetType := opCode
		binary.BigEndian.PutUint32(packet[1:], ch.remoteId)
		if extendedCode > 0 {
			binary.BigEndian.PutUint32(packet[5:], uint32(extendedCode))
		}
		binary.BigEndian.PutUint32(packet[headerLength-4:], uint32(len(todo)))
		copy(packet[headerLength:], todo)
		if err = ch.writePacket(packetType, packet); err != nil {
			return n, err
		}

		n += len(todo)
		data = data[len(todo):]
	}

	ch.writeMu.Lock()
	ch.packetPool[extendedCode] = packet
	ch.writeMu.Unlock()

	return n, err
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

func (c *channel) ReadExtended(data []byte, extended uint32) (n int, err error) {
	return c.pending.read(data)
}

func (c *channel) close() {
	c.pending.eof()
	close(c.msg)
	c.writeMu.Lock()
	// This is not necessary for a normal channel teardown, but if
	// there was another error, it is.
	c.sentClose = true
	c.writeMu.Unlock()
}

// responseMessageReceived is called when a success or failure message is
// received on a channel to check that such a message is reasonable for the
// given channel.
func (ch *channel) responseMessageReceived() error {
	if ch.direction == channelInbound {
		return errors.New("ssh: channel response message received on inbound channel")
	}
	if ch.decided {
		return errors.New("ssh: duplicate response received for channel")
	}
	ch.decided = true
	return nil
}

func (ch *channel) handlePacket(packetType byte, packet []byte) error {
	switch packetType {
	case msgChannelData, smsgStdoutData, smsgStderrData:
		return ch.handleData(packetType, packet)
	case msgChannelClose:
		ch.sendMessage(channelCloseMsg{Remote: ch.remoteId})
		ch.close()
		return nil
	}

	decoded, err := decode(packetType, packet)
	if err != nil {
		return err
	}

	switch msg := decoded.(type) {
	case *channelOpenFailureMsg:
		if err := ch.responseMessageReceived(); err != nil {
			return err
		}
		ch.msg <- msg
	case *channelOpenConfirmationMsg:
		if err := ch.responseMessageReceived(); err != nil {
			return err
		}
		ch.remoteId = msg.Local
		ch.msg <- msg
	default:
		ch.msg <- msg
	}
	return nil
}

func (t *transport) newChannel(chanType string, direction channelDirection, extraData []byte) *channel {
	ch := &channel{
		conn:       t,
		pending:    newBuffer(),
		direction:  direction,
		msg:        make(chan interface{}, 16),
		chanType:   chanType,
		extraData:  extraData,
		packetPool: make(map[uint32][]byte),
	}
	return ch
}

var errUndecided = errors.New("ssh: must Accept or Reject channel")
var errDecidedAlready = errors.New("ssh: can call Accept or Reject only once")

type extChannel struct {
	code uint32
	ch   *channel
}

func (e *extChannel) Write(data []byte) (n int, err error) {
	return e.ch.WriteExtended(data, e.code)
}

func (e *extChannel) Read(data []byte) (n int, err error) {
	return e.ch.ReadExtended(data, e.code)
}

func (ch *channel) Read(data []byte) (int, error) {
	if !ch.decided {
		return 0, errUndecided
	}
	return ch.ReadExtended(data, 0)
}

func (ch *channel) Write(data []byte) (int, error) {
	if !ch.decided {
		return 0, errUndecided
	}
	return ch.WriteExtended(data, 0)
}

func (ch *channel) CloseWrite() error {
	if !ch.decided {
		return errUndecided
	}
	ch.sentEOF = true
	return ch.sendMessage(channelCloseMsg{
		Remote: ch.remoteId})
}

func (ch *channel) Close() error {
	if !ch.decided {
		return errUndecided
	}

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
