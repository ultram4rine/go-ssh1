package ssh1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"reflect"
	"strconv"
	"strings"
)

const (
	msgNone = iota
	msgDisconnect
	smsgPublicKey
	cmsgSessionKey
	cmsgUser
	cmsgAuthRhosts
	cmsgAuthRSA
	smsgAuthRSAChallenge
	cmsgAuthRSAResponse
	cmsgAuthPassword
	cmsgRequestPTY
	cmsgWindowSize
	cmsgExecShell
	cmsgExecCmd
	smsgSuccess
	smsgFailure
	cmsgStdinData
	smsgStdoutData
	smsgStderrData
	cmsgEOF
	smsgExitstatus
	msgChannelOpenConfirmation
	msgChannelOpenFailure
	msgChannelData
	msgChannelClose
	msgChannelCloseConfirmation
	// OBSOLETED: SSH_CMSG_X11_REQUEST_FORWARDING.
	_
	smsgX11Open
	cmsgPortForwardRequest
	msgPortOpen
	cmsgAgentRequestForwarding
	smsgAgentOpen
	msgIgnore
	cmsgExitConfirmation
	cmsgX11RequestForwarding
	cmsgAuthRhostsRSA
	msgDebug
	cmsgRequestCompression
	cmsgMaxPacketSize
	cmsgAuthTis
	smsgAuthTisChallenge
	cmsgAuthTisResponse
	cmsgAuthKerberos
	smsgAuthKerberosResponse
	cmsgHaveKerberosTGT
	cmsgHaveAFSToken = 65
)

// Protocol version 1.5 overloads some version 1.3 message types.
const (
	msgChannelInputEOF    = msgChannelClose
	msgChannelOutputClose = msgChannelCloseConfirmation
)

type disconnectMsg struct {
	Cause string `ssh1type:"1"`
}

func (m disconnectMsg) Error() string {
	return fmt.Sprintf("ssh1: disconnect, reason: %s", m.Cause)
}

type pubKeySmsg struct {
	Cookie               [8]byte `ssh1type:"2"`
	ServerKey            uint32
	ServerKeyPubExponent *big.Int
	ServerKeyPubModulus  *big.Int
	HostKey              uint32
	HostKeyPubExponent   *big.Int
	HostKeyPubModulus    *big.Int
	ProtocolFlags        uint32
	CipherMask           uint32
	AuthMask             uint32
}

type sessionKeyCmsg struct {
	Cipher        byte `ssh1type:"3"`
	Cookie        [8]byte
	SessionKey    *big.Int
	ProtocolFlags uint32
}

type userCmsg struct {
	UserName string `ssh1type:"4"`
}

type authRhostsCmsg struct {
	UserName string `ssh1type:"5"`
}

type authRSACmsg struct {
	IdentityPubModulus big.Int `ssh1type:"6"`
}

type authRSAChallengeSmsg struct {
	Challenge big.Int `ssh1type:"7"`
}

type authRSAResponceCmsg struct {
	Challenge [16]byte `ssh1type:"8"`
}

type authPasswordCmsg struct {
	Password string `ssh1type:"9"`
}

type requestPTYCmsg struct {
	TermEnv      string `ssh1type:"10"`
	Height       uint32
	Width        uint32
	WidthPixels  uint32
	HeightPixels uint32
	TTYModes     []byte
}

type windowSizeCmsg struct {
	Height       uint32 `ssh1type:"11"`
	Width        uint32
	WidthPixels  uint32
	HeightPixels uint32
}

type execCmdCmsg struct {
	Command string `ssh1type:"13"`
}

type stdinDataCmsg struct {
	Data string `ssh1type:"16"`
}

type stdoutDataSmsg struct {
	Data string `ssh1type:"17"`
}

type stderrDataSmsg struct {
	Data string `ssh1type:"18"`
}

type exitstatusSmsg struct {
	Status uint32 `ssh1type:"20"`
}

type channelOpenConfirmationMsg struct {
	Remote uint32 `ssh1type:"21"`
	Local  uint32
}

type channelOpenFailureMsg struct {
	Remote uint32 `ssh1type:"22"`
}

type channelDataMsg struct {
	Remote uint32 `ssh1type:"23"`
	Data   string
}

type channelCloseMsg struct {
	Remote uint32 `ssh1type:"24"`
}

type channelCloseConfirmationMsg struct {
	Remote uint32 `ssh1type:"25"`
}

type x11OpenSmsg struct {
	Local      uint32 `ssh1type:"27"`
	Originator string
}

type portForwardRequestCmsg struct {
	ServerPort uint32 `ssh1type:"28"`
	Host       string
	Port       uint32
}

type portOpenMsg struct {
	Local      uint32 `ssh1type:"29"`
	Host       string
	Port       uint32
	Originator string
}

type agentOpenSmsg struct {
	Local uint32 `ssh1type:"31"`
}

type ignoreMsg struct {
	Data string `ssh1type:"32"`
}

type x11RequestForwardingCmsg struct {
	X11AuthProto string `ssh1type:"34"`
	X11AuthData  string
	ScreenNum    uint32
}

type authRhostsRSACmsg struct {
	UserName           string `ssh1type:"35"`
	HostKey            uint32
	HostKeyPubExponent big.Int
	HostKeyPubModulus  big.Int
}

type debugMsg struct {
	Debug string `ssh1type:"36"`
}

type requestCompressionCmsg struct {
	Level uint32 `ssh1type:"37"`
}

type maxPacketSizeCmsg struct {
	Size uint32 `ssh1type:"38"`
}

type authTisChallengeSmsg struct {
	Challenge string `ssh1type:"40"`
}

type authTisResponseCmsg struct {
	Response string `ssh1type:"41"`
}

type authKerberosCmsg struct {
	AuthInfo string `ssh1type:"42"`
}

type authKerberosResponseSmsg struct {
	Response string `ssh1type:"43"`
}

type haveKerberosTGTCmsg struct {
	Credentials string `ssh1type:"44"`
}

// typeTags returns the possible type bytes for the given reflect.Type, which
// should be a struct. The possible values are separated by a '|' character.
func typeTags(structType reflect.Type) (tags []byte) {
	tagStr := structType.Field(0).Tag.Get("ssh1type")

	for _, tag := range strings.Split(tagStr, "|") {
		i, err := strconv.Atoi(tag)
		if err == nil {
			tags = append(tags, byte(i))
		}
	}

	return tags
}

func fieldError(t reflect.Type, field int, problem string) error {
	if problem != "" {
		problem = ": " + problem
	}
	return fmt.Errorf("ssh1: unmarshal error for field %s of type %s%s", t.Field(field).Name, t.Name(), problem)
}

var errShortRead = errors.New("ssh1: short read")

var (
	bigIntType = reflect.TypeOf((*big.Int)(nil))
	bigOne     = big.NewInt(1)
)

// Unmarshal parses data in SSH wire format into a structure. The out
// argument should be a pointer to struct. If the first member of the
// struct has the "ssh1type" tag set to a '|'-separated set of numbers
// in decimal, the packet must start with one of those numbers. In
// case of error, Unmarshal returns a ParseError or
// UnexpectedMessageError.
func Unmarshal(packetType byte, data []byte, out interface{}) error {
	v := reflect.ValueOf(out).Elem()
	structType := v.Type()
	expectedTypes := typeTags(structType)

	var expectedType byte
	if len(expectedTypes) > 0 {
		expectedType = expectedTypes[0]
	}

	if len(data) == 0 {
		return parseError(expectedType)
	}

	if len(expectedTypes) > 0 {
		goodType := false
		for _, e := range expectedTypes {
			if e > 0 && packetType == e {
				goodType = true
				break
			}
		}
		if !goodType {
			return fmt.Errorf("ssh1: unexpected message type %d (expected one of %v)", data[0], expectedTypes)
		}
	}

	var ok bool
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		t := field.Type()
		switch t.Kind() {
		case reflect.Uint8:
			fmt.Println("uint8")
			if len(data) < 1 {
				return errShortRead
			}
			field.SetUint(uint64(data[0]))
			data = data[1:]
		case reflect.Uint32:
			fmt.Println("uint32")
			var u32 uint32
			if u32, data, ok = parseUint32(data); !ok {
				return errShortRead
			}
			field.SetUint(uint64(u32))
		case reflect.Array:
			fmt.Println("array")
			if t.Elem().Kind() != reflect.Uint8 {
				return fieldError(structType, i, "array of unsupported type")
			}
			if len(data) < t.Len() {
				return errShortRead
			}
			for j, n := 0, t.Len(); j < n; j++ {
				field.Index(j).Set(reflect.ValueOf(data[j]))
			}
			data = data[t.Len():]
		case reflect.String:
			fmt.Println("string")
			var s []byte
			if s, data, ok = parseString(data); !ok {
				return fieldError(structType, i, "")
			}
			field.SetString(string(s))
		case reflect.Slice:
			fmt.Println("slice")
			switch t.Elem().Kind() {
			case reflect.Uint8:
				if structType.Field(i).Tag.Get("ssh") == "rest" {
					field.Set(reflect.ValueOf(data))
					data = nil
				} else {
					var s []byte
					if s, data, ok = parseString(data); !ok {
						return errShortRead
					}
					field.Set(reflect.ValueOf(s))
				}
			case reflect.String:
				var nl []string
				if nl, data, ok = parseNameList(data); !ok {
					return errShortRead
				}
				field.Set(reflect.ValueOf(nl))
			default:
				return fieldError(structType, i, "slice of unsupported type")
			}
		case reflect.Ptr:
			fmt.Println("ptr")
			if t == bigIntType {
				var n *big.Int
				if n, data, ok = parseInt(data); !ok {
					return errShortRead
				}
				field.Set(reflect.ValueOf(n))
			} else {
				return fieldError(structType, i, "pointer to unsupported type")
			}
		default:
			return fieldError(structType, i, fmt.Sprintf("unsupported type: %v", t))
		}
		fmt.Println("value: ", field)
	}

	if len(data) != 0 {
		return parseError(expectedType)
	}

	return nil
}

// Marshal serializes the message in msg to SSH wire format.  The msg
// argument should be a struct or pointer to struct. If the first
// member has the "ssh1type" tag set to a number in decimal, that
// number is prepended to the result. If the last of member has the
// "ssh" tag set to "rest", its contents are appended to the output.
func Marshal(msg interface{}) []byte {
	out := make([]byte, 0, 64)
	return marshalStruct(out, msg)
}

func marshalStruct(out []byte, msg interface{}) []byte {
	v := reflect.Indirect(reflect.ValueOf(msg))
	msgTypes := typeTags(v.Type())
	if len(msgTypes) > 0 {
		out = append(out, msgTypes[0])
	}

	for i, n := 0, v.NumField(); i < n; i++ {
		field := v.Field(i)
		switch t := field.Type(); t.Kind() {
		case reflect.Bool:
			var v uint8
			if field.Bool() {
				v = 1
			}
			out = append(out, v)
		case reflect.Array:
			if t.Elem().Kind() != reflect.Uint8 {
				panic(fmt.Sprintf("array of non-uint8 in field %d: %T", i, field.Interface()))
			}
			for j, l := 0, t.Len(); j < l; j++ {
				out = append(out, uint8(field.Index(j).Uint()))
			}
		case reflect.Uint32:
			out = appendU32(out, uint32(field.Uint()))
		case reflect.Uint64:
			out = appendU64(out, uint64(field.Uint()))
		case reflect.Uint8:
			out = append(out, uint8(field.Uint()))
		case reflect.String:
			s := field.String()
			out = appendInt(out, len(s))
			out = append(out, s...)
		case reflect.Slice:
			switch t.Elem().Kind() {
			case reflect.Uint8:
				if v.Type().Field(i).Tag.Get("ssh") != "rest" {
					out = appendInt(out, field.Len())
				}
				out = append(out, field.Bytes()...)
			case reflect.String:
				offset := len(out)
				out = appendU32(out, 0)
				if n := field.Len(); n > 0 {
					for j := 0; j < n; j++ {
						f := field.Index(j)
						if j != 0 {
							out = append(out, ',')
						}
						out = append(out, f.String()...)
					}
					// overwrite length value
					binary.BigEndian.PutUint32(out[offset:], uint32(len(out)-offset-4))
				}
			default:
				panic(fmt.Sprintf("slice of unknown type in field %d: %T", i, field.Interface()))
			}
		case reflect.Ptr:
			if t == bigIntType {
				var n *big.Int
				nValue := reflect.ValueOf(&n)
				nValue.Elem().Set(field)
				needed := intLength(n)
				oldLength := len(out)

				if cap(out)-len(out) < needed {
					newOut := make([]byte, len(out), 2*(len(out)+needed))
					copy(newOut, out)
					out = newOut
				}
				out = out[:oldLength+needed]
				marshalInt(out[oldLength:], n)
			} else {
				panic(fmt.Sprintf("pointer to unknown type in field %d: %T", i, field.Interface()))
			}
		}
	}

	return out
}

func parseString(in []byte) (out, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	fmt.Println("ok")
	length := binary.BigEndian.Uint32(in)
	in = in[4:]
	if uint32(len(in)) < length {
		return
	}
	fmt.Println("ok")
	out = in[:length]
	rest = in[length:]
	ok = true
	return
}

var (
	comma         = []byte{','}
	emptyNameList = []string{}
)

func parseNameList(in []byte) (out []string, rest []byte, ok bool) {
	contents, rest, ok := parseString(in)
	if !ok {
		return
	}
	if len(contents) == 0 {
		out = emptyNameList
		return
	}
	parts := bytes.Split(contents, comma)
	out = make([]string, len(parts))
	for i, part := range parts {
		out[i] = string(part)
	}
	return
}

func parseInt(in []byte) (out *big.Int, rest []byte, ok bool) {
	if len(in) < 2 {
		return
	}

	bits := binary.BigEndian.Uint16(in)
	in = in[2:]

	out = new(big.Int)
	out.SetBytes(in[:((bits+7)/8)+1])

	rest = in[(bits+7)/8:]
	ok = true

	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseUint64(in []byte) (uint64, []byte, bool) {
	if len(in) < 8 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint64(in), in[8:], true
}

func intLength(n *big.Int) int {
	length := 4 /* length bytes */
	if n.Sign() < 0 {
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bitLen := nMinus1.BitLen()
		if bitLen%8 == 0 {
			// The number will need 0xff padding
			length++
		}
		length += (bitLen + 7) / 8
	} else if n.Sign() == 0 {
		// A zero is the zero length string
	} else {
		bitLen := n.BitLen()
		if bitLen%8 == 0 {
			// The number will need 0x00 padding
			length++
		}
		length += (bitLen + 7) / 8
	}

	return length
}

func marshalUint32(to []byte, n uint32) []byte {
	binary.BigEndian.PutUint32(to, n)
	return to[4:]
}

func marshalUint64(to []byte, n uint64) []byte {
	binary.BigEndian.PutUint64(to, n)
	return to[8:]
}

func marshalInt(to []byte, n *big.Int) []byte {
	lengthBytes := to
	to = to[4:]
	length := 0

	if n.Sign() < 0 {
		// A negative number has to be converted to two's-complement
		// form. So we'll subtract 1 and invert. If the
		// most-significant-bit isn't set then we'll need to pad the
		// beginning with 0xff in order to keep the number negative.
		nMinus1 := new(big.Int).Neg(n)
		nMinus1.Sub(nMinus1, bigOne)
		bytes := nMinus1.Bytes()
		for i := range bytes {
			bytes[i] ^= 0xff
		}
		if len(bytes) == 0 || bytes[0]&0x80 == 0 {
			to[0] = 0xff
			to = to[1:]
			length++
		}
		nBytes := copy(to, bytes)
		to = to[nBytes:]
		length += nBytes
	} else if n.Sign() == 0 {
		// A zero is the zero length string
	} else {
		bytes := n.Bytes()
		if len(bytes) > 0 && bytes[0]&0x80 != 0 {
			// We'll have to pad this with a 0x00 in order to
			// stop it looking like a negative number.
			to[0] = 0
			to = to[1:]
			length++
		}
		nBytes := copy(to, bytes)
		to = to[nBytes:]
		length += nBytes
	}

	lengthBytes[0] = byte(length >> 24)
	lengthBytes[1] = byte(length >> 16)
	lengthBytes[2] = byte(length >> 8)
	lengthBytes[3] = byte(length)
	return to
}

func writeInt(w io.Writer, n *big.Int) {
	length := intLength(n)
	buf := make([]byte, length)
	marshalInt(buf, n)
	w.Write(buf)
}

func writeString(w io.Writer, s []byte) {
	var lengthBytes [4]byte
	lengthBytes[0] = byte(len(s) >> 24)
	lengthBytes[1] = byte(len(s) >> 16)
	lengthBytes[2] = byte(len(s) >> 8)
	lengthBytes[3] = byte(len(s))
	w.Write(lengthBytes[:])
	w.Write(s)
}

func stringLength(n int) int {
	return 4 + n
}

func marshalString(to []byte, s []byte) []byte {
	to[0] = byte(len(s) >> 24)
	to[1] = byte(len(s) >> 16)
	to[2] = byte(len(s) >> 8)
	to[3] = byte(len(s))
	to = to[4:]
	copy(to, s)
	return to[len(s):]
}

func decode(packetType byte, packet []byte) (interface{}, error) {
	var msg interface{}
	switch packetType {
	case msgDisconnect:
		msg = new(disconnectMsg)
	case smsgPublicKey:
		msg = new(pubKeySmsg)
	case cmsgSessionKey:
		msg = new(sessionKeyCmsg)
	case cmsgUser:
		msg = new(userCmsg)
	case cmsgAuthRhosts:
		msg = new(authRhostsCmsg)
	case cmsgAuthRSA:
		msg = new(authRSACmsg)
	case smsgAuthRSAChallenge:
		msg = new(authRSAChallengeSmsg)
	case cmsgAuthRSAResponse:
		msg = new(authRSAResponceCmsg)
	case cmsgAuthPassword:
		msg = new(authPasswordCmsg)
	case cmsgRequestPTY:
		msg = new(requestPTYCmsg)
	case cmsgWindowSize:
		msg = new(windowSizeCmsg)
	case cmsgExecCmd:
		msg = new(execCmdCmsg)
	case cmsgStdinData:
		msg = new(stdinDataCmsg)
	case smsgStdoutData:
		msg = new(stdoutDataSmsg)
	case smsgStderrData:
		msg = new(stderrDataSmsg)
	case smsgExitstatus:
		msg = new(exitstatusSmsg)
	case msgChannelOpenConfirmation:
		msg = new(channelOpenConfirmationMsg)
	case msgChannelOpenFailure:
		msg = new(channelOpenFailureMsg)
	case msgChannelData:
		msg = new(channelDataMsg)
	case msgChannelClose:
		msg = new(channelCloseMsg)
	case msgChannelCloseConfirmation:
		msg = new(channelCloseConfirmationMsg)
	case smsgX11Open:
		msg = new(x11OpenSmsg)
	case cmsgPortForwardRequest:
		msg = new(portForwardRequestCmsg)
	case msgPortOpen:
		msg = new(portOpenMsg)
	case smsgAgentOpen:
		msg = new(agentOpenSmsg)
	case msgIgnore:
		msg = new(ignoreMsg)
	case cmsgX11RequestForwarding:
		msg = new(x11RequestForwardingCmsg)
	case cmsgAuthRhostsRSA:
		msg = new(authRhostsRSACmsg)
	case msgDebug:
		msg = new(debugMsg)
	case cmsgRequestCompression:
		msg = new(requestCompressionCmsg)
	case cmsgMaxPacketSize:
		msg = new(maxPacketSizeCmsg)
	case smsgAuthTisChallenge:
		msg = new(authTisChallengeSmsg)
	case cmsgAuthTisResponse:
		msg = new(authTisResponseCmsg)
	case cmsgAuthKerberos:
		msg = new(authKerberosCmsg)
	case smsgAuthKerberosResponse:
		msg = new(authKerberosResponseSmsg)
	case cmsgHaveKerberosTGT:
		msg = new(haveKerberosTGTCmsg)
	default:
		return nil, unexpectedMessageError(0, packet[0])
	}
	if err := Unmarshal(packetType, packet, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
