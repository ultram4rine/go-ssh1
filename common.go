package ssh1

import "fmt"

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

func appendString(buf []byte, s string) []byte {
	buf = appendU32(buf, uint32(len(s)))
	buf = append(buf, s...)
	return buf
}

func appendU32(buf []byte, n uint32) []byte {
	return append(buf, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func appendInt(buf []byte, n int) []byte {
	return appendU32(buf, uint32(n))
}
