package ssh1

import (
	"fmt"
	"math/big"
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
	//OBSOLETED: SSH_CMSG_X11_REQUEST_FORWARDING
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

//Protocol version 1.5 overloads some version 1.3 message types
const (
	msgChannelInputEOF    = msgChannelClose
	msgChannelOutputClose = msgChannelCloseConfirmation
)

type disconnectMsg struct {
	Cause string `sshtype:"1"`
}

func (m disconnectMsg) Error() string {
	return fmt.Sprintf("ssh: disconnect, reason: %s", m.Cause)
}

type pubKeySmsg struct {
	Cookie               [8]byte `sshtype:"2"`
	ServerKey            uint32
	ServerKeyPubExponent big.Int
	ServerKeyPubModulus  big.Int
	HostKey              uint32
	HostKeyPubExponent   big.Int
	HostKeyPubModulus    big.Int
	ProtocolFlags        uint32
	CipherMask           uint32
	AuthMask             uint32
}

type sessionKeyCmsg struct {
	Cipher        byte `sshtype:"3"`
	Cookie        [8]byte
	SessionKey    big.Int
	ProtocolFlags uint32
}

type userCmsg struct {
	UserName string `sshtype:"4"`
}

type authRhostsCmsg struct {
	UserName string `sshtype:"5"`
}

type authRSACmsg struct {
	IdentityPubModulus big.Int `sshtype:"6"`
}

type authRSAChallengeSmsg struct {
	Challenge big.Int `sshtype:"7"`
}

type authRSAResponceCmsg struct {
	Challenge [16]byte `sshtype:"8"`
}

type authPasswordCmsg struct {
	Password string `sshtype:"9"`
}

type requestPTYCmsg struct {
	TermEnv      string `sshtype:"10"`
	Height       uint32
	Width        uint32
	WidthPixels  uint32
	HeightPixels uint32
	TTYModes     []byte
}

type windowSizeCmsg struct {
	Height       uint32 `sshtype:"11"`
	Width        uint32
	WidthPixels  uint32
	HeightPixels uint32
}

type execCmdCmsg struct {
	Command string `sshtype:"13"`
}

type stdinDataCmsg struct {
	Data string `sshtype:"16"`
}

type stdoutDataSmsg struct {
	Data string `sshtype:"17"`
}

type stderrDataSmsg struct {
	Data string `sshtype:"18"`
}

type exitStatusSmsg struct {
	Status uint32 `sshtype:"20"`
}

type channelOpenConfirmationMsg struct {
	Remote uint32 `sshtype:"21"`
	Local  uint32
}

type channelOpenFailureMsg struct {
	Remote uint32 `sshtype:"22"`
}

type channelDataMsg struct {
	Remote uint32 `sshtype:"23"`
	Data   string
}

type channelCloseMsg struct {
	Remote uint32 `sshtype:"24"`
}

type channelCloseConfirmationMsg struct {
	Remote uint32 `sshtype:"25"`
}

type x11OpenSmsg struct {
	Local      uint32 `sshtype:"27"`
	Originator string
}

type portForwardRequestCmsg struct {
	ServerPort uint32 `sshtype:"28"`
	Host       string
	Port       uint32
}

type portOpenMsg struct {
	Local      uint32 `sshtype:"29"`
	Host       string
	Port       uint32
	Originator string
}

type agentOpenSmsg struct {
	Local uint32 `sshtype:"31"`
}

type ignoreMsg struct {
	Data string `sshtype:"32"`
}

type x11RequestForwardingCmsg struct {
	X11AuthProto string `sshtype:"34"`
	X11AuthData  string
	ScreenNum    uint32
}

type authRhostsRSACmsg struct {
	UserName           string `sshtype:"35"`
	HostKey            uint32
	HostKeyPubExponent big.Int
	HostKeyPubModulus  big.Int
}

type debugMsg struct {
	Debug string `sshtype:"36"`
}

type requestCompressionCmsg struct {
	Level uint32 `sshtype:"37"`
}

type maxPacketSizeCmsg struct {
	Size uint32 `sshtype:"38"`
}

type authTisChallengeSmsg struct {
	Challenge string `sshtype:"40"`
}

type authTisResponseCmsg struct {
	Response string `sshtype:"41"`
}

type authKerberosCmsg struct {
	AuthInfo string `sshtype:"42"`
}

type authKerberosResponseSmsg struct {
	Response string `sshtype:"43"`
}

type haveKerberosTGTCmsg struct {
	Credentials string `sshtype:"44"`
}
