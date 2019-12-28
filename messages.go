package ssh1

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
