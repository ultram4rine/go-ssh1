package ssh1

const (
	SSH_AUTH_RHOSTS = iota + 1
	SSH_AUTH_RSA
	SSH_AUTH_PASSWORD
	SSH_AUTH_RHOSTS_RSA
	SSH_AUTH_TIS
	SSH_AUTH_KERBEROS
	SSH_PASS_KERBEROS_TGT
	SSH_PASS_AFS_TOKEN = 21
)
