package ssh1

const (
	// SSH_AUTH_RHOSTS is auth using .rhosts file
	SSH_AUTH_RHOSTS = iota + 1
	// SSH_AUTH_RSA is RSA auth
	SSH_AUTH_RSA
	// SSH_AUTH_PASSWORD is auth using password
	SSH_AUTH_PASSWORD
	// SSH_AUTH_RHOSTS_RSA is auth using .rhosts file with RSA
	SSH_AUTH_RHOSTS_RSA
	SSH_AUTH_TIS
	SSH_AUTH_KERBEROS
	passKerberosTGT
	passAFSToken = 21
)

var authMethods = map[int]string{
	SSH_AUTH_RHOSTS:     "rhosts",
	SSH_AUTH_RSA:        "rsa",
	SSH_AUTH_PASSWORD:   "password",
	SSH_AUTH_RHOSTS_RSA: "rhosts_rsa",
}

// CreateAuthMask returns a bitmask of choosen auth methods or panic
// if auth method not supported or length of choosen methods too small
// or too big
func CreateAuthMask(methods ...int) *Bitmask {
	var mask = new(Bitmask)

	if len(methods) <= 0 {
		panic("ssh1: too few auth methods")
	}
	if len(methods) > len(authMethods) {
		panic("ssh1: too many auth methods")
	}

	for _, m := range methods {
		if _, ok := authMethods[m]; !ok {
			panic("ssh1: choosen auth method doesn't supported")
		}
		mask.addFlag(m)
	}

	return mask
}
