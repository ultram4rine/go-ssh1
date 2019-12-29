package ssh1

const (
	authRhosts = iota + 1
	authRSA
	authPassword
	authRhostsRSA
	authTIS
	authKerberos
	passKerberosTGT
	passAFSToken = 21
)
