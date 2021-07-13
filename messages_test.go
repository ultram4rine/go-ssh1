package ssh1

import (
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

func TestMarshalUnmarshal(t *testing.T) {
	rand := rand.New(rand.NewSource(0))

	cookieBytes := make([]byte, 8)
	rand.Read(cookieBytes)
	var cookie [8]byte
	copy(cookie[:], cookieBytes)

	sessionKeyBytes := make([]byte, 32)
	rand.Read(sessionKeyBytes)
	sk := new(big.Int)
	sk = sk.SetBytes(sessionKeyBytes)

	val := sessionKeyCmsg{
		Cipher:        byte(2),
		Cookie:        cookie,
		SessionKey:    sk,
		ProtocolFlags: 0,
	}
	var iface sessionKeyCmsg

	pt, p := Marshal(val)
	if err := Unmarshal(pt, p, &iface); err != nil {
		t.Errorf("Unmarshal %#v: %s", iface, err)
	}

	if !reflect.DeepEqual(iface, val) {
		t.Errorf("got: %#v\nwant:%#v\n%x", iface, val, p)
	}
}
