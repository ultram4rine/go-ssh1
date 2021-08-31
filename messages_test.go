package ssh1

import (
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

type allTypesMsg struct {
	Byte   byte `ssh1type:"254"`
	UInt32 uint32
	Array  [8]byte
	String string
	BigInt *big.Int
	Slice  []byte
}

func TestMarshalUnmarshal(t *testing.T) {
	rand := rand.New(rand.NewSource(0))

	randomBytes := make([]byte, 50)
	rand.Read(randomBytes)

	var aBytes [8]byte
	copy(aBytes[:], randomBytes)

	bigInt := new(big.Int)
	bigInt = bigInt.SetBytes(randomBytes[8:40])

	val := allTypesMsg{
		Byte:   1,
		UInt32: 1024,
		Array:  aBytes,
		String: "bla-bla",
		BigInt: bigInt,
		Slice:  randomBytes[40:],
	}
	var iface allTypesMsg

	pt, p := Marshal(val)
	if err := Unmarshal(pt, p, &iface); err != nil {
		t.Errorf("Unmarshal %#v: %s", iface, err)
	}

	if !reflect.DeepEqual(iface, val) {
		t.Errorf("got: %#v\nwant:%#v\n%x", iface, val, p)
	}
}
