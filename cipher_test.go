package ssh1

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPacketCiphers(t *testing.T) {
	for k, v := range CipherNames {
		t.Run("cipher="+v,
			func(t *testing.T) { testPacketCipher(t, k, v) })
	}
}

func testPacketCipher(t *testing.T, k int, v string) {
	var (
		server packetCipher
		client packetCipher
		err    error
	)

	switch k {
	case SSH_CIPHER_IDEA:
		{
			server, err = newIDEACFBCipher([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, []byte{0, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatalf("newTripleDESCBCCipher(%q, %q): %v", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, []byte{0, 0, 0, 0, 0, 0, 0, 0}, err)
			}
			client, err = newIDEACFBCipher([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, []byte{0, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatalf("newTripleDESCBCCipher(%q, %q): %v", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, []byte{0, 0, 0, 0, 0, 0, 0, 0}, err)
			}
		}
	case SSH_CIPHER_DES:
		{
			server, err = newDESCBCCipher([]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatalf("newDESCBCCipher(%q, %q): %v", []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 0, 0, 0, 0, 0, 0, 0}, err)
			}
			client, err = newDESCBCCipher([]byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatalf("newDESCBCCipher(%q, %q): %v", []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{0, 0, 0, 0, 0, 0, 0, 0}, err)
			}
		}
	case SSH_CIPHER_3DES:
		{
			server, err = newTripleDESCBCCipher([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, []byte{0, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatalf("newTripleDESCBCCipher(%q, %q): %v", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, []byte{0, 0, 0, 0, 0, 0, 0, 0}, err)
			}
			client, err = newTripleDESCBCCipher([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, []byte{0, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatalf("newTripleDESCBCCipher(%q, %q): %v", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, []byte{0, 0, 0, 0, 0, 0, 0, 0}, err)
			}
		}
	case SSH_CIPHER_RC4:
		{
			server, err = newRC4([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, []byte{0, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatalf("newRC4(%q, %q): %v", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, []byte{0, 0, 0, 0, 0, 0, 0, 0}, err)
			}
			client, err = newRC4([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, []byte{0, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				t.Fatalf("newRC4(%q, %q): %v", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}, []byte{0, 0, 0, 0, 0, 0, 0, 0}, err)
			}
		}
	default:
		{
			t.Fatalf("unsupported cipher: %v", v)
		}
	}

	want := "bla bla"
	input := []byte(want)
	buf := &bytes.Buffer{}
	if err := server.writeCipherPacket(0, buf, rand.Reader, 0, input); err != nil {
		t.Fatalf("writeCipherPacket(%q, %q, %q, %q, %q): %v", 0, buf, rand.Reader, 0, input, err)
	}

	pt, packet, err := client.readCipherPacket(0, buf)
	if err != nil {
		t.Fatalf("readCipherPacket(%q, %q): %v", 0, buf, err)
	}

	if pt != 0 {
		t.Errorf("packet type(DES CBC): got %q, want %q", pt, 0)
	}

	if string(packet) != want {
		t.Errorf("roundtrip(DES CBC): got %q, want %q", packet, want)
	}
}
