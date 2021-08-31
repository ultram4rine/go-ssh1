package ssh1

import (
	"bytes"
	"crypto/rand"
	"testing"
)

var cipherNames = map[int]string{
	SSH_CIPHER_IDEA:     "idea",
	SSH_CIPHER_DES:      "des",
	SSH_CIPHER_3DES:     "3des",
	SSH_CIPHER_RC4:      "rc4",
	SSH_CIPHER_BLOWFISH: "blowfish",
}

func TestPacketCiphers(t *testing.T) {
	for k, v := range cipherNames {
		t.Run("cipher="+v,
			func(t *testing.T) { testPacketCipher(t, k, v) })
	}
}

func testPacketCipher(t *testing.T, k int, v string) {
	var (
		server packetCipher
		client packetCipher
		key    = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
		iv     = []byte{0, 0, 0, 0, 0, 0, 0, 0}
		err    error
	)

	switch k {
	case SSH_CIPHER_IDEA:
		{
			server, err = newIDEACFBCipher(key[:16], iv)
			if err != nil {
				t.Fatalf("newTripleDESCBCCipher(%q, %q): %v", key[:16], iv, err)
			}
			client, err = newIDEACFBCipher(key[:16], iv)
			if err != nil {
				t.Fatalf("newTripleDESCBCCipher(%q, %q): %v", key[:16], iv, err)
			}
		}
	case SSH_CIPHER_DES:
		{
			server, err = newDESCBCCipher(key[:8], iv)
			if err != nil {
				t.Fatalf("newDESCBCCipher(%q, %q): %v", key[:8], iv, err)
			}
			client, err = newDESCBCCipher(key[:8], iv)
			if err != nil {
				t.Fatalf("newDESCBCCipher(%q, %q): %v", key[:8], iv, err)
			}
		}
	case SSH_CIPHER_3DES:
		{
			server, err = newTripleDESCBCCipher(key[:24], iv)
			if err != nil {
				t.Fatalf("newTripleDESCBCCipher(%q, %q): %v", key[:24], iv, err)
			}
			client, err = newTripleDESCBCCipher(key[:24], iv)
			if err != nil {
				t.Fatalf("newTripleDESCBCCipher(%q, %q): %v", key[:24], iv, err)
			}
		}
	case SSH_CIPHER_RC4:
		{
			server, err = newRC4(key[:24], iv)
			if err != nil {
				t.Fatalf("newRC4(%q, %q): %v", key[:24], iv, err)
			}
			client, err = newRC4(key[:24], iv)
			if err != nil {
				t.Fatalf("newRC4(%q, %q): %v", key[:24], iv, err)
			}
		}
	case SSH_CIPHER_BLOWFISH:
		{
			server, err = newBlowfishCBCCipher(key[:], iv)
			if err != nil {
				t.Fatalf("newBlowfishCBCCipher(%q, %q): %v", key[:], iv, err)
			}
			client, err = newBlowfishCBCCipher(key[:], iv)
			if err != nil {
				t.Fatalf("newBlowfishCBCCipher(%q, %q): %v", key[:], iv, err)
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
	if err := server.writeCipherPacket(buf, rand.Reader, 0, input); err != nil {
		t.Fatalf("writeCipherPacket(%q, %q, %q, %q, %q): %v", 0, buf, rand.Reader, 0, input, err)
	}

	pt, packet, err := client.readCipherPacket(buf)
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
