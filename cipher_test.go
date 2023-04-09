package ssh1

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

func TestChooseCipher(t *testing.T) {
	var (
		cipherMask   = newBitmask(SSH_CIPHER_3DES)
		ciphersOrder = []int{SSH_CIPHER_3DES}
	)
	cipherNumber, err := chooseCipher(*cipherMask, ciphersOrder)
	if err != nil {
		t.Fatalf("chooseCipher(%d, %d): %v", *cipherMask, ciphersOrder, err)
	}
	if cipherNumber != SSH_CIPHER_3DES {
		t.Errorf("choose cipher(3DES): got %d, want %d", cipherNumber, SSH_CIPHER_3DES)
	}
}

func TestChooseCipherFail(t *testing.T) {
	var (
		cipherMask   = newBitmask(7)
		ciphersOrder = []int{SSH_CIPHER_3DES}
	)
	cipherNumber, err := chooseCipher(*cipherMask, ciphersOrder)
	if err == nil {
		t.Fatalf("chooseCipher(%d, %q): err is nil", *cipherMask, ciphersOrder)
	}
	if cipherNumber != -1 {
		t.Errorf("choose cipher(unsupported cipher): got %d, want %d", cipherNumber, -1)
	}
}

func TestCheckLengthFail(t *testing.T) {
	var lengths = [2]uint32{4, 262145}
	for _, l := range lengths {
		t.Run(fmt.Sprintf("length=%d", l),
			func(t *testing.T) {
				if err := checkLength(l); err == nil {
					t.Fatalf("checkLength(%d): err is nil", l)
				}
			})
	}
}

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
