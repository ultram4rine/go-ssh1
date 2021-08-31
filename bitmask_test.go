package ssh1

import "testing"

func TestHasFlag(t *testing.T) {
	var m = newBitmask(SSH_CIPHER_3DES)
	v := m.hasFlag(SSH_CIPHER_3DES)
	if !v {
		t.Error("Expected true, got", v)
	}
}

func TestAddFlag(t *testing.T) {
	var m = newBitmask(SSH_CIPHER_3DES)
	m.addFlag(SSH_CIPHER_DES)
	v := m.hasFlag(SSH_CIPHER_DES)
	if !v {
		t.Error("Expected true, got", v)
	}
}

func TestRemoveFlag(t *testing.T) {
	var m = newBitmask(SSH_CIPHER_3DES)
	m.removeFlag(SSH_CIPHER_3DES)
	v := m.hasFlag(SSH_CIPHER_3DES)
	if !v {
		t.Error("Expected false, got", v)
	}
}

func TestToggleFlag(t *testing.T) {
	var m = newBitmask(SSH_CIPHER_3DES)
	m.toggleFlag(SSH_CIPHER_3DES)
	v := m.hasFlag(SSH_CIPHER_3DES)
	if v {
		t.Error("Expected false, got", v)
	}
}
