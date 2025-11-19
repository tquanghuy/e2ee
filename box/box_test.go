package box

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tquanghuy/e2ee/keys"
)

func TestEncryptDecrypt(t *testing.T) {
	alice, _ := keys.Generate()
	bob, _ := keys.Generate()

	tests := []struct {
		name    string
		message []byte
	}{
		{"Normal message", []byte("Hello World")},
		{"Empty message", []byte("")},
		{"Long message", make([]byte, 10000)},
		{"Binary message", []byte{0x00, 0xFF, 0xAA, 0x55}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := Encrypt(tt.message, bob.ExchangePub, alice.IdentityPriv)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			plaintext, err := Decrypt(ciphertext, bob.ExchangePriv, alice.IdentityPub)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if !bytes.Equal(plaintext, tt.message) {
				t.Errorf("Decrypt() = %v, want %v", plaintext, tt.message)
			}
		})
	}
}

func TestDecryptErrors(t *testing.T) {
	alice, _ := keys.Generate()
	bob, _ := keys.Generate()

	validMsg := []byte("test message")
	validCiphertext, _ := Encrypt(validMsg, bob.ExchangePub, alice.IdentityPriv)

	tests := []struct {
		name        string
		ciphertext  []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "Too short",
			ciphertext:  []byte("short"),
			wantErr:     true,
			errContains: "ciphertext too short",
		},
		{
			name:       "Corrupted ephemeral key",
			ciphertext: mutateByte(validCiphertext, 0), // First byte is part of ephemeral key
			wantErr:    true,
			// The error might be "invalid ephemeral public key" or "failed to derive shared secret" or AEAD failure depending on where it fails.
			// Usually changing a byte in public key makes it a valid point still on Curve25519 (all 32-byte strings are valid X25519 keys mostly),
			// so it will likely fail at AEAD decryption because shared secret is wrong.
			errContains: "decryption failed",
		},
		{
			name:        "Corrupted nonce",
			ciphertext:  mutateByte(validCiphertext, 32), // 32 is start of nonce
			wantErr:     true,
			errContains: "decryption failed",
		},
		{
			name:        "Corrupted ciphertext body",
			ciphertext:  mutateByte(validCiphertext, len(validCiphertext)-1),
			wantErr:     true,
			errContains: "decryption failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decrypt(tt.ciphertext, bob.ExchangePriv, alice.IdentityPub)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errContains != "" {
				if !contains(err.Error(), tt.errContains) {
					t.Errorf("Decrypt() error = %v, want error containing %q", err, tt.errContains)
				}
			}
		})
	}
}

func TestSignVerify(t *testing.T) {
	alice, _ := keys.Generate()

	tests := []struct {
		name    string
		message []byte
	}{
		{"Normal message", []byte("Important Document")},
		{"Empty message", []byte{}},
		{"Long message", make([]byte, 5000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := Sign(tt.message, alice.IdentityPriv)
			if !Verify(tt.message, sig, alice.IdentityPub) {
				t.Error("Verify() failed for valid signature")
			}

			// Test invalid signature
			if len(sig) > 0 {
				badSig := make([]byte, len(sig))
				copy(badSig, sig)
				badSig[0] ^= 0xFF
				if Verify(tt.message, badSig, alice.IdentityPub) {
					t.Error("Verify() succeeded for invalid signature")
				}
			}
		})
	}
}

// Helpers

func mutateByte(data []byte, index int) []byte {
	newData := make([]byte, len(data))
	copy(newData, data)
	newData[index] ^= 0xFF
	return newData
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
