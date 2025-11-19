package box

import (
	"bytes"
	"testing"

	"github.com/tquanghuy/e2ee/keys"
)

func TestEncryptDecrypt(t *testing.T) {
	alice, err := keys.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Alice keys: %v", err)
	}
	bob, err := keys.Generate()
	if err != nil {
		t.Fatalf("Failed to generate Bob keys: %v", err)
	}

	message := []byte("Hello World")
	ciphertext, err := Encrypt(message, bob.ExchangePub, alice.IdentityPriv)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	plaintext, err := Decrypt(ciphertext, bob.ExchangePriv, alice.IdentityPub)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(message, plaintext) {
		t.Errorf("Expected %s, got %s", message, plaintext)
	}
}

func TestSignVerify(t *testing.T) {
	alice, err := keys.Generate()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	message := []byte("Important Document")
	signature := Sign(message, alice.IdentityPriv)

	if !Verify(message, signature, alice.IdentityPub) {
		t.Error("Signature verification failed")
	}

	// Test invalid signature
	signature[0] ^= 0xFF
	if Verify(message, signature, alice.IdentityPub) {
		t.Error("Verification succeeded with invalid signature")
	}
}

func TestDecryptInvalid(t *testing.T) {
	alice, _ := keys.Generate()
	bob, _ := keys.Generate()

	// Too short
	if _, err := Decrypt([]byte("short"), bob.ExchangePriv, alice.IdentityPub); err == nil {
		t.Error("Expected error for short ciphertext")
	}

	// Corrupted
	msg := []byte("test")
	ciphertext, _ := Encrypt(msg, bob.ExchangePub, alice.IdentityPriv)
	ciphertext[len(ciphertext)-1] ^= 0xFF
	if _, err := Decrypt(ciphertext, bob.ExchangePriv, alice.IdentityPub); err == nil {
		t.Error("Expected error for corrupted ciphertext")
	}
}
