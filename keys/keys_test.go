package keys

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerate(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if kp == nil {
		t.Fatal("Generate() returned nil keypair")
	}

	// Check Identity Keys (Ed25519)
	if len(kp.IdentityPriv) != ed25519.PrivateKeySize {
		t.Errorf("IdentityPriv length = %d, want %d", len(kp.IdentityPriv), ed25519.PrivateKeySize)
	}
	if len(kp.IdentityPub) != ed25519.PublicKeySize {
		t.Errorf("IdentityPub length = %d, want %d", len(kp.IdentityPub), ed25519.PublicKeySize)
	}

	// Check Exchange Keys (X25519)
	// ecdh.PrivateKey and PublicKey don't expose direct byte length checks easily without Bytes(),
	// but we can check if they are non-nil.
	if kp.ExchangePriv == nil {
		t.Error("ExchangePriv is nil")
	}
	if kp.ExchangePub == nil {
		t.Error("ExchangePub is nil")
	}

	// Verify Public Bundle
	bundle := kp.Public()
	if bundle == nil {
		t.Fatal("Public() returned nil bundle")
	}
	if !bundle.IdentityPub.Equal(kp.IdentityPub) {
		t.Error("Public bundle IdentityPub does not match original")
	}
	if !bundle.ExchangePub.Equal(kp.ExchangePub) {
		t.Error("Public bundle ExchangePub does not match original")
	}
}
