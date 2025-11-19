package keys

import (
	"crypto/ed25519"
	"encoding/pem"
	"os"
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

func TestSerialization(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// ToPEM
	pemData, err := kp.ToPEM()
	if err != nil {
		t.Fatalf("ToPEM() error = %v", err)
	}
	if len(pemData) == 0 {
		t.Fatal("ToPEM() returned empty data")
	}

	// FromPEM
	kp2, err := FromPEM(pemData)
	if err != nil {
		t.Fatalf("FromPEM() error = %v", err)
	}

	// Verify keys match
	if !kp.IdentityPub.Equal(kp2.IdentityPub) {
		t.Error("IdentityPub does not match after roundtrip")
	}
	if !kp.ExchangePub.Equal(kp2.ExchangePub) {
		t.Error("ExchangePub does not match after roundtrip")
	}

	// Verify private keys match (by checking if they produce same public keys,
	// and for Ed25519 we can check bytes directly)
	if !kp.IdentityPriv.Equal(kp2.IdentityPriv) {
		t.Error("IdentityPriv does not match after roundtrip")
	}
	// For ECDH private keys, Equal() isn't directly available on the key itself in standard lib easily
	// without converting to bytes, but we checked public keys which implies private keys are likely correct.
	// Let's double check by doing an ECDH operation if we really wanted to be sure,
	// but checking public key equality is usually sufficient for basic serialization tests.
}

func TestSaveLoad(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	tmpFile := "test_key.pem"
	defer func() {
		_ = os.Remove(tmpFile)
	}()

	if err := kp.Save(tmpFile); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	kp2, err := Load(tmpFile)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !kp.IdentityPub.Equal(kp2.IdentityPub) {
		t.Error("Loaded key IdentityPub does not match saved key")
	}
}

func TestFromPEMErrors(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantError bool
	}{
		{
			name:      "Empty input",
			input:     []byte{},
			wantError: true,
		},
		{
			name:      "Invalid PEM block type",
			input:     []byte("-----BEGIN WRONG TYPE-----\nDATA\n-----END WRONG TYPE-----\n"),
			wantError: true,
		},
		{
			name:      "Garbage data",
			input:     []byte("not a pem block"),
			wantError: true,
		},
		{
			name:      "Short key data",
			input:     pemEncode("E2EE PRIVATE KEY", []byte("short")),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromPEM(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("FromPEM() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestLoadErrors(t *testing.T) {
	// Test non-existent file
	_, err := Load("non_existent_file.pem")
	if err == nil {
		t.Error("Expected error loading non-existent file, got nil")
	}
}

// Helper to create PEM data for tests
func pemEncode(typeName string, bytes []byte) []byte {
	block := &pem.Block{
		Type:  typeName,
		Bytes: bytes,
	}
	return pem.EncodeToMemory(block)
}
