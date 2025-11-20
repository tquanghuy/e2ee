package e2ee

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// KeyPair holds both the identity keypair (Ed25519) and the exchange keypair (X25519).
// In a real E2EE scenario, you often have an identity key (signing) and prekeys (encryption).
// For simplicity in this SDK, we bundle them, but keep them cryptographically separate.
//
// The KeyPair now supports versioned exchange keys for key rotation.
// ExchangePriv and ExchangePub point to the currently active exchange key for backward compatibility.
type KeyPair struct {
	IdentityPriv ed25519.PrivateKey
	IdentityPub  ed25519.PublicKey
	ExchangePriv *ecdh.PrivateKey // Points to active exchange key (for backward compatibility)
	ExchangePub  *ecdh.PublicKey  // Points to active exchange public key (for backward compatibility)

	// Versioned exchange keys for key rotation support
	ExchangeKeys          []VersionedExchangeKey // All exchange key versions
	ActiveExchangeVersion uint32                 // Current active version number
}

// Generate generates a new set of keys for a user.
func Generate() (*KeyPair, error) {
	// Generate Ed25519 Identity Key
	identityPub, identityPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity key: %w", err)
	}

	// Generate X25519 Exchange Key
	curve := ecdh.X25519()
	exchangePriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate exchange key: %w", err)
	}

	// Create initial versioned exchange key (version 1)
	initialVersion := VersionedExchangeKey{
		Version:   1,
		Key:       exchangePriv,
		PublicKey: exchangePriv.PublicKey(),
		CreatedAt: time.Now(),
		ExpiresAt: nil,
		Status:    KeyStatusActive,
	}

	return &KeyPair{
		IdentityPriv:          identityPriv,
		IdentityPub:           identityPub,
		ExchangePriv:          exchangePriv,
		ExchangePub:           exchangePriv.PublicKey(),
		ExchangeKeys:          []VersionedExchangeKey{initialVersion},
		ActiveExchangeVersion: 1,
	}, nil
}

// PublicKeyBundle represents the public keys that need to be shared with other users.
type PublicKeyBundle struct {
	IdentityPub ed25519.PublicKey
	ExchangePub *ecdh.PublicKey
}

// Public returns the public key bundle for this keypair.
func (kp *KeyPair) Public() *PublicKeyBundle {
	return &PublicKeyBundle{
		IdentityPub: kp.IdentityPub,
		ExchangePub: kp.ExchangePub,
	}
}

// ToPEM encodes the private keypair to a PEM block.
// It serializes the Identity Private Key (Ed25519) and Exchange Private Key (X25519).
// Note: This is a custom format bundling both keys.
func (kp *KeyPair) ToPEM() ([]byte, error) {
	// We will use a simple custom PEM block "E2EE PRIVATE KEY"
	// The content will be: IdentityPriv (64 bytes) || ExchangePriv (32 bytes)
	// Total 96 bytes.
	// Ideally we should use ASN.1 but for simplicity/compactness in this specific SDK we use raw concatenation
	// wrapped in PEM.

	if len(kp.IdentityPriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid identity private key size")
	}

	// ECDH private key bytes
	exchangeBytes := kp.ExchangePriv.Bytes()

	data := make([]byte, 0, len(kp.IdentityPriv)+len(exchangeBytes))
	data = append(data, kp.IdentityPriv...)
	data = append(data, exchangeBytes...)

	block := &pem.Block{
		Type:  "E2EE PRIVATE KEY",
		Bytes: data,
	}

	return pem.EncodeToMemory(block), nil
}

// FromPEM decodes a keypair from a PEM block.
// This function supports both legacy (single key) and versioned formats.
// Legacy keys are automatically migrated to version 1.
func FromPEM(data []byte) (*KeyPair, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Check if it's a versioned format
	if block.Type == "E2EE VERSIONED PRIVATE KEY" {
		return fromVersionedPEM(block)
	}

	// Legacy format: "E2EE PRIVATE KEY"
	if block.Type != "E2EE PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing E2EE PRIVATE KEY")
	}

	if len(block.Bytes) != ed25519.PrivateKeySize+32 { // 64 + 32 = 96
		return nil, fmt.Errorf("invalid key data length")
	}

	identityPriv := ed25519.PrivateKey(block.Bytes[:ed25519.PrivateKeySize])
	exchangePrivBytes := block.Bytes[ed25519.PrivateKeySize:]

	// Reconstruct keys
	identityPub := identityPriv.Public().(ed25519.PublicKey)

	curve := ecdh.X25519()
	exchangePriv, err := curve.NewPrivateKey(exchangePrivBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid exchange private key: %w", err)
	}

	// Migrate legacy key to versioned format (version 1)
	initialVersion := VersionedExchangeKey{
		Version:   1,
		Key:       exchangePriv,
		PublicKey: exchangePriv.PublicKey(),
		CreatedAt: time.Now(), // Use current time for migrated keys
		ExpiresAt: nil,
		Status:    KeyStatusActive,
	}

	return &KeyPair{
		IdentityPriv:          identityPriv,
		IdentityPub:           identityPub,
		ExchangePriv:          exchangePriv,
		ExchangePub:           exchangePriv.PublicKey(),
		ExchangeKeys:          []VersionedExchangeKey{initialVersion},
		ActiveExchangeVersion: 1,
	}, nil
}

// Save saves the keypair to a file in PEM format.
func (kp *KeyPair) Save(filename string) error {
	data, err := kp.ToPEM()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0600)
}

// Load loads a keypair from a file.
func Load(filename string) (*KeyPair, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return FromPEM(data)
}
