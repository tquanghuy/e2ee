package keys

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

// KeyPair holds both the identity keypair (Ed25519) and the exchange keypair (X25519).
// In a real E2EE scenario, you often have an identity key (signing) and prekeys (encryption).
// For simplicity in this SDK, we bundle them, but keep them cryptographically separate.
type KeyPair struct {
	IdentityPriv ed25519.PrivateKey
	IdentityPub  ed25519.PublicKey
	ExchangePriv *ecdh.PrivateKey
	ExchangePub  *ecdh.PublicKey
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

	return &KeyPair{
		IdentityPriv: identityPriv,
		IdentityPub:  identityPub,
		ExchangePriv: exchangePriv,
		ExchangePub:  exchangePriv.PublicKey(),
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
