package e2ee

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"fmt"
	"time"
)

// PrekeyBundle represents a bundle of public keys for establishing a session.
// This follows the Signal Protocol's X3DH key agreement pattern.
// A prekey bundle contains the recipient's identity key and signed prekey,
// which allows a sender to establish an encrypted session asynchronously.
type PrekeyBundle struct {
	// IdentityKey is the recipient's long-term identity public key (Ed25519)
	IdentityKey ed25519.PublicKey

	// SignedPrekey is the recipient's current signed prekey (X25519)
	SignedPrekey *SignedPrekeyPublic

	// PrekeySignature is the signature of the signed prekey by the identity key
	PrekeySignature []byte
}

// SignedPrekeyPublic represents the public portion of a signed prekey.
// In the Signal Protocol, signed prekeys are medium-term keys that are
// rotated periodically (e.g., weekly or monthly) and signed by the identity key.
type SignedPrekeyPublic struct {
	// KeyID uniquely identifies this prekey
	KeyID uint32

	// PublicKey is the X25519 public key
	PublicKey *ecdh.PublicKey

	// Timestamp indicates when this prekey was created
	Timestamp time.Time

	// Signature is the Ed25519 signature of the public key by the identity key
	Signature []byte
}

// CreatePrekeyBundle creates a prekey bundle from a KeyPair.
// This bundle can be published to a server or shared with other parties
// to enable asynchronous encrypted communication.
func (kp *KeyPair) CreatePrekeyBundle() (*PrekeyBundle, error) {
	activeKey := kp.GetActiveExchangeKey()
	if activeKey == nil {
		return nil, fmt.Errorf("no active exchange key available")
	}

	// Sign the public key with the identity key
	pubKeyBytes := activeKey.PublicKey.Bytes()
	signature := ed25519.Sign(kp.IdentityPriv, pubKeyBytes)

	signedPrekey := &SignedPrekeyPublic{
		KeyID:     activeKey.Version,
		PublicKey: activeKey.PublicKey,
		Timestamp: activeKey.CreatedAt,
		Signature: signature,
	}

	return &PrekeyBundle{
		IdentityKey:     kp.IdentityPub,
		SignedPrekey:    signedPrekey,
		PrekeySignature: signature,
	}, nil
}

// VerifyPrekeyBundle verifies the signature on a prekey bundle.
// This ensures that the signed prekey was actually created by the holder
// of the identity key, preventing man-in-the-middle attacks.
func VerifyPrekeyBundle(bundle *PrekeyBundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle cannot be nil")
	}

	if bundle.SignedPrekey == nil {
		return fmt.Errorf("signed prekey cannot be nil")
	}

	// Verify the signature
	pubKeyBytes := bundle.SignedPrekey.PublicKey.Bytes()
	if !ed25519.Verify(bundle.IdentityKey, pubKeyBytes, bundle.PrekeySignature) {
		return fmt.Errorf("prekey signature verification failed")
	}

	return nil
}

// Prekey type aliases for Signal Protocol terminology compatibility
// These provide industry-standard naming while maintaining backward compatibility

// SignedPrekey is an alias for VersionedExchangeKey to match Signal Protocol terminology.
// In Signal, "signed prekeys" are medium-term keys that are rotated periodically.
type SignedPrekey = VersionedExchangeKey

// GetActiveSignedPrekey returns the currently active signed prekey.
// This is an alias for GetActiveExchangeKey using Signal Protocol terminology.
func (kp *KeyPair) GetActiveSignedPrekey() *SignedPrekey {
	return kp.GetActiveExchangeKey()
}

// GetSignedPrekey retrieves a specific signed prekey by version/ID.
// This is an alias for GetExchangeKey using Signal Protocol terminology.
func (kp *KeyPair) GetSignedPrekey(version uint32) (*SignedPrekey, error) {
	return kp.GetExchangeKey(version)
}

// GetValidSignedPrekeys returns all non-expired signed prekeys.
// This is an alias for GetValidExchangeKeys using Signal Protocol terminology.
func (kp *KeyPair) GetValidSignedPrekeys() []SignedPrekey {
	return kp.GetValidExchangeKeys()
}

// RotateSignedPrekey generates a new signed prekey and marks the current one as deprecated.
// This is an alias for RotateExchangeKey using Signal Protocol terminology.
// In Signal, signed prekeys are typically rotated weekly or monthly.
func (kp *KeyPair) RotateSignedPrekey() error {
	return kp.RotateExchangeKey()
}

// PrekeyStatus is an alias for KeyStatus to match Signal Protocol terminology.
type PrekeyStatus = KeyStatus

const (
	// PrekeyStatusActive indicates the prekey is currently used for new sessions.
	PrekeyStatusActive = KeyStatusActive

	// PrekeyStatusDeprecated indicates the prekey is still accepted but not used for new sessions.
	PrekeyStatusDeprecated = KeyStatusDeprecated

	// PrekeyStatusExpired indicates the prekey is no longer accepted.
	PrekeyStatusExpired = KeyStatusExpired
)

// PrekeyRotationPolicy is an alias for KeyRotationPolicy to match Signal Protocol terminology.
type PrekeyRotationPolicy = KeyRotationPolicy

// DefaultPrekeyRotationPolicy returns a sensible default prekey rotation policy.
// This is an alias for DefaultRotationPolicy using Signal Protocol terminology.
func DefaultPrekeyRotationPolicy() *PrekeyRotationPolicy {
	return DefaultRotationPolicy()
}
