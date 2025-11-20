package e2ee

import (
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"time"
)

// KeyStatus represents the lifecycle state of a versioned key.
type KeyStatus int

const (
	// KeyStatusActive indicates the key is currently used for new encryptions.
	KeyStatusActive KeyStatus = iota
	// KeyStatusDeprecated indicates the key is still accepted for decryption but not used for new encryptions.
	KeyStatusDeprecated
	// KeyStatusExpired indicates the key is no longer accepted for any operations.
	KeyStatusExpired
)

// String returns a string representation of the KeyStatus.
func (s KeyStatus) String() string {
	switch s {
	case KeyStatusActive:
		return "active"
	case KeyStatusDeprecated:
		return "deprecated"
	case KeyStatusExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// VersionedExchangeKey wraps an exchange key with version metadata and lifecycle information.
type VersionedExchangeKey struct {
	Version   uint32           // Monotonically increasing version number
	Key       *ecdh.PrivateKey // The actual X25519 private key
	PublicKey *ecdh.PublicKey  // The corresponding public key
	CreatedAt time.Time        // Timestamp when key was created
	ExpiresAt *time.Time       // Optional expiration time
	Status    KeyStatus        // Current lifecycle status
}

// IsValid returns true if the key is in a valid state for decryption.
func (v *VersionedExchangeKey) IsValid() bool {
	if v.Status == KeyStatusExpired {
		return false
	}
	if v.ExpiresAt != nil && time.Now().After(*v.ExpiresAt) {
		return false
	}
	return true
}

// IsActive returns true if the key can be used for new encryptions.
func (v *VersionedExchangeKey) IsActive() bool {
	return v.Status == KeyStatusActive && v.IsValid()
}

// KeyRotationPolicy defines the configuration for automatic key rotation and expiration.
type KeyRotationPolicy struct {
	// RotationInterval specifies how often to rotate keys.
	// If zero, automatic rotation is disabled.
	RotationInterval time.Duration

	// DeprecationPeriod specifies how long to keep old keys as deprecated before expiring them.
	// If zero, keys are immediately expired when rotated.
	DeprecationPeriod time.Duration

	// MaxActiveVersions specifies the maximum number of active/deprecated keys to maintain.
	// Older keys beyond this limit will be expired.
	// If zero, no limit is enforced.
	MaxActiveVersions int
}

// DefaultRotationPolicy returns a sensible default rotation policy.
// Keys are rotated every 30 days, deprecated for 7 days, and up to 5 versions are kept.
func DefaultRotationPolicy() *KeyRotationPolicy {
	return &KeyRotationPolicy{
		RotationInterval:  30 * 24 * time.Hour, // 30 days
		DeprecationPeriod: 7 * 24 * time.Hour,  // 7 days
		MaxActiveVersions: 5,
	}
}

// RotateExchangeKey generates a new exchange key version and marks the current active key as deprecated.
// This method should be called on a KeyPair to rotate its exchange keys.
func (kp *KeyPair) RotateExchangeKey() error {
	// Mark current active key as deprecated
	for i := range kp.ExchangeKeys {
		if kp.ExchangeKeys[i].Status == KeyStatusActive {
			kp.ExchangeKeys[i].Status = KeyStatusDeprecated
		}
	}

	// Generate new exchange key
	curve := ecdh.X25519()
	newPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate new exchange key: %w", err)
	}

	// Determine new version number
	newVersion := kp.ActiveExchangeVersion + 1

	// Create versioned key
	newVersionedKey := VersionedExchangeKey{
		Version:   newVersion,
		Key:       newPriv,
		PublicKey: newPriv.PublicKey(),
		CreatedAt: time.Now(),
		ExpiresAt: nil,
		Status:    KeyStatusActive,
	}

	// Add to collection
	kp.ExchangeKeys = append(kp.ExchangeKeys, newVersionedKey)
	kp.ActiveExchangeVersion = newVersion

	// Update legacy fields for backward compatibility
	kp.ExchangePriv = newPriv
	kp.ExchangePub = newPriv.PublicKey()

	return nil
}

// GetExchangeKey retrieves a specific exchange key version.
func (kp *KeyPair) GetExchangeKey(version uint32) (*VersionedExchangeKey, error) {
	for i := range kp.ExchangeKeys {
		if kp.ExchangeKeys[i].Version == version {
			return &kp.ExchangeKeys[i], nil
		}
	}
	return nil, fmt.Errorf("exchange key version %d not found", version)
}

// GetActiveExchangeKey returns the current active exchange key.
func (kp *KeyPair) GetActiveExchangeKey() *VersionedExchangeKey {
	for i := range kp.ExchangeKeys {
		if kp.ExchangeKeys[i].Status == KeyStatusActive {
			return &kp.ExchangeKeys[i]
		}
	}
	return nil
}

// GetValidExchangeKeys returns all non-expired exchange keys.
func (kp *KeyPair) GetValidExchangeKeys() []VersionedExchangeKey {
	var valid []VersionedExchangeKey
	for _, key := range kp.ExchangeKeys {
		if key.IsValid() {
			valid = append(valid, key)
		}
	}
	return valid
}

// ExpireOldKeys marks old keys as expired based on the provided policy.
func (kp *KeyPair) ExpireOldKeys(policy *KeyRotationPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}

	now := time.Now()

	// Expire keys based on deprecation period
	if policy.DeprecationPeriod > 0 {
		for i := range kp.ExchangeKeys {
			if kp.ExchangeKeys[i].Status == KeyStatusDeprecated {
				deprecatedDuration := now.Sub(kp.ExchangeKeys[i].CreatedAt)
				if deprecatedDuration > policy.DeprecationPeriod {
					kp.ExchangeKeys[i].Status = KeyStatusExpired
					expiresAt := now
					kp.ExchangeKeys[i].ExpiresAt = &expiresAt
				}
			}
		}
	}

	// Enforce max active versions limit
	if policy.MaxActiveVersions > 0 {
		validKeys := kp.GetValidExchangeKeys()
		if len(validKeys) > policy.MaxActiveVersions {
			// Sort by version (oldest first) and expire excess
			excessCount := len(validKeys) - policy.MaxActiveVersions
			for i := 0; i < excessCount; i++ {
				// Find and expire the oldest valid key
				oldestVersion := uint32(^uint32(0)) // max uint32
				oldestIdx := -1
				for j := range kp.ExchangeKeys {
					if kp.ExchangeKeys[j].IsValid() && kp.ExchangeKeys[j].Version < oldestVersion {
						oldestVersion = kp.ExchangeKeys[j].Version
						oldestIdx = j
					}
				}
				if oldestIdx >= 0 {
					kp.ExchangeKeys[oldestIdx].Status = KeyStatusExpired
					expiresAt := now
					kp.ExchangeKeys[oldestIdx].ExpiresAt = &expiresAt
				}
			}
		}
	}

	return nil
}

// PruneExpiredKeys removes expired keys from the collection.
// This permanently deletes expired keys and cannot be undone.
func (kp *KeyPair) PruneExpiredKeys() error {
	var activeKeys []VersionedExchangeKey
	for _, key := range kp.ExchangeKeys {
		if key.Status != KeyStatusExpired {
			activeKeys = append(activeKeys, key)
		}
	}
	kp.ExchangeKeys = activeKeys
	return nil
}

// ShouldRotate checks if a key rotation is needed based on the policy.
func (kp *KeyPair) ShouldRotate(policy *KeyRotationPolicy) bool {
	if policy == nil || policy.RotationInterval == 0 {
		return false
	}

	activeKey := kp.GetActiveExchangeKey()
	if activeKey == nil {
		return true // No active key, should rotate
	}

	timeSinceCreation := time.Since(activeKey.CreatedAt)
	return timeSinceCreation >= policy.RotationInterval
}
