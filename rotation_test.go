package e2ee

import (
	"bytes"
	"testing"
	"time"
)

func TestRotateExchangeKey(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Initial state: should have version 1
	if kp.ActiveExchangeVersion != 1 {
		t.Errorf("Initial active version = %d, want 1", kp.ActiveExchangeVersion)
	}
	if len(kp.ExchangeKeys) != 1 {
		t.Errorf("Initial exchange keys count = %d, want 1", len(kp.ExchangeKeys))
	}

	// Rotate key
	if err := kp.RotateExchangeKey(); err != nil {
		t.Fatalf("RotateExchangeKey() error = %v", err)
	}

	// After rotation: should have version 2
	if kp.ActiveExchangeVersion != 2 {
		t.Errorf("After rotation active version = %d, want 2", kp.ActiveExchangeVersion)
	}
	if len(kp.ExchangeKeys) != 2 {
		t.Errorf("After rotation exchange keys count = %d, want 2", len(kp.ExchangeKeys))
	}

	// Old key should be deprecated
	oldKey, err := kp.GetExchangeKey(1)
	if err != nil {
		t.Fatalf("GetExchangeKey(1) error = %v", err)
	}
	if oldKey.Status != KeyStatusDeprecated {
		t.Errorf("Old key status = %v, want %v", oldKey.Status, KeyStatusDeprecated)
	}

	// New key should be active
	newKey, err := kp.GetExchangeKey(2)
	if err != nil {
		t.Fatalf("GetExchangeKey(2) error = %v", err)
	}
	if newKey.Status != KeyStatusActive {
		t.Errorf("New key status = %v, want %v", newKey.Status, KeyStatusActive)
	}
}

func TestMultipleRotations(t *testing.T) {
	kp, _ := Generate()

	// Rotate 5 times
	for i := 0; i < 5; i++ {
		if err := kp.RotateExchangeKey(); err != nil {
			t.Fatalf("Rotation %d failed: %v", i+1, err)
		}
	}

	// Should have 6 keys total (initial + 5 rotations)
	if len(kp.ExchangeKeys) != 6 {
		t.Errorf("After 5 rotations, exchange keys count = %d, want 6", len(kp.ExchangeKeys))
	}

	// Active version should be 6
	if kp.ActiveExchangeVersion != 6 {
		t.Errorf("After 5 rotations, active version = %d, want 6", kp.ActiveExchangeVersion)
	}

	// Only version 6 should be active
	activeCount := 0
	for _, key := range kp.ExchangeKeys {
		if key.Status == KeyStatusActive {
			activeCount++
			if key.Version != 6 {
				t.Errorf("Active key version = %d, want 6", key.Version)
			}
		}
	}
	if activeCount != 1 {
		t.Errorf("Active key count = %d, want 1", activeCount)
	}
}

func TestEncryptDecryptWithVersions(t *testing.T) {
	alice, _ := Generate()
	bob, _ := Generate()

	message := []byte("Hello with versioned keys!")

	// Encrypt with Bob's current key (version 1)
	ciphertext1, err := EncryptWithVersion(message, bob.ExchangePub, 1, alice.IdentityPriv)
	if err != nil {
		t.Fatalf("EncryptWithVersion() error = %v", err)
	}

	// Rotate Bob's key
	bob.RotateExchangeKey()

	// Bob should still be able to decrypt message encrypted with old key
	plaintext1, err := DecryptWithKeyPair(ciphertext1, bob, alice.IdentityPub)
	if err != nil {
		t.Fatalf("DecryptWithKeyPair() error = %v", err)
	}
	if !bytes.Equal(plaintext1, message) {
		t.Errorf("Decrypted message = %s, want %s", plaintext1, message)
	}

	// Encrypt with Bob's new key (version 2)
	ciphertext2, err := EncryptWithVersion(message, bob.ExchangePub, 2, alice.IdentityPriv)
	if err != nil {
		t.Fatalf("EncryptWithVersion() with version 2 error = %v", err)
	}

	// Bob should be able to decrypt message encrypted with new key
	plaintext2, err := DecryptWithKeyPair(ciphertext2, bob, alice.IdentityPub)
	if err != nil {
		t.Fatalf("DecryptWithKeyPair() for version 2 error = %v", err)
	}
	if !bytes.Equal(plaintext2, message) {
		t.Errorf("Decrypted message = %s, want %s", plaintext2, message)
	}
}

func TestExpiredKeyRejection(t *testing.T) {
	alice, _ := Generate()
	bob, _ := Generate()

	message := []byte("Test message")

	// Encrypt with Bob's current key
	ciphertext, err := EncryptWithVersion(message, bob.ExchangePub, 1, alice.IdentityPriv)
	if err != nil {
		t.Fatalf("EncryptWithVersion() error = %v", err)
	}

	// Manually expire Bob's key
	bob.ExchangeKeys[0].Status = KeyStatusExpired
	now := time.Now()
	bob.ExchangeKeys[0].ExpiresAt = &now

	// Decryption should fail
	_, err = DecryptWithKeyPair(ciphertext, bob, alice.IdentityPub)
	if err == nil {
		t.Error("DecryptWithKeyPair() should fail with expired key, got nil error")
	}
}

func TestKeyRotationPolicy(t *testing.T) {
	kp, _ := Generate()

	// Create keys with different ages
	for i := 0; i < 3; i++ {
		kp.RotateExchangeKey()
	}

	// Manually set creation times to simulate aging
	now := time.Now()
	kp.ExchangeKeys[0].CreatedAt = now.Add(-10 * 24 * time.Hour) // 10 days old
	kp.ExchangeKeys[1].CreatedAt = now.Add(-8 * 24 * time.Hour)  // 8 days old
	kp.ExchangeKeys[2].CreatedAt = now.Add(-5 * 24 * time.Hour)  // 5 days old

	// Mark first two as deprecated
	kp.ExchangeKeys[0].Status = KeyStatusDeprecated
	kp.ExchangeKeys[1].Status = KeyStatusDeprecated

	policy := &KeyRotationPolicy{
		DeprecationPeriod: 7 * 24 * time.Hour, // 7 days
		MaxActiveVersions: 3,
	}

	// Expire old keys
	if err := kp.ExpireOldKeys(policy); err != nil {
		t.Fatalf("ExpireOldKeys() error = %v", err)
	}

	// Both first and second keys should be expired (deprecated for > 7 days)
	if kp.ExchangeKeys[0].Status != KeyStatusExpired {
		t.Errorf("Key 0 status = %v, want %v", kp.ExchangeKeys[0].Status, KeyStatusExpired)
	}

	if kp.ExchangeKeys[1].Status != KeyStatusExpired {
		t.Errorf("Key 1 status = %v, want %v (deprecated for 8 days)", kp.ExchangeKeys[1].Status, KeyStatusExpired)
	}

	// Third key should still be deprecated (deprecated for < 7 days)
	if kp.ExchangeKeys[2].Status != KeyStatusDeprecated {
		t.Errorf("Key 2 status = %v, want %v", kp.ExchangeKeys[2].Status, KeyStatusDeprecated)
	}
}

func TestVersionedSerialization(t *testing.T) {
	kp, _ := Generate()

	// Rotate a few times
	kp.RotateExchangeKey()
	kp.RotateExchangeKey()

	// Serialize to versioned PEM
	pemData, err := kp.ToVersionedPEM()
	if err != nil {
		t.Fatalf("ToVersionedPEM() error = %v", err)
	}

	// Deserialize
	kp2, err := FromPEM(pemData)
	if err != nil {
		t.Fatalf("FromPEM() error = %v", err)
	}

	// Verify identity keys match
	if !kp.IdentityPub.Equal(kp2.IdentityPub) {
		t.Error("Identity public keys don't match after roundtrip")
	}

	// Verify active version matches
	if kp.ActiveExchangeVersion != kp2.ActiveExchangeVersion {
		t.Errorf("Active version = %d, want %d", kp2.ActiveExchangeVersion, kp.ActiveExchangeVersion)
	}

	// Verify number of exchange keys matches
	if len(kp.ExchangeKeys) != len(kp2.ExchangeKeys) {
		t.Errorf("Exchange keys count = %d, want %d", len(kp2.ExchangeKeys), len(kp.ExchangeKeys))
	}

	// Verify each key version exists
	for _, originalKey := range kp.ExchangeKeys {
		loadedKey, err := kp2.GetExchangeKey(originalKey.Version)
		if err != nil {
			t.Errorf("GetExchangeKey(%d) error = %v", originalKey.Version, err)
			continue
		}
		if loadedKey.Status != originalKey.Status {
			t.Errorf("Key %d status = %v, want %v", originalKey.Version, loadedKey.Status, originalKey.Status)
		}
	}
}

func TestBackwardCompatibility(t *testing.T) {
	// Generate a keypair and save it in legacy format
	kp, _ := Generate()
	legacyPEM, err := kp.ToPEM()
	if err != nil {
		t.Fatalf("ToPEM() error = %v", err)
	}

	// Load it back
	kp2, err := FromPEM(legacyPEM)
	if err != nil {
		t.Fatalf("FromPEM() error = %v", err)
	}

	// Should be migrated to version 1
	if kp2.ActiveExchangeVersion != 1 {
		t.Errorf("Migrated active version = %d, want 1", kp2.ActiveExchangeVersion)
	}
	if len(kp2.ExchangeKeys) != 1 {
		t.Errorf("Migrated exchange keys count = %d, want 1", len(kp2.ExchangeKeys))
	}

	// Keys should match
	if !kp.IdentityPub.Equal(kp2.IdentityPub) {
		t.Error("Identity keys don't match after migration")
	}
	if !kp.ExchangePub.Equal(kp2.ExchangePub) {
		t.Error("Exchange keys don't match after migration")
	}
}

func TestMigrationFromLegacy(t *testing.T) {
	alice, _ := Generate()
	bob, _ := Generate()

	message := []byte("Test backward compatibility")

	// Encrypt using legacy Encrypt function
	legacyCiphertext, err := Encrypt(message, bob.ExchangePub, alice.IdentityPriv)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Should be able to decrypt with DecryptWithKeyPair (auto-detects legacy format)
	plaintext, err := DecryptWithKeyPair(legacyCiphertext, bob, alice.IdentityPub)
	if err != nil {
		t.Fatalf("DecryptWithKeyPair() error = %v", err)
	}
	if !bytes.Equal(plaintext, message) {
		t.Errorf("Decrypted message = %s, want %s", plaintext, message)
	}

	// Legacy ciphertext should not be detected as versioned
	if IsVersionedCiphertext(legacyCiphertext) {
		t.Error("Legacy ciphertext incorrectly detected as versioned")
	}
}

func TestShouldRotate(t *testing.T) {
	kp, _ := Generate()

	policy := &KeyRotationPolicy{
		RotationInterval: 24 * time.Hour, // 1 day
	}

	// Newly generated key should not need rotation
	if kp.ShouldRotate(policy) {
		t.Error("Newly generated key should not need rotation")
	}

	// Manually set creation time to 2 days ago
	kp.ExchangeKeys[0].CreatedAt = time.Now().Add(-48 * time.Hour)

	// Should need rotation now
	if !kp.ShouldRotate(policy) {
		t.Error("Key older than rotation interval should need rotation")
	}
}

func TestPruneExpiredKeys(t *testing.T) {
	kp, _ := Generate()

	// Create multiple keys
	for i := 0; i < 4; i++ {
		kp.RotateExchangeKey()
	}

	// Expire first two keys
	now := time.Now()
	kp.ExchangeKeys[0].Status = KeyStatusExpired
	kp.ExchangeKeys[0].ExpiresAt = &now
	kp.ExchangeKeys[1].Status = KeyStatusExpired
	kp.ExchangeKeys[1].ExpiresAt = &now

	initialCount := len(kp.ExchangeKeys)

	// Prune expired keys
	if err := kp.PruneExpiredKeys(); err != nil {
		t.Fatalf("PruneExpiredKeys() error = %v", err)
	}

	// Should have 2 fewer keys
	if len(kp.ExchangeKeys) != initialCount-2 {
		t.Errorf("After pruning, key count = %d, want %d", len(kp.ExchangeKeys), initialCount-2)
	}

	// No expired keys should remain
	for _, key := range kp.ExchangeKeys {
		if key.Status == KeyStatusExpired {
			t.Error("Found expired key after pruning")
		}
	}
}

func TestGetValidExchangeKeys(t *testing.T) {
	kp, _ := Generate()

	// Create multiple keys
	for i := 0; i < 3; i++ {
		kp.RotateExchangeKey()
	}

	// Expire one key
	now := time.Now()
	kp.ExchangeKeys[0].Status = KeyStatusExpired
	kp.ExchangeKeys[0].ExpiresAt = &now

	// Get valid keys
	validKeys := kp.GetValidExchangeKeys()

	// Should have 3 valid keys (4 total - 1 expired)
	if len(validKeys) != 3 {
		t.Errorf("Valid keys count = %d, want 3", len(validKeys))
	}

	// None should be expired
	for _, key := range validKeys {
		if key.Status == KeyStatusExpired {
			t.Error("GetValidExchangeKeys() returned expired key")
		}
	}
}
