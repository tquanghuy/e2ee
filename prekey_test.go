package e2ee

import (
	"testing"
)

func TestCreatePrekeyBundle(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	bundle, err := kp.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("CreatePrekeyBundle() error = %v", err)
	}

	// Verify bundle structure
	if bundle == nil {
		t.Fatal("CreatePrekeyBundle() returned nil bundle")
	}

	if !bundle.IdentityKey.Equal(kp.IdentityPub) {
		t.Error("Bundle identity key doesn't match keypair")
	}

	if bundle.SignedPrekey == nil {
		t.Fatal("Bundle signed prekey is nil")
	}

	if bundle.SignedPrekey.KeyID != 1 {
		t.Errorf("Bundle signed prekey ID = %d, want 1", bundle.SignedPrekey.KeyID)
	}

	if len(bundle.PrekeySignature) == 0 {
		t.Error("Bundle prekey signature is empty")
	}
}

func TestVerifyPrekeyBundle(t *testing.T) {
	kp, _ := Generate()
	bundle, _ := kp.CreatePrekeyBundle()

	// Valid bundle should verify
	err := VerifyPrekeyBundle(bundle)
	if err != nil {
		t.Errorf("VerifyPrekeyBundle() error = %v, want nil", err)
	}

	// Corrupt signature should fail
	bundle.PrekeySignature[0] ^= 0xFF
	err = VerifyPrekeyBundle(bundle)
	if err == nil {
		t.Error("VerifyPrekeyBundle() should fail with corrupted signature")
	}
}

func TestPrekeyBundleAfterRotation(t *testing.T) {
	kp, _ := Generate()

	// Create initial bundle
	bundle1, _ := kp.CreatePrekeyBundle()

	// Rotate prekey
	kp.RotateSignedPrekey()

	// Create new bundle
	bundle2, _ := kp.CreatePrekeyBundle()

	// Bundles should have different prekey IDs
	if bundle1.SignedPrekey.KeyID == bundle2.SignedPrekey.KeyID {
		t.Error("Bundles after rotation should have different prekey IDs")
	}

	// Both should verify
	if err := VerifyPrekeyBundle(bundle1); err != nil {
		t.Errorf("Original bundle verification failed: %v", err)
	}

	if err := VerifyPrekeyBundle(bundle2); err != nil {
		t.Errorf("New bundle verification failed: %v", err)
	}

	// New bundle should have higher ID
	if bundle2.SignedPrekey.KeyID <= bundle1.SignedPrekey.KeyID {
		t.Errorf("New bundle ID %d should be greater than old ID %d",
			bundle2.SignedPrekey.KeyID, bundle1.SignedPrekey.KeyID)
	}
}

func TestSignalProtocolAliases(t *testing.T) {
	kp, _ := Generate()

	// Test GetActiveSignedPrekey alias
	activePrekey := kp.GetActiveSignedPrekey()
	if activePrekey == nil {
		t.Error("GetActiveSignedPrekey() returned nil")
	}

	// Test GetSignedPrekey alias
	prekey, err := kp.GetSignedPrekey(1)
	if err != nil {
		t.Errorf("GetSignedPrekey(1) error = %v", err)
	}
	if prekey == nil {
		t.Error("GetSignedPrekey(1) returned nil")
	}

	// Test GetValidSignedPrekeys alias
	validPrekeys := kp.GetValidSignedPrekeys()
	if len(validPrekeys) != 1 {
		t.Errorf("GetValidSignedPrekeys() count = %d, want 1", len(validPrekeys))
	}

	// Test RotateSignedPrekey alias
	err = kp.RotateSignedPrekey()
	if err != nil {
		t.Errorf("RotateSignedPrekey() error = %v", err)
	}

	// Should now have 2 prekeys
	validPrekeys = kp.GetValidSignedPrekeys()
	if len(validPrekeys) != 2 {
		t.Errorf("After rotation, GetValidSignedPrekeys() count = %d, want 2", len(validPrekeys))
	}
}

func TestPrekeyStatusConstants(t *testing.T) {
	// Verify that prekey status constants match key status constants
	if PrekeyStatusActive != KeyStatusActive {
		t.Error("PrekeyStatusActive should equal KeyStatusActive")
	}

	if PrekeyStatusDeprecated != KeyStatusDeprecated {
		t.Error("PrekeyStatusDeprecated should equal KeyStatusDeprecated")
	}

	if PrekeyStatusExpired != KeyStatusExpired {
		t.Error("PrekeyStatusExpired should equal KeyStatusExpired")
	}
}

func TestDefaultPrekeyRotationPolicy(t *testing.T) {
	policy := DefaultPrekeyRotationPolicy()
	if policy == nil {
		t.Fatal("DefaultPrekeyRotationPolicy() returned nil")
	}

	// Should match DefaultRotationPolicy
	defaultPolicy := DefaultRotationPolicy()
	if policy.RotationInterval != defaultPolicy.RotationInterval {
		t.Error("Prekey policy rotation interval doesn't match default")
	}

	if policy.DeprecationPeriod != defaultPolicy.DeprecationPeriod {
		t.Error("Prekey policy deprecation period doesn't match default")
	}

	if policy.MaxActiveVersions != defaultPolicy.MaxActiveVersions {
		t.Error("Prekey policy max versions doesn't match default")
	}
}

func TestPrekeyBundleWithMultipleRotations(t *testing.T) {
	kp, _ := Generate()

	// Rotate multiple times
	for i := 0; i < 3; i++ {
		kp.RotateSignedPrekey()
	}

	// Create bundle - should use latest prekey
	bundle, err := kp.CreatePrekeyBundle()
	if err != nil {
		t.Fatalf("CreatePrekeyBundle() error = %v", err)
	}

	// Should have the latest prekey ID (4 = initial + 3 rotations)
	if bundle.SignedPrekey.KeyID != 4 {
		t.Errorf("Bundle prekey ID = %d, want 4", bundle.SignedPrekey.KeyID)
	}

	// Verify bundle
	if err := VerifyPrekeyBundle(bundle); err != nil {
		t.Errorf("VerifyPrekeyBundle() error = %v", err)
	}
}
