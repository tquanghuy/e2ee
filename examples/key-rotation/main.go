package main

import (
	"fmt"
	"log"
	"time"

	"github.com/tquanghuy/e2ee"
)

func main() {
	fmt.Println("=== E2EE Key Rotation Example ===")

	// 1. Generate initial keypairs for Alice and Bob
	fmt.Println("1. Generating initial keypairs...")
	alice, err := e2ee.Generate()
	if err != nil {
		log.Fatal(err)
	}
	bob, err := e2ee.Generate()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Alice: Identity key generated, Exchange key version %d\n", alice.ActiveExchangeVersion)
	fmt.Printf("   Bob: Identity key generated, Exchange key version %d\n\n", bob.ActiveExchangeVersion)

	// 2. Alice sends a message to Bob using his current key
	fmt.Println("2. Alice encrypts a message for Bob (version 1)...")
	message1 := []byte("Hello Bob! This is encrypted with your version 1 key.")
	ciphertext1, err := e2ee.EncryptWithVersion(message1, bob.ExchangePub, 1, alice.IdentityPriv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Message encrypted (size: %d bytes)\n\n", len(ciphertext1))

	// 3. Bob rotates his exchange key
	fmt.Println("3. Bob rotates his exchange key...")
	if err := bob.RotateExchangeKey(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Bob's active exchange key version: %d\n", bob.ActiveExchangeVersion)
	fmt.Printf("   Bob now has %d exchange key versions\n\n", len(bob.ExchangeKeys))

	// 4. Bob can still decrypt the old message
	fmt.Println("4. Bob decrypts the message encrypted with his old key...")
	plaintext1, err := e2ee.DecryptWithKeyPair(ciphertext1, bob, alice.IdentityPub)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Decrypted: %s\n\n", plaintext1)

	// 5. Alice sends a new message using Bob's new key
	fmt.Println("5. Alice encrypts a new message for Bob (version 2)...")
	message2 := []byte("This message uses your new version 2 key!")
	ciphertext2, err := e2ee.EncryptWithVersion(message2, bob.ExchangePub, 2, alice.IdentityPriv)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Message encrypted (size: %d bytes)\n\n", len(ciphertext2))

	// 6. Bob decrypts the new message
	fmt.Println("6. Bob decrypts the message encrypted with his new key...")
	plaintext2, err := e2ee.DecryptWithKeyPair(ciphertext2, bob, alice.IdentityPub)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Decrypted: %s\n\n", plaintext2)

	// 7. Demonstrate key rotation policy
	fmt.Println("7. Applying key rotation policy...")
	policy := e2ee.DefaultRotationPolicy()
	fmt.Printf("   Policy: Rotate every %v, deprecate after %v\n", policy.RotationInterval, policy.DeprecationPeriod)

	// Check if rotation is needed
	if bob.ShouldRotate(policy) {
		fmt.Println("   Key rotation needed (based on policy)")
	} else {
		fmt.Println("   No rotation needed yet")
	}

	// 8. Simulate aging keys and expiring them
	fmt.Println("\n8. Simulating key expiration...")
	// Manually set old key creation time to 40 days ago
	bob.ExchangeKeys[0].CreatedAt = time.Now().Add(-40 * 24 * time.Hour)

	// Expire old keys based on policy
	if err := bob.ExpireOldKeys(policy); err != nil {
		log.Fatal(err)
	}

	// Check status of keys
	for _, key := range bob.ExchangeKeys {
		fmt.Printf("   Version %d: %s\n", key.Version, key.Status)
	}

	// 9. Demonstrate versioned serialization
	fmt.Println("\n9. Saving Bob's keypair with multiple versions...")
	fmt.Printf("   Serializing %d exchange key versions\n", len(bob.ExchangeKeys))

	// Save to file
	if err := bob.Save("bob_versioned.pem"); err != nil {
		log.Fatal(err)
	}
	fmt.Println("   Saved to bob_versioned.pem")

	// 10. Load and verify
	fmt.Println("\n10. Loading Bob's keypair from file...")
	bobLoaded, err := e2ee.Load("bob_versioned.pem")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Loaded %d exchange key versions\n", len(bobLoaded.ExchangeKeys))
	fmt.Printf("   Active version: %d\n", bobLoaded.ActiveExchangeVersion)

	// 11. Demonstrate backward compatibility
	fmt.Println("\n11. Testing backward compatibility...")
	// Use legacy Encrypt function
	legacyMessage := []byte("This uses the legacy encryption format")
	legacyCiphertext, err := e2ee.Encrypt(legacyMessage, bob.ExchangePub, alice.IdentityPriv)
	if err != nil {
		log.Fatal(err)
	}

	// Decrypt with new DecryptWithKeyPair function
	legacyPlaintext, err := e2ee.DecryptWithKeyPair(legacyCiphertext, bob, alice.IdentityPub)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("   Legacy format decrypted successfully: %s\n", legacyPlaintext)

	// 12. Get valid keys
	fmt.Println("\n12. Checking valid (non-expired) keys...")
	validKeys := bob.GetValidExchangeKeys()
	fmt.Printf("   Bob has %d valid exchange keys\n", len(validKeys))
	for _, key := range validKeys {
		fmt.Printf("   - Version %d (%s)\n", key.Version, key.Status)
	}

	fmt.Println("\n=== Key Rotation Example Complete ===")
}
