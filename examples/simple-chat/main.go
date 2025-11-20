package main

import (
	"fmt"
	"log"

	"github.com/tquanghuy/e2ee"
)

func main() {
	fmt.Println("--- E2EE Demo ---")

	// 1. Key Generation
	fmt.Println("\n[1] Generating Keys...")
	alice, err := e2ee.Generate()
	if err != nil {
		log.Fatalf("Failed to generate Alice's keys: %v", err)
	}
	bob, err := e2ee.Generate()
	if err != nil {
		log.Fatalf("Failed to generate Bob's keys: %v", err)
	}
	fmt.Println("Alice and Bob have generated their keypairs.")

	// 2. Encryption/Decryption
	fmt.Println("\n[2] Testing Authenticated Encryption...")
	msg := "Hello Bob, secure message from Alice!"
	fmt.Printf("Original Message: %s\n", msg)

	// Alice encrypts for Bob, signing with her Identity Key
	ciphertext, err := e2ee.Encrypt([]byte(msg), bob.ExchangePub, alice.IdentityPriv)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Ciphertext length: %d bytes\n", len(ciphertext))

	// Bob decrypts, verifying it came from Alice
	decrypted, err := e2ee.Decrypt(ciphertext, bob.ExchangePriv, alice.IdentityPub)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted Message: %s\n", string(decrypted))

	if string(decrypted) != msg {
		log.Fatalf("Decryption mismatch!")
	}

	// 3. Signing/Verification (Manual)
	fmt.Println("\n[3] Testing Manual Signing/Verification...")
	signMsg := "This is a signed document."
	signature := e2ee.Sign([]byte(signMsg), alice.IdentityPriv)
	fmt.Printf("Signature generated. Length: %d bytes\n", len(signature))

	valid := e2ee.Verify([]byte(signMsg), signature, alice.IdentityPub)
	fmt.Printf("Signature Valid? %v\n", valid)

	if !valid {
		log.Fatalf("Signature verification failed!")
	}

	// 4. Tamper Test
	fmt.Println("\n[4] Testing Tamper Resistance...")
	ciphertext[len(ciphertext)-1] ^= 0xFF // Flip last bit
	_, err = e2ee.Decrypt(ciphertext, bob.ExchangePriv, alice.IdentityPub)
	if err == nil {
		log.Fatalf("Decryption succeeded on tampered ciphertext! (Should fail)")
	} else {
		fmt.Printf("Decryption correctly failed on tampered ciphertext: %v\n", err)
	}

	fmt.Println("\n--- Demo Completed Successfully ---")
}
