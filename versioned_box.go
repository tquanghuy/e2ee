package e2ee

// This file contains additional encryption/decryption functions that support key versioning.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// EncryptWithVersion encrypts a message for a recipient using a specific key version.
// This allows encrypting with older key versions for backward compatibility.
// Format: [Version (4)] [EphemeralPublicKey (32)] [Nonce (24)] [Ciphertext]
func EncryptWithVersion(message []byte, recipientExchangePub *ecdh.PublicKey, recipientKeyVersion uint32, senderIdentityPriv ed25519.PrivateKey) ([]byte, error) {
	// Sign the message
	signature := ed25519.Sign(senderIdentityPriv, message)
	securedData := make([]byte, 0, len(message)+len(signature))
	securedData = append(securedData, message...)
	securedData = append(securedData, signature...)

	// Generate ephemeral sender key
	ephemeralCurve := ecdh.X25519()
	ephemeralPriv, err := ephemeralCurve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	ephemeralPub := ephemeralPriv.PublicKey()

	// Derive shared secret
	sharedSecret, err := ephemeralPriv.ECDH(recipientExchangePub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Use the shared secret to create a AEAD cipher
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, securedData, nil)

	// Pack the result with version prefix
	ephemeralPubBytes := ephemeralPub.Bytes()
	result := make([]byte, 4+len(ephemeralPubBytes)+len(nonce)+len(ciphertext))

	// Write version (4 bytes, big endian)
	binary.BigEndian.PutUint32(result[0:4], recipientKeyVersion)

	// Write ephemeral public key
	copy(result[4:], ephemeralPubBytes)

	// Write nonce
	copy(result[4+len(ephemeralPubBytes):], nonce)

	// Write ciphertext
	copy(result[4+len(ephemeralPubBytes)+len(nonce):], ciphertext)

	return result, nil
}

// DecryptWithKeyPair decrypts a message using a KeyPair that may contain multiple key versions.
// It automatically detects the key version from the ciphertext and uses the appropriate key.
func DecryptWithKeyPair(packedCiphertext []byte, recipient *KeyPair, senderIdentityPub ed25519.PublicKey) ([]byte, error) {
	// Check if this is a versioned ciphertext
	if IsVersionedCiphertext(packedCiphertext) {
		// Extract version
		version, err := ExtractKeyVersion(packedCiphertext)
		if err != nil {
			return nil, err
		}

		// Get the appropriate exchange key
		versionedKey, err := recipient.GetExchangeKey(version)
		if err != nil {
			return nil, fmt.Errorf("key version %d not found: %w", version, err)
		}

		// Check if key is valid (not expired)
		if !versionedKey.IsValid() {
			return nil, fmt.Errorf("key version %d is expired or invalid", version)
		}

		// Decrypt using the versioned format
		return decryptVersioned(packedCiphertext, versionedKey.Key, senderIdentityPub)
	}

	// Legacy format - use the active exchange key
	return Decrypt(packedCiphertext, recipient.ExchangePriv, senderIdentityPub)
}

// decryptVersioned decrypts a versioned ciphertext.
func decryptVersioned(packedCiphertext []byte, exchangePriv *ecdh.PrivateKey, senderIdentityPub ed25519.PublicKey) ([]byte, error) {
	curve := ecdh.X25519()
	pubKeySize := 32
	nonceSize := chacha20poly1305.NonceSizeX
	signatureSize := ed25519.SignatureSize
	versionSize := 4

	if len(packedCiphertext) < versionSize+pubKeySize+nonceSize+signatureSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract components (skip version, already extracted)
	ephemeralPubBytes := packedCiphertext[versionSize : versionSize+pubKeySize]
	nonce := packedCiphertext[versionSize+pubKeySize : versionSize+pubKeySize+nonceSize]
	ciphertext := packedCiphertext[versionSize+pubKeySize+nonceSize:]

	// Reconstruct ephemeral public key
	ephemeralPub, err := curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Derive shared secret
	sharedSecret, err := exchangePriv.ECDH(ephemeralPub)
	if err != nil {
		return nil, fmt.Errorf("failed to derive shared secret: %w", err)
	}

	// Create AEAD
	aead, err := chacha20poly1305.NewX(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	// Decrypt
	plaintextWithSig, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Split message and signature
	if len(plaintextWithSig) < signatureSize {
		return nil, errors.New("decrypted data too short to contain signature")
	}

	msgLen := len(plaintextWithSig) - signatureSize
	message := plaintextWithSig[:msgLen]
	signature := plaintextWithSig[msgLen:]

	// Verify Signature
	if !ed25519.Verify(senderIdentityPub, message, signature) {
		return nil, errors.New("signature verification failed")
	}

	return message, nil
}

// ExtractKeyVersion extracts the key version from a versioned ciphertext.
// Returns an error if the ciphertext is not versioned or is too short.
func ExtractKeyVersion(ciphertext []byte) (uint32, error) {
	if len(ciphertext) < 4 {
		return 0, errors.New("ciphertext too short to contain version")
	}
	version := binary.BigEndian.Uint32(ciphertext[0:4])
	return version, nil
}

// IsVersionedCiphertext checks if a ciphertext includes a version prefix.
// This is a heuristic check: if the ciphertext is long enough and starts with
// a reasonable version number (1-1000), we assume it's versioned.
func IsVersionedCiphertext(ciphertext []byte) bool {
	if len(ciphertext) < 4 {
		return false
	}

	// Extract potential version
	version := binary.BigEndian.Uint32(ciphertext[0:4])

	// Heuristic: version should be between 1 and 1000 for versioned ciphertexts
	// Legacy ciphertexts start with 32-byte ephemeral public key, which when
	// interpreted as uint32 is very unlikely to be in this range
	return version >= 1 && version <= 1000
}
