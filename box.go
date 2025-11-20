package e2ee

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Encrypt encrypts a message for a recipient using X25519 key exchange and ChaCha20-Poly1305.
// It also signs the message with the sender's Identity Key to ensure authenticity.
// Format: [EphemeralPublicKey (32)] [Nonce (24)] [Signature (64)] [Ciphertext]
func Encrypt(message []byte, recipientExchangePub *ecdh.PublicKey, senderIdentityPriv ed25519.PrivateKey) ([]byte, error) {
	// 1. Sign the message first (Sign-then-Encrypt is generally safer if encrypting the signature,
	// but here we will Encrypt-then-Sign or Sign-then-Encrypt?
	// Standard Signal: X3DH gives shared secret. Double Ratchet encrypts.
	// Simple Box: Ephemeral Key Exchange -> Shared Secret -> AEAD.
	// To authenticate sender: Sign the plaintext? Or Sign the ciphertext?
	// If we sign plaintext, we encrypt (msg + sig).
	// Let's do: Ciphertext = AEAD(SharedSecret, Nonce, Message)
	// Output = EphemeralPub || Nonce || Signature(IdentityKey, Ciphertext) || Ciphertext
	// This authenticates that the sender (IdentityKey) sent this specific ciphertext.

	// Wait, standard "crypto_box" in NaCl authenticates via the shared secret (SenderPriv + RecipientPub).
	// But here we use Ephemeral keys for forward secrecy, so the recipient doesn't know who sent it just from ECDH.
	// So we MUST sign it.

	// Let's sign the PLAINTEXT.
	// Payload = Message
	// Signature = Sign(IdentityPriv, Payload)
	// SecuredData = Payload || Signature
	// Ciphertext = AEAD(SharedSecret, Nonce, SecuredData)

	// This ensures confidentiality of the signature (identity protection) and integrity.

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

	// Pack the result
	ephemeralPubBytes := ephemeralPub.Bytes()
	result := make([]byte, 0, len(ephemeralPubBytes)+len(nonce)+len(ciphertext))
	result = append(result, ephemeralPubBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// Decrypt decrypts a message from a sender and verifies the signature.
func Decrypt(packedCiphertext []byte, myExchangePriv *ecdh.PrivateKey, senderIdentityPub ed25519.PublicKey) ([]byte, error) {
	curve := ecdh.X25519()
	pubKeySize := 32
	nonceSize := chacha20poly1305.NonceSizeX
	signatureSize := ed25519.SignatureSize

	if len(packedCiphertext) < pubKeySize+nonceSize+signatureSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract components
	ephemeralPubBytes := packedCiphertext[:pubKeySize]
	nonce := packedCiphertext[pubKeySize : pubKeySize+nonceSize]
	ciphertext := packedCiphertext[pubKeySize+nonceSize:]

	// Reconstruct ephemeral public key
	ephemeralPub, err := curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral public key: %w", err)
	}

	// Derive shared secret
	sharedSecret, err := myExchangePriv.ECDH(ephemeralPub)
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

// Sign signs a message using Ed25519.
func Sign(message []byte, privKey ed25519.PrivateKey) []byte {
	return ed25519.Sign(privKey, message)
}

// Verify verifies a signature using Ed25519.
func Verify(message, signature []byte, pubKey ed25519.PublicKey) bool {
	return ed25519.Verify(pubKey, message, signature)
}
