package e2ee

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"time"
)

// ToVersionedPEM encodes the keypair with all versioned exchange keys to a PEM block.
// This format supports multiple key versions for key rotation.
// Format: IdentityPriv (64) || ActiveVersion (4) || NumKeys (4) || [Version (4) || CreatedAt (8) || ExpiresAt (8) || Status (1) || Key (32)]...
func (kp *KeyPair) ToVersionedPEM() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write identity private key
	buf.Write(kp.IdentityPriv)

	// Write active version
	if err := binary.Write(buf, binary.BigEndian, kp.ActiveExchangeVersion); err != nil {
		return nil, fmt.Errorf("failed to write active version: %w", err)
	}

	// Write number of exchange keys
	numKeys := uint32(len(kp.ExchangeKeys))
	if err := binary.Write(buf, binary.BigEndian, numKeys); err != nil {
		return nil, fmt.Errorf("failed to write number of keys: %w", err)
	}

	// Write each versioned exchange key
	for _, vk := range kp.ExchangeKeys {
		// Version
		if err := binary.Write(buf, binary.BigEndian, vk.Version); err != nil {
			return nil, fmt.Errorf("failed to write key version: %w", err)
		}

		// CreatedAt (Unix timestamp in seconds)
		createdAtUnix := vk.CreatedAt.Unix()
		if err := binary.Write(buf, binary.BigEndian, createdAtUnix); err != nil {
			return nil, fmt.Errorf("failed to write created timestamp: %w", err)
		}

		// ExpiresAt (Unix timestamp in seconds, 0 if nil)
		var expiresAtUnix int64
		if vk.ExpiresAt != nil {
			expiresAtUnix = vk.ExpiresAt.Unix()
		}
		if err := binary.Write(buf, binary.BigEndian, expiresAtUnix); err != nil {
			return nil, fmt.Errorf("failed to write expires timestamp: %w", err)
		}

		// Status
		if err := binary.Write(buf, binary.BigEndian, uint8(vk.Status)); err != nil {
			return nil, fmt.Errorf("failed to write key status: %w", err)
		}

		// Key bytes
		keyBytes := vk.Key.Bytes()
		buf.Write(keyBytes)
	}

	block := &pem.Block{
		Type:  "E2EE VERSIONED PRIVATE KEY",
		Bytes: buf.Bytes(),
	}

	return pem.EncodeToMemory(block), nil
}

// fromVersionedPEM decodes a versioned keypair from a PEM block.
func fromVersionedPEM(block *pem.Block) (*KeyPair, error) {
	data := block.Bytes
	buf := bytes.NewReader(data)

	// Read identity private key (64 bytes)
	identityPriv := make([]byte, 64)
	if _, err := buf.Read(identityPriv); err != nil {
		return nil, fmt.Errorf("failed to read identity private key: %w", err)
	}
	identityPub := identityPriv[32:] // Ed25519 public key is second half

	// Read active version
	var activeVersion uint32
	if err := binary.Read(buf, binary.BigEndian, &activeVersion); err != nil {
		return nil, fmt.Errorf("failed to read active version: %w", err)
	}

	// Read number of keys
	var numKeys uint32
	if err := binary.Read(buf, binary.BigEndian, &numKeys); err != nil {
		return nil, fmt.Errorf("failed to read number of keys: %w", err)
	}

	// Read each versioned exchange key
	exchangeKeys := make([]VersionedExchangeKey, 0, numKeys)
	curve := ecdh.X25519()

	for i := uint32(0); i < numKeys; i++ {
		var version uint32
		if err := binary.Read(buf, binary.BigEndian, &version); err != nil {
			return nil, fmt.Errorf("failed to read key version: %w", err)
		}

		var createdAtUnix int64
		if err := binary.Read(buf, binary.BigEndian, &createdAtUnix); err != nil {
			return nil, fmt.Errorf("failed to read created timestamp: %w", err)
		}

		var expiresAtUnix int64
		if err := binary.Read(buf, binary.BigEndian, &expiresAtUnix); err != nil {
			return nil, fmt.Errorf("failed to read expires timestamp: %w", err)
		}

		var statusByte uint8
		if err := binary.Read(buf, binary.BigEndian, &statusByte); err != nil {
			return nil, fmt.Errorf("failed to read key status: %w", err)
		}

		keyBytes := make([]byte, 32)
		if _, err := buf.Read(keyBytes); err != nil {
			return nil, fmt.Errorf("failed to read key bytes: %w", err)
		}

		privKey, err := curve.NewPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid exchange private key: %w", err)
		}

		vk := VersionedExchangeKey{
			Version:   version,
			Key:       privKey,
			PublicKey: privKey.PublicKey(),
			CreatedAt: time.Unix(createdAtUnix, 0),
			Status:    KeyStatus(statusByte),
		}

		if expiresAtUnix > 0 {
			expiresAt := time.Unix(expiresAtUnix, 0)
			vk.ExpiresAt = &expiresAt
		}

		exchangeKeys = append(exchangeKeys, vk)
	}

	// Find active exchange key
	var activeExchangePriv *ecdh.PrivateKey
	var activeExchangePub *ecdh.PublicKey
	for i := range exchangeKeys {
		if exchangeKeys[i].Version == activeVersion {
			activeExchangePriv = exchangeKeys[i].Key
			activeExchangePub = exchangeKeys[i].PublicKey
			break
		}
	}

	if activeExchangePriv == nil {
		return nil, fmt.Errorf("active exchange key version %d not found", activeVersion)
	}

	return &KeyPair{
		IdentityPriv:          identityPriv,
		IdentityPub:           identityPub,
		ExchangePriv:          activeExchangePriv,
		ExchangePub:           activeExchangePub,
		ExchangeKeys:          exchangeKeys,
		ActiveExchangeVersion: activeVersion,
	}, nil
}
