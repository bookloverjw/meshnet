// Package crypto provides WireGuard-compatible key generation and management.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

const KeySize = 32

// Key represents a 32-byte Curve25519 key used by WireGuard.
type Key [KeySize]byte

// GeneratePrivateKey creates a new random Curve25519 private key.
func GeneratePrivateKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("generate private key: %w", err)
	}
	// Clamp per Curve25519 spec
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return k, nil
}

// PublicKey derives the Curve25519 public key from a private key.
func (k Key) PublicKey() Key {
	var pub, priv [KeySize]byte
	copy(priv[:], k[:])
	curve25519.ScalarBaseMult(&pub, &priv)
	return Key(pub)
}

// String returns the base64-encoded representation of the key.
func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// ParseKey decodes a base64-encoded key string.
func ParseKey(s string) (Key, error) {
	var k Key
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return k, fmt.Errorf("decode key: %w", err)
	}
	if len(b) != KeySize {
		return k, fmt.Errorf("invalid key length: got %d, want %d", len(b), KeySize)
	}
	copy(k[:], b)
	return k, nil
}

// IsZero returns true if the key is all zeros.
func (k Key) IsZero() bool {
	var zero Key
	return k == zero
}

// GeneratePreSharedKey creates a random 256-bit pre-shared key for additional
// symmetric encryption on top of the Curve25519 exchange.
func GeneratePreSharedKey() (Key, error) {
	var k Key
	if _, err := rand.Read(k[:]); err != nil {
		return k, fmt.Errorf("generate preshared key: %w", err)
	}
	return k, nil
}
