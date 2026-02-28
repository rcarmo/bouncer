// Package token generates cryptographically random 6-digit enrollment tokens.
package token

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Generate returns a random 6-digit token string (000000–999999).
func Generate() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", fmt.Errorf("token: generate: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
