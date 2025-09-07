package shamir

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/hashicorp/vault/shamir"
)

type Share struct {
	Index byte
	Data  []byte
}

type Config struct {
	Parts     int
	Threshold int
}

func (c *Config) Validate() error {
	if c.Parts < 2 {
		return fmt.Errorf("parts must be at least 2, got %d", c.Parts)
	}
	if c.Threshold < 2 {
		return fmt.Errorf("threshold must be at least 2, got %d", c.Threshold)
	}
	if c.Threshold > c.Parts {
		return fmt.Errorf("threshold (%d) cannot be greater than parts (%d)", c.Threshold, c.Parts)
	}
	if c.Parts > 255 {
		return fmt.Errorf("parts cannot exceed 255, got %d", c.Parts)
	}
	return nil
}

func Split(secret []byte, config Config) ([]Share, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	if len(secret) == 0 {
		return nil, fmt.Errorf("secret cannot be empty")
	}

	shares, err := shamir.Split(secret, config.Parts, config.Threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}

	result := make([]Share, len(shares))
	for i, share := range shares {
		result[i] = Share{
			Index: byte(i + 1),
			Data:  share,
		}
	}

	return result, nil
}

func Combine(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, fmt.Errorf("at least 2 shares are required for reconstruction")
	}

	shareBytes := make([][]byte, len(shares))
	for i, share := range shares {
		if len(share.Data) == 0 {
			return nil, fmt.Errorf("share %d has empty data", share.Index)
		}
		shareBytes[i] = share.Data
	}

	secret, err := shamir.Combine(shareBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	return secret, nil
}

func VerifyShare(share Share, expectedLen int) error {
	if len(share.Data) != expectedLen {
		return fmt.Errorf("invalid share length: expected %d, got %d", expectedLen, len(share.Data))
	}
	if share.Index == 0 {
		return fmt.Errorf("share index cannot be 0")
	}
	return nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid length: %d", n)
	}

	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return b, nil
}

func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func SecureZero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
