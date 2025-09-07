package mnemonic

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/pbkdf2"
)

const (
	MinEntropyBits = 128
	MaxEntropyBits = 256
)

type Mnemonic struct {
	words      []string
	passphrase string
}

func NewMnemonic(entropyBits int) (*Mnemonic, error) {
	if entropyBits < MinEntropyBits || entropyBits > MaxEntropyBits {
		return nil, fmt.Errorf("entropy bits must be between %d and %d", MinEntropyBits, MaxEntropyBits)
	}

	if entropyBits%32 != 0 {
		return nil, fmt.Errorf("entropy bits must be a multiple of 32")
	}

	entropy, err := bip39.NewEntropy(entropyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic: %w", err)
	}

	return &Mnemonic{
		words: strings.Split(mnemonic, " "),
	}, nil
}

func FromWords(words string) (*Mnemonic, error) {
	words = strings.TrimSpace(words)
	if !bip39.IsMnemonicValid(words) {
		return nil, fmt.Errorf("invalid mnemonic phrase")
	}

	return &Mnemonic{
		words: strings.Split(words, " "),
	}, nil
}

func FromEntropy(entropy []byte) (*Mnemonic, error) {
	if len(entropy) < 16 || len(entropy) > 32 {
		return nil, fmt.Errorf("entropy must be between 16 and 32 bytes")
	}

	if len(entropy)%4 != 0 {
		return nil, fmt.Errorf("entropy length must be a multiple of 4")
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate mnemonic from entropy: %w", err)
	}

	return &Mnemonic{
		words: strings.Split(mnemonic, " "),
	}, nil
}

func (m *Mnemonic) Words() string {
	return strings.Join(m.words, " ")
}

func (m *Mnemonic) WordList() []string {
	result := make([]string, len(m.words))
	copy(result, m.words)
	return result
}

func (m *Mnemonic) WordCount() int {
	return len(m.words)
}

func (m *Mnemonic) SetPassphrase(passphrase string) {
	m.passphrase = passphrase
}

func (m *Mnemonic) Seed() []byte {
	return bip39.NewSeed(m.Words(), m.passphrase)
}

func (m *Mnemonic) SeedWithPassphrase(passphrase string) []byte {
	return bip39.NewSeed(m.Words(), passphrase)
}

func (m *Mnemonic) Entropy() ([]byte, error) {
	entropy, err := bip39.EntropyFromMnemonic(m.Words())
	if err != nil {
		return nil, fmt.Errorf("failed to get entropy from mnemonic: %w", err)
	}
	return entropy, nil
}

func (m *Mnemonic) Validate() error {
	if !bip39.IsMnemonicValid(m.Words()) {
		return fmt.Errorf("invalid mnemonic phrase")
	}
	return nil
}

func DeriveKey(mnemonic, passphrase string, iterations int) []byte {
	if iterations <= 0 {
		iterations = 2048
	}
	salt := "mnemonic" + passphrase
	return pbkdf2.Key([]byte(mnemonic), []byte(salt), iterations, 64, sha512.New)
}

func ChecksumMnemonic(mnemonic string) (string, error) {
	entropy, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return "", fmt.Errorf("invalid mnemonic: %w", err)
	}

	h := sha256.Sum256(entropy)
	return hex.EncodeToString(h[:4]), nil
}

func ValidateWordCount(count int) bool {
	validCounts := []int{12, 15, 18, 21, 24}
	for _, valid := range validCounts {
		if count == valid {
			return true
		}
	}
	return false
}

func EntropyBitsFromWordCount(wordCount int) (int, error) {
	switch wordCount {
	case 12:
		return 128, nil
	case 15:
		return 160, nil
	case 18:
		return 192, nil
	case 21:
		return 224, nil
	case 24:
		return 256, nil
	default:
		return 0, fmt.Errorf("invalid word count: %d", wordCount)
	}
}

func SecureCompareWords(a, b string) bool {
	aWords := strings.Fields(strings.TrimSpace(a))
	bWords := strings.Fields(strings.TrimSpace(b))

	if len(aWords) != len(bWords) {
		return false
	}

	match := true
	for i := range aWords {
		if aWords[i] != bWords[i] {
			match = false
		}
	}

	return match
}
