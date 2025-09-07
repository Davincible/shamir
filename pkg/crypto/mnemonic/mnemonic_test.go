package mnemonic

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tyler-smith/go-bip39"
)

func TestNewMnemonic(t *testing.T) {
	tests := []struct {
		name        string
		entropyBits int
		wantWords   int
		wantError   bool
	}{
		{"128 bits (12 words)", 128, 12, false},
		{"160 bits (15 words)", 160, 15, false},
		{"192 bits (18 words)", 192, 18, false},
		{"224 bits (21 words)", 224, 21, false},
		{"256 bits (24 words)", 256, 24, false},
		{"Invalid: 64 bits", 64, 0, true},
		{"Invalid: 512 bits", 512, 0, true},
		{"Invalid: 129 bits", 129, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMnemonic(tt.entropyBits)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, m)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, m)
				assert.Equal(t, tt.wantWords, m.WordCount())
				assert.True(t, bip39.IsMnemonicValid(m.Words()))
			}
		})
	}
}

func TestFromWords(t *testing.T) {
	validMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	m, err := FromWords(validMnemonic)
	require.NoError(t, err)
	assert.Equal(t, 12, m.WordCount())
	assert.Equal(t, validMnemonic, m.Words())

	invalidMnemonic := "invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid"
	_, err = FromWords(invalidMnemonic)
	assert.Error(t, err)
}

func TestFromEntropy(t *testing.T) {
	tests := []struct {
		name      string
		entropy   []byte
		wantError bool
	}{
		{"16 bytes", make([]byte, 16), false},
		{"20 bytes", make([]byte, 20), false},
		{"24 bytes", make([]byte, 24), false},
		{"28 bytes", make([]byte, 28), false},
		{"32 bytes", make([]byte, 32), false},
		{"Invalid: 15 bytes", make([]byte, 15), true},
		{"Invalid: 33 bytes", make([]byte, 33), true},
		{"Invalid: 18 bytes", make([]byte, 18), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := FromEntropy(tt.entropy)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, m)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, m)

				recoveredEntropy, err := m.Entropy()
				require.NoError(t, err)
				assert.Equal(t, tt.entropy, recoveredEntropy)
			}
		})
	}
}

func TestSeedGeneration(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	m, err := FromWords(mnemonic)
	require.NoError(t, err)

	seed := m.Seed()
	expectedSeed := bip39.NewSeed(mnemonic, "")
	assert.Equal(t, expectedSeed, seed)

	seedWithPassphrase := m.SeedWithPassphrase("TREZOR")
	expectedWithPassphrase := bip39.NewSeed(mnemonic, "TREZOR")
	assert.Equal(t, expectedWithPassphrase, seedWithPassphrase)

	m.SetPassphrase("test")
	seedWithSet := m.Seed()
	expectedWithSet := bip39.NewSeed(mnemonic, "test")
	assert.Equal(t, expectedWithSet, seedWithSet)
}

func TestValidateWordCount(t *testing.T) {
	tests := []struct {
		count int
		valid bool
	}{
		{12, true},
		{15, true},
		{18, true},
		{21, true},
		{24, true},
		{11, false},
		{13, false},
		{25, false},
		{0, false},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.count)), func(t *testing.T) {
			assert.Equal(t, tt.valid, ValidateWordCount(tt.count))
		})
	}
}

func TestEntropyBitsFromWordCount(t *testing.T) {
	tests := []struct {
		wordCount int
		wantBits  int
		wantError bool
	}{
		{12, 128, false},
		{15, 160, false},
		{18, 192, false},
		{21, 224, false},
		{24, 256, false},
		{13, 0, true},
		{0, 0, true},
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.wordCount)), func(t *testing.T) {
			bits, err := EntropyBitsFromWordCount(tt.wordCount)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantBits, bits)
			}
		})
	}
}

func TestDeriveKey(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	passphrase := "TREZOR"

	key1 := DeriveKey(mnemonic, passphrase, 2048)
	assert.Len(t, key1, 64)

	key2 := DeriveKey(mnemonic, passphrase, 2048)
	assert.Equal(t, key1, key2)

	key3 := DeriveKey(mnemonic, "different", 2048)
	assert.NotEqual(t, key1, key3)

	key4 := DeriveKey(mnemonic, passphrase, 0)
	assert.Equal(t, key1, key4)
}

func TestChecksumMnemonic(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	checksum, err := ChecksumMnemonic(mnemonic)
	require.NoError(t, err)
	assert.NotEmpty(t, checksum)
	assert.Len(t, checksum, 8)

	_, err = hex.DecodeString(checksum)
	assert.NoError(t, err)

	_, err = ChecksumMnemonic("invalid mnemonic phrase")
	assert.Error(t, err)
}

func TestSecureCompareWords(t *testing.T) {
	tests := []struct {
		name  string
		a     string
		b     string
		equal bool
	}{
		{
			"Equal mnemonics",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			true,
		},
		{
			"Different mnemonics",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon above",
			false,
		},
		{
			"Different word count",
			"abandon abandon abandon",
			"abandon abandon",
			false,
		},
		{
			"Extra spaces",
			"abandon  abandon",
			"abandon abandon",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.equal, SecureCompareWords(tt.a, tt.b))
		})
	}
}

func TestWordListImmutability(t *testing.T) {
	m, err := NewMnemonic(128)
	require.NoError(t, err)

	words := m.WordList()
	originalWords := make([]string, len(words))
	copy(originalWords, words)

	words[0] = "modified"

	assert.Equal(t, originalWords, m.WordList())
	assert.Equal(t, strings.Join(originalWords, " "), m.Words())
}

func BenchmarkNewMnemonic(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := NewMnemonic(256)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSeedGeneration(b *testing.B) {
	m, err := NewMnemonic(256)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.SeedWithPassphrase("passphrase")
	}
}
