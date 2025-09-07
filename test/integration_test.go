package test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/Davincible/shamir/pkg/crypto/hdkey"
	"github.com/Davincible/shamir/pkg/crypto/mnemonic"
	"github.com/Davincible/shamir/pkg/crypto/shamir"
	"github.com/Davincible/shamir/pkg/secure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullWorkflow(t *testing.T) {
	m, err := mnemonic.NewMnemonic(256)
	require.NoError(t, err)

	originalMnemonic := m.Words()
	t.Logf("Generated mnemonic: %s", originalMnemonic)

	entropy, err := m.Entropy()
	require.NoError(t, err)
	defer secure.Zero(entropy)

	config := shamir.Config{
		Parts:     5,
		Threshold: 3,
	}
	shares, err := shamir.Split(entropy, config)
	require.NoError(t, err)
	assert.Len(t, shares, 5)

	reconstructed, err := shamir.Combine(shares[:3])
	require.NoError(t, err)
	assert.Equal(t, entropy, reconstructed)

	recoveredMnemonic, err := mnemonic.FromEntropy(reconstructed)
	require.NoError(t, err)
	assert.Equal(t, originalMnemonic, recoveredMnemonic.Words())

	seed := recoveredMnemonic.SeedWithPassphrase("test-passphrase")
	defer secure.Zero(seed)

	masterKey, err := hdkey.NewMasterKey(seed)
	require.NoError(t, err)

	derivedKey, err := masterKey.DerivePath("m/44'/60'/0'/0/0")
	require.NoError(t, err)

	assert.NotEmpty(t, derivedKey.PublicKeyHex())
	assert.NotEmpty(t, derivedKey.ExtendedPublicKey())

	t.Logf("Successfully derived public key: %s", derivedKey.PublicKeyHex())
}

func TestDifferentShareCombinations(t *testing.T) {
	secret := []byte("test secret for multiple combinations")
	config := shamir.Config{
		Parts:     7,
		Threshold: 4,
	}

	shares, err := shamir.Split(secret, config)
	require.NoError(t, err)

	combinations := [][]int{
		{0, 1, 2, 3},
		{3, 4, 5, 6},
		{0, 2, 4, 6},
		{1, 3, 5, 6},
		{0, 1, 5, 6},
	}

	for _, combo := range combinations {
		selectedShares := make([]shamir.Share, len(combo))
		for i, idx := range combo {
			selectedShares[i] = shares[idx]
		}

		reconstructed, err := shamir.Combine(selectedShares)
		require.NoError(t, err)
		assert.Equal(t, secret, reconstructed)
	}
}

func TestLedgerCompatibility(t *testing.T) {
	testMnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	m, err := mnemonic.FromWords(testMnemonic)
	require.NoError(t, err)

	seed := m.SeedWithPassphrase("")
	masterKey, err := hdkey.NewMasterKey(seed)
	require.NoError(t, err)

	ledgerPath := "m/44'/60'/0'/0/0"
	derivedKey, err := masterKey.DerivePath(ledgerPath)
	require.NoError(t, err)

	publicKey := derivedKey.PublicKeyHex()
	assert.NotEmpty(t, publicKey)

	t.Logf("Ledger-compatible public key at %s: %s", ledgerPath, publicKey)
}

func TestSecureMemoryHandling(t *testing.T) {
	sensitive := []byte("very sensitive data")
	original := make([]byte, len(sensitive))
	copy(original, sensitive)

	sb := secure.FromBytes(sensitive)
	defer sb.Destroy()

	retrieved := sb.Get()
	assert.Equal(t, original, retrieved)

	sb.Clear()
	cleared := sb.Get()
	assert.NotEqual(t, original, cleared)
	assert.Equal(t, make([]byte, len(original)), cleared)
}

func TestShareIntegrity(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 64)
	config := shamir.Config{
		Parts:     10,
		Threshold: 6,
	}

	shares, err := shamir.Split(secret, config)
	require.NoError(t, err)

	for i, share := range shares {
		err := shamir.VerifyShare(share, len(share.Data))
		assert.NoError(t, err, "Share %d should be valid", i)
	}

	corruptedShare := shamir.Share{
		Index: shares[0].Index,
		Data:  append(shares[0].Data, 0xFF),
	}
	err = shamir.VerifyShare(corruptedShare, len(shares[0].Data))
	assert.Error(t, err)
}

func TestPassphraseHandling(t *testing.T) {
	m, err := mnemonic.NewMnemonic(128)
	require.NoError(t, err)

	passphrases := []string{
		"",
		"simple",
		"Complex!@#$%^&*()Passphrase123",
		"Unicode: 你好世界 🔐",
	}

	seeds := make([][]byte, len(passphrases))
	for i, passphrase := range passphrases {
		seeds[i] = m.SeedWithPassphrase(passphrase)
		defer secure.Zero(seeds[i])

		for j := 0; j < i; j++ {
			assert.NotEqual(t, seeds[j], seeds[i],
				"Different passphrases should produce different seeds")
		}
	}
}

func TestMultipleDerivationPaths(t *testing.T) {
	m, err := mnemonic.NewMnemonic(256)
	require.NoError(t, err)

	seed := m.Seed()
	defer secure.Zero(seed)

	masterKey, err := hdkey.NewMasterKey(seed)
	require.NoError(t, err)

	paths := []string{
		"m/44'/0'/0'/0/0",  // Bitcoin
		"m/44'/60'/0'/0/0", // Ethereum
		"m/44'/2'/0'/0/0",  // Litecoin
		"m/49'/0'/0'/0/0",  // Bitcoin SegWit
		"m/84'/0'/0'/0/0",  // Bitcoin Native SegWit
	}

	keys := make(map[string]string)
	for _, path := range paths {
		derivedKey, err := masterKey.DerivePath(path)
		require.NoError(t, err)

		publicKey := derivedKey.PublicKeyHex()
		assert.NotEmpty(t, publicKey)

		for existingPath, existingKey := range keys {
			assert.NotEqual(t, existingKey, publicKey,
				"Path %s and %s should produce different keys", path, existingPath)
		}

		keys[path] = publicKey
		t.Logf("Path %s: %s", path, publicKey)
	}
}

func TestErrorRecovery(t *testing.T) {
	secret := []byte("test secret")
	config := shamir.Config{
		Parts:     5,
		Threshold: 3,
	}

	shares, err := shamir.Split(secret, config)
	require.NoError(t, err)

	invalidShares := []shamir.Share{
		{Index: 1, Data: []byte("invalid")},
		shares[1],
		shares[2],
	}
	_, err = shamir.Combine(invalidShares)
	assert.Error(t, err)

	tooFewShares := shares[:2]
	_, err = shamir.Combine(tooFewShares)
	assert.NoError(t, err)

	duplicateShares := []shamir.Share{
		shares[0],
		shares[0],
		shares[1],
	}
	_, err = shamir.Combine(duplicateShares)
	assert.Error(t, err)
}

func BenchmarkFullWorkflow(b *testing.B) {
	m, _ := mnemonic.NewMnemonic(256)
	entropy, _ := m.Entropy()
	config := shamir.Config{
		Parts:     5,
		Threshold: 3,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shares, _ := shamir.Split(entropy, config)
		reconstructed, _ := shamir.Combine(shares[:3])
		recoveredMnemonic, _ := mnemonic.FromEntropy(reconstructed)
		seed := recoveredMnemonic.Seed()
		masterKey, _ := hdkey.NewMasterKey(seed)
		masterKey.DerivePath("m/44'/60'/0'/0/0")
	}
}

func TestShareSerialization(t *testing.T) {
	secret := []byte("test serialization")
	config := shamir.Config{
		Parts:     3,
		Threshold: 2,
	}

	shares, err := shamir.Split(secret, config)
	require.NoError(t, err)

	hexShares := make([]string, len(shares))
	for i, share := range shares {
		hexShares[i] = hex.EncodeToString(share.Data)
	}

	reconstructedShares := make([]shamir.Share, len(hexShares))
	for i, hexShare := range hexShares {
		data, err := hex.DecodeString(hexShare)
		require.NoError(t, err)
		reconstructedShares[i] = shamir.Share{
			Index: byte(i + 1),
			Data:  data,
		}
	}

	reconstructed, err := shamir.Combine(reconstructedShares[:2])
	require.NoError(t, err)
	assert.Equal(t, secret, reconstructed)
}
