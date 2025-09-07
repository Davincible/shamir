package hdkey

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMasterKey(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	require.NoError(t, err)

	masterKey, err := NewMasterKey(seed)
	require.NoError(t, err)
	assert.NotNil(t, masterKey)
	assert.Equal(t, "m", masterKey.Path())
	assert.True(t, masterKey.IsPrivate())

	_, err = NewMasterKey([]byte("too short"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "seed must be at least 16 bytes")
}

func TestDerivePath(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	masterKey, err := NewMasterKey(seed)
	require.NoError(t, err)

	tests := []struct {
		name      string
		path      string
		wantError bool
	}{
		{
			name: "Valid BIP44 path",
			path: "m/44'/0'/0'/0/0",
		},
		{
			name: "Valid Ethereum path",
			path: "m/44'/60'/0'/0/0",
		},
		{
			name:      "Invalid path - no m/",
			path:      "44'/0'/0'/0/0",
			wantError: true,
		},
		{
			name:      "Invalid path - invalid segment",
			path:      "m/44'/abc/0'/0/0",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derivedKey, err := masterKey.DerivePath(tt.path)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, derivedKey)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, derivedKey)
				assert.Equal(t, tt.path, derivedKey.Path())
				assert.NotEmpty(t, derivedKey.PublicKeyHex())
				assert.NotEmpty(t, derivedKey.ExtendedPublicKey())
			}
		})
	}
}

func TestDeriveAccount(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	masterKey, err := NewMasterKey(seed)
	require.NoError(t, err)

	accountKey, err := masterKey.DeriveAccount(PurposeBIP44, CoinTypeBitcoin, 0)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/0'/0'", accountKey.Path())

	ethKey, err := masterKey.DeriveAccount(PurposeBIP44, CoinTypeEthereum, 1)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/60'/1'", ethKey.Path())
}

func TestDeriveLedgerPath(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	masterKey, err := NewMasterKey(seed)
	require.NoError(t, err)

	ledgerKey, err := masterKey.DeriveLedgerPath(0)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/60'/0'", ledgerKey.Path())
}

func TestDeriveAddress(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	masterKey, err := NewMasterKey(seed)
	require.NoError(t, err)

	accountKey, err := masterKey.DeriveAccount(PurposeBIP44, CoinTypeBitcoin, 0)
	require.NoError(t, err)

	addressKey, err := accountKey.DeriveAddress(0, 0)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/0'/0'/0/0", addressKey.Path())

	changeKey, err := accountKey.DeriveAddress(1, 5)
	require.NoError(t, err)
	assert.Equal(t, "m/44'/0'/0'/1/5", changeKey.Path())
}

func TestKeyProperties(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	masterKey, err := NewMasterKey(seed)
	require.NoError(t, err)

	derivedKey, err := masterKey.DerivePath("m/44'/0'/0'/0/0")
	require.NoError(t, err)

	pubKey := derivedKey.PublicKey()
	assert.NotEmpty(t, pubKey)
	assert.Len(t, pubKey, 33)

	pubKeyHex := derivedKey.PublicKeyHex()
	assert.NotEmpty(t, pubKeyHex)
	assert.Len(t, pubKeyHex, 66)

	decodedPubKey, err := hex.DecodeString(pubKeyHex)
	require.NoError(t, err)
	assert.Equal(t, pubKey, decodedPubKey)

	if derivedKey.IsPrivate() {
		privKey := derivedKey.PrivateKey()
		assert.NotEmpty(t, privKey)
		assert.Len(t, privKey, 32)

		privKeyHex := derivedKey.PrivateKeyHex()
		assert.NotEmpty(t, privKeyHex)
		assert.Len(t, privKeyHex, 64)

		decodedPrivKey, err := hex.DecodeString(privKeyHex)
		require.NoError(t, err)
		assert.Equal(t, privKey, decodedPrivKey)
	}

	xpub := derivedKey.ExtendedPublicKey()
	assert.NotEmpty(t, xpub)
	assert.True(t, len(xpub) > 100)

	if derivedKey.IsPrivate() {
		xprv := derivedKey.ExtendedPrivateKey()
		assert.NotEmpty(t, xprv)
		assert.True(t, len(xprv) > 100)
	}

	fingerprint := derivedKey.Fingerprint()
	assert.NotEmpty(t, fingerprint)
	assert.Len(t, fingerprint, 4)

	chainCode := derivedKey.ChainCode()
	assert.NotEmpty(t, chainCode)
	assert.Len(t, chainCode, 32)
}

func TestParseDerivationPath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		want      *DerivationPath
		wantError bool
	}{
		{
			name: "Valid BIP44 path",
			path: "m/44'/0'/0'/0/0",
			want: &DerivationPath{
				Purpose:  44,
				CoinType: 0,
				Account:  0,
				Change:   0,
				Index:    0,
			},
		},
		{
			name: "Valid Ethereum path",
			path: "m/44'/60'/1'/0/5",
			want: &DerivationPath{
				Purpose:  44,
				CoinType: 60,
				Account:  1,
				Change:   0,
				Index:    5,
			},
		},
		{
			name:      "Invalid path - no m/",
			path:      "44'/0'/0'/0/0",
			wantError: true,
		},
		{
			name:      "Invalid path - too short",
			path:      "m/44'/0'",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dp, err := ParseDerivationPath(tt.path)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, dp)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, dp)
				assert.Equal(t, tt.path, dp.String())
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name  string
		path  string
		valid bool
	}{
		{"Valid path", "m/44'/0'/0'/0/0", true},
		{"Invalid path", "invalid", false},
		{"Empty path", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePath(tt.path)
			if tt.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestGenerateMasterKey(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	privateKey, chainCode, err := GenerateMasterKey(seed)
	require.NoError(t, err)
	assert.Len(t, privateKey, 32)
	assert.Len(t, chainCode, 32)
	assert.NotEqual(t, privateKey, chainCode)
}

func TestFromExtendedKey(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	masterKey, err := NewMasterKey(seed)
	require.NoError(t, err)

	xpub := masterKey.ExtendedPublicKey()
	pubKey, err := FromExtendedKey(xpub)
	require.NoError(t, err)
	assert.False(t, pubKey.IsPrivate())

	xprv := masterKey.ExtendedPrivateKey()
	privKey, err := FromExtendedKey(xprv)
	require.NoError(t, err)
	assert.True(t, privKey.IsPrivate())

	_, err = FromExtendedKey("invalid")
	assert.Error(t, err)
}

func TestKeyConsistency(t *testing.T) {
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)

	masterKey1, err := NewMasterKey(seed)
	require.NoError(t, err)

	masterKey2, err := NewMasterKey(seed)
	require.NoError(t, err)

	assert.Equal(t, masterKey1.PublicKeyHex(), masterKey2.PublicKeyHex())
	assert.Equal(t, masterKey1.PrivateKeyHex(), masterKey2.PrivateKeyHex())

	path := "m/44'/0'/0'/0/0"
	derived1, err := masterKey1.DerivePath(path)
	require.NoError(t, err)

	derived2, err := masterKey2.DerivePath(path)
	require.NoError(t, err)

	assert.Equal(t, derived1.PublicKeyHex(), derived2.PublicKeyHex())
	assert.Equal(t, derived1.PrivateKeyHex(), derived2.PrivateKeyHex())
}

func BenchmarkDerivePath(b *testing.B) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	masterKey, _ := NewMasterKey(seed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = masterKey.DerivePath("m/44'/0'/0'/0/0")
	}
}

func BenchmarkNewMasterKey(b *testing.B) {
	seed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = NewMasterKey(seed)
	}
}
