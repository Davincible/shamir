package shamir

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitAndCombine(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		parts     int
		threshold int
	}{
		{
			name:      "Simple secret 3 of 5",
			secret:    []byte("my secret data"),
			parts:     5,
			threshold: 3,
		},
		{
			name:      "256-bit key 2 of 3",
			secret:    bytes.Repeat([]byte{0x42}, 32),
			parts:     3,
			threshold: 2,
		},
		{
			name:      "Large secret 5 of 7",
			secret:    bytes.Repeat([]byte("test"), 256),
			parts:     7,
			threshold: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := Config{
				Parts:     tt.parts,
				Threshold: tt.threshold,
			}

			shares, err := Split(tt.secret, config)
			require.NoError(t, err)
			assert.Len(t, shares, tt.parts)

			for i, share := range shares {
				assert.NotEmpty(t, share.Data)
				assert.Equal(t, byte(i+1), share.Index)
			}

			reconstructed, err := Combine(shares[:tt.threshold])
			require.NoError(t, err)
			assert.Equal(t, tt.secret, reconstructed)

			reconstructed2, err := Combine(shares[tt.parts-tt.threshold:])
			require.NoError(t, err)
			assert.Equal(t, tt.secret, reconstructed2)
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantError bool
	}{
		{
			name: "Valid config",
			config: Config{
				Parts:     5,
				Threshold: 3,
			},
			wantError: false,
		},
		{
			name: "Parts too small",
			config: Config{
				Parts:     1,
				Threshold: 1,
			},
			wantError: true,
		},
		{
			name: "Threshold too small",
			config: Config{
				Parts:     5,
				Threshold: 1,
			},
			wantError: true,
		},
		{
			name: "Threshold greater than parts",
			config: Config{
				Parts:     3,
				Threshold: 5,
			},
			wantError: true,
		},
		{
			name: "Parts exceeds maximum",
			config: Config{
				Parts:     256,
				Threshold: 100,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCombineInsufficientShares(t *testing.T) {
	secret := []byte("test secret")
	config := Config{
		Parts:     5,
		Threshold: 3,
	}

	shares, err := Split(secret, config)
	require.NoError(t, err)

	_, err = Combine(shares[:1])
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least 2 shares")
}

func TestCombineInvalidShares(t *testing.T) {
	secret := []byte("test secret")
	config := Config{
		Parts:     5,
		Threshold: 3,
	}

	shares, err := Split(secret, config)
	require.NoError(t, err)

	// Create an invalid share with empty data
	invalidShares := []Share{
		{Index: 1, Data: []byte{}},
		shares[1],
		shares[2],
	}

	_, err = Combine(invalidShares)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty data")
}

func TestVerifyShare(t *testing.T) {
	secret := []byte("test secret")
	config := Config{
		Parts:     3,
		Threshold: 2,
	}

	shares, err := Split(secret, config)
	require.NoError(t, err)

	expectedLen := len(shares[0].Data)

	err = VerifyShare(shares[0], expectedLen)
	assert.NoError(t, err)

	err = VerifyShare(Share{Index: 0, Data: shares[0].Data}, expectedLen)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "index cannot be 0")

	err = VerifyShare(Share{Index: 1, Data: []byte{1, 2}}, expectedLen)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid share length")
}

func TestGenerateRandomBytes(t *testing.T) {
	tests := []struct {
		name      string
		size      int
		wantError bool
	}{
		{"16 bytes", 16, false},
		{"32 bytes", 32, false},
		{"256 bytes", 256, false},
		{"Zero bytes", 0, true},
		{"Negative bytes", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes, err := GenerateRandomBytes(tt.size)
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, bytes)
			} else {
				assert.NoError(t, err)
				assert.Len(t, bytes, tt.size)

				bytes2, err := GenerateRandomBytes(tt.size)
				assert.NoError(t, err)
				assert.NotEqual(t, bytes, bytes2)
			}
		})
	}
}

func TestSecureCompare(t *testing.T) {
	a := []byte("test data")
	b := []byte("test data")
	c := []byte("different")

	assert.True(t, SecureCompare(a, b))
	assert.False(t, SecureCompare(a, c))
	assert.False(t, SecureCompare(a, []byte("test dat")))
}

func TestSecureZero(t *testing.T) {
	data := []byte("sensitive data")
	original := make([]byte, len(data))
	copy(original, data)

	SecureZero(data)

	assert.NotEqual(t, original, data)
	for _, b := range data {
		assert.Equal(t, byte(0), b)
	}
}

func BenchmarkSplit(b *testing.B) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	config := Config{
		Parts:     5,
		Threshold: 3,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Split(secret, config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCombine(b *testing.B) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	config := Config{
		Parts:     5,
		Threshold: 3,
	}

	shares, err := Split(secret, config)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Combine(shares[:3])
		if err != nil {
			b.Fatal(err)
		}
	}
}
