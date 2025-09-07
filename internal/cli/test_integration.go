// +build integration

package cli

import (
	"testing"
	"time"

	"github.com/Davincible/shamir/pkg/config"
	"github.com/Davincible/shamir/pkg/crypto/secretsharing"
	"github.com/Davincible/shamir/pkg/sharestore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnhancedFeatures tests the new enhanced functionality
func TestEnhancedFeatures(t *testing.T) {
	// Test configuration system
	t.Run("ConfigurationSystem", func(t *testing.T) {
		cm, err := config.NewConfigManager()
		require.NoError(t, err)
		
		cfg := cm.GetConfig()
		assert.NotNil(t, cfg)
		assert.Equal(t, "slip039", cfg.Defaults.Scheme)
		assert.Equal(t, 2, cfg.Defaults.Threshold)
		assert.Equal(t, 3, cfg.Defaults.Shares)
	})
	
	// Test share store
	t.Run("ShareStore", func(t *testing.T) {
		store, err := sharestore.NewShareStore(t.TempDir())
		require.NoError(t, err)
		
		// Create a test share set
		shareSet := &sharestore.ShareSet{
			Name:        "Test Share Set",
			Description: "Test description",
			Scheme:      secretsharing.SchemeSLIP039,
			Created:     time.Now(),
			Modified:    time.Now(),
			Threshold:   2,
			TotalShares: 3,
			Tags:        []string{"test"},
			Shares: []sharestore.ShareInfo{
				{
					Index:      1,
					GroupIndex: 1,
					Status:     sharestore.ShareStatusAvailable,
					Created:    time.Now(),
				},
			},
		}
		
		err = store.AddShareSet(shareSet)
		require.NoError(t, err)
		
		// Retrieve and verify
		retrieved, err := store.GetShareSet(shareSet.ID)
		require.NoError(t, err)
		assert.Equal(t, shareSet.Name, retrieved.Name)
		assert.Equal(t, shareSet.Scheme, retrieved.Scheme)
		
		// Test search
		results := store.SearchShareSets("test")
		assert.Len(t, results, 1)
		assert.Equal(t, shareSet.ID, results[0].ID)
	})
	
	// Test PVSS scheme registration
	t.Run("PVSSIntegration", func(t *testing.T) {
		schemes := secretsharing.DefaultRegistry.ListSchemes()
		assert.Contains(t, schemes, secretsharing.SchemePVSS)
		assert.Contains(t, schemes, secretsharing.SchemeSLIP039)
		
		// Test getting PVSS sharer
		sharer, err := secretsharing.DefaultRegistry.Get(secretsharing.SchemePVSS)
		require.NoError(t, err)
		assert.Equal(t, secretsharing.SchemePVSS, sharer.GetScheme())
	})
}

// TestCommandCreation tests that all new commands can be created without panic
func TestCommandCreation(t *testing.T) {
	tests := []struct {
		name    string
		cmdFunc func() interface{}
	}{
		{
			name: "ShareCommand",
			cmdFunc: func() interface{} {
				return NewShareCommand()
			},
		},
		{
			name: "ManageCommand", 
			cmdFunc: func() interface{} {
				return NewManageCommand()
			},
		},
		{
			name: "RecoverCommand",
			cmdFunc: func() interface{} {
				return NewRecoverCommand()
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				cmd := tt.cmdFunc()
				assert.NotNil(t, cmd)
			})
		})
	}
}

// TestSecretSharingConfig tests the enhanced configuration
func TestSecretSharingConfig(t *testing.T) {
	config := secretsharing.SecretSharingConfig{
		Scheme:         secretsharing.SchemePVSS,
		GroupThreshold: 1,
		Groups: []secretsharing.GroupConfiguration{
			{
				MemberThreshold: 2,
				MemberCount:     3,
			},
		},
		CurveType: "p256",
	}
	
	// Test PVSS sharer validation
	sharer, err := secretsharing.DefaultRegistry.Get(secretsharing.SchemePVSS)
	require.NoError(t, err)
	
	err = sharer.ValidateConfig(config)
	assert.NoError(t, err)
}

// BenchmarkPVSSOperations benchmarks PVSS performance
func BenchmarkPVSSOperations(b *testing.B) {
	secret := []byte("test secret for benchmarking")
	config := secretsharing.SecretSharingConfig{
		Scheme:         secretsharing.SchemePVSS,
		GroupThreshold: 1,
		Groups: []secretsharing.GroupConfiguration{
			{
				MemberThreshold: 3,
				MemberCount:     5,
			},
		},
		CurveType: "p256",
	}
	
	sharer, err := secretsharing.DefaultRegistry.Get(secretsharing.SchemePVSS)
	require.NoError(b, err)
	
	b.Run("Split", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			shares, err := sharer.Split(secret, config)
			require.NoError(b, err)
			require.Len(b, shares, 5)
		}
	})
	
	// Pre-generate shares for combine benchmark
	shares, err := sharer.Split(secret, config)
	require.NoError(b, err)
	
	b.Run("Combine", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			recovered, err := sharer.Combine(shares[:3], "")
			require.NoError(b, err)
			require.Equal(b, secret, recovered)
		}
	})
	
	b.Run("Verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := sharer.Verify(shares[0])
			require.NoError(b, err)
		}
	})
}