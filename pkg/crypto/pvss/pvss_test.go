package pvss

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestPVSSSystemCreation(t *testing.T) {
	tests := []struct {
		name        string
		curveType   CurveType
		threshold   int
		numShares   int
		expectError bool
	}{
		{"Valid P256 2-of-3", CurveP256, 2, 3, false},
		{"Valid P256 3-of-5", CurveP256, 3, 5, false},
		{"Invalid threshold zero", CurveP256, 0, 3, true},
		{"Invalid threshold too high", CurveP256, 4, 3, true},
		{"Invalid curve", CurveType("invalid"), 2, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			system, err := NewPVSSSystem(tt.curveType, tt.threshold, tt.numShares)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			if system.Threshold != tt.threshold {
				t.Errorf("Expected threshold %d, got %d", tt.threshold, system.Threshold)
			}
			if system.NumShares != tt.numShares {
				t.Errorf("Expected numShares %d, got %d", tt.numShares, system.NumShares)
			}
		})
	}
}

func TestPVSSBasicShareGeneration(t *testing.T) {
	system, err := NewPVSSSystem(CurveP256, 2, 3)
	if err != nil {
		t.Fatalf("Failed to create PVSS system: %v", err)
	}

	secret := []byte("test secret 123")
	shares, err := system.GenerateShares(secret)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	if len(shares) != 3 {
		t.Errorf("Expected 3 shares, got %d", len(shares))
	}

	// Verify each share has proper structure
	for i, share := range shares {
		if share.Index != i+1 {
			t.Errorf("Share %d has incorrect index: expected %d, got %d", i, i+1, share.Index)
		}
		if share.Value == nil {
			t.Errorf("Share %d has nil value", i)
		}
		if share.Commitment == nil {
			t.Errorf("Share %d has nil commitment", i)
		}
		if len(share.Commitment.Commitments) != system.Threshold {
			t.Errorf("Share %d commitment has wrong length: expected %d, got %d", 
				i, system.Threshold, len(share.Commitment.Commitments))
		}
	}
}

func TestPVSSShareVerification(t *testing.T) {
	system, err := NewPVSSSystem(CurveP256, 2, 3)
	if err != nil {
		t.Fatalf("Failed to create PVSS system: %v", err)
	}

	secret := []byte("test secret for verification")
	shares, err := system.GenerateShares(secret)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	// All generated shares should verify
	for i, share := range shares {
		if err := system.VerifyShare(share); err != nil {
			t.Errorf("Share %d failed verification: %v", i, err)
		}
	}

	// Test with corrupted share value
	corruptedShare := *shares[0]
	corruptedShare.Value = big.NewInt(12345) // Arbitrary incorrect value
	if err := system.VerifyShare(&corruptedShare); err == nil {
		t.Error("Corrupted share passed verification when it should have failed")
	}

	// Test with nil commitment
	nilCommitmentShare := *shares[0]
	nilCommitmentShare.Commitment = nil
	if err := system.VerifyShare(&nilCommitmentShare); err == nil {
		t.Error("Share with nil commitment passed verification")
	}
}

func TestPVSSSecretReconstruction(t *testing.T) {
	system, err := NewPVSSSystem(CurveP256, 3, 5)
	if err != nil {
		t.Fatalf("Failed to create PVSS system: %v", err)
	}

	originalSecret := []byte("this is a test secret for reconstruction")
	shares, err := system.GenerateShares(originalSecret)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	// Test with exact threshold
	thresholdShares := shares[:3]
	recoveredSecret, err := system.RecoverSecret(thresholdShares)
	if err != nil {
		t.Fatalf("Failed to recover secret with threshold shares: %v", err)
	}

	// For PVSS, secret is processed (possibly hashed), so we need to check processed version
	processedOriginal := processSecretForTest(system, originalSecret)
	if !compareBytes(recoveredSecret, processedOriginal) {
		t.Errorf("Recovered secret doesn't match original processed secret")
		t.Logf("Original processed: %x", processedOriginal)
		t.Logf("Recovered: %x", recoveredSecret)
	}

	// Test with more than threshold shares
	allShares := shares
	recoveredSecret2, err := system.RecoverSecret(allShares)
	if err != nil {
		t.Fatalf("Failed to recover secret with all shares: %v", err)
	}

	if !compareBytes(recoveredSecret, recoveredSecret2) {
		t.Error("Secret recovered with different number of shares should be identical")
	}
}

func TestPVSSInsufficientShares(t *testing.T) {
	system, err := NewPVSSSystem(CurveP256, 3, 5)
	if err != nil {
		t.Fatalf("Failed to create PVSS system: %v", err)
	}

	secret := []byte("test secret")
	shares, err := system.GenerateShares(secret)
	if err != nil {
		t.Fatalf("Failed to generate shares: %v", err)
	}

	// Try to recover with insufficient shares (2 out of 3 required)
	insufficientShares := shares[:2]
	_, err = system.RecoverSecret(insufficientShares)
	if err == nil {
		t.Error("Expected error when recovering with insufficient shares, but got none")
	}
}

func TestPVSSSecretSizes(t *testing.T) {
	system, err := NewPVSSSystem(CurveP256, 2, 3)
	if err != nil {
		t.Fatalf("Failed to create PVSS system: %v", err)
	}

	testCases := []struct {
		name   string
		secret []byte
	}{
		{"16 byte secret", make([]byte, 16)},
		{"32 byte secret", make([]byte, 32)},
		{"Large secret", make([]byte, 128)}, // Should be hashed down
		{"Small secret", []byte("small")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill with random data
			rand.Read(tc.secret)

			shares, err := system.GenerateShares(tc.secret)
			if err != nil {
				t.Fatalf("Failed to generate shares for %s: %v", tc.name, err)
			}

			recoveredSecret, err := system.RecoverSecret(shares[:system.Threshold])
			if err != nil {
				t.Fatalf("Failed to recover secret for %s: %v", tc.name, err)
			}

			// Compare with processed original
			processedOriginal := processSecretForTest(system, tc.secret)
			if !compareBytes(recoveredSecret, processedOriginal) {
				t.Errorf("Secret recovery failed for %s", tc.name)
			}
		})
	}
}

func TestPVSSEmptySecret(t *testing.T) {
	system, err := NewPVSSSystem(CurveP256, 2, 3)
	if err != nil {
		t.Fatalf("Failed to create PVSS system: %v", err)
	}

	_, err = system.GenerateShares([]byte{})
	if err == nil {
		t.Error("Expected error for empty secret, but got none")
	}
}

func TestPVSSPolynomialEvaluation(t *testing.T) {
	system, err := NewPVSSSystem(CurveP256, 2, 3)
	if err != nil {
		t.Fatalf("Failed to create PVSS system: %v", err)
	}

	// Create a simple polynomial: f(x) = 5 + 3x (mod order)
	coefficients := []*big.Int{
		big.NewInt(5), // constant term
		big.NewInt(3), // coefficient of x
	}

	// Test evaluation at different points
	testCases := []struct {
		x        *big.Int
		expected *big.Int
	}{
		{big.NewInt(0), big.NewInt(5)},  // f(0) = 5
		{big.NewInt(1), big.NewInt(8)},  // f(1) = 5 + 3*1 = 8
		{big.NewInt(2), big.NewInt(11)}, // f(2) = 5 + 3*2 = 11
	}

	for _, tc := range testCases {
		result := system.evaluatePolynomial(coefficients, tc.x)
		expected := new(big.Int).Mod(tc.expected, system.Params.Order)
		
		if result.Cmp(expected) != 0 {
			t.Errorf("Polynomial evaluation at x=%s: expected %s, got %s", 
				tc.x, expected, result)
		}
	}
}

func TestPVSSPointOperations(t *testing.T) {
	// Test point equality
	p1 := &Point{X: big.NewInt(100), Y: big.NewInt(200)}
	p2 := &Point{X: big.NewInt(100), Y: big.NewInt(200)}
	p3 := &Point{X: big.NewInt(101), Y: big.NewInt(200)}

	if !p1.Equal(p2) {
		t.Error("Identical points should be equal")
	}
	if p1.Equal(p3) {
		t.Error("Different points should not be equal")
	}

	// Test infinity point
	inf1 := &Point{X: nil, Y: nil}
	inf2 := &Point{X: nil, Y: nil}
	if !inf1.IsInfinity() {
		t.Error("Point with nil coordinates should be infinity")
	}
	if !inf1.Equal(inf2) {
		t.Error("Infinity points should be equal")
	}
	if inf1.Equal(p1) {
		t.Error("Infinity point should not equal regular point")
	}
}

func TestPVSSSystemIntegrity(t *testing.T) {
	// Test that the same secret always produces verifiable shares
	system, err := NewPVSSSystem(CurveP256, 3, 5)
	if err != nil {
		t.Fatalf("Failed to create PVSS system: %v", err)
	}

	secret := []byte("consistent secret for testing")
	
	// Generate shares multiple times
	for i := 0; i < 5; i++ {
		shares, err := system.GenerateShares(secret)
		if err != nil {
			t.Fatalf("Failed to generate shares on iteration %d: %v", i, err)
		}

		// All shares should verify
		for j, share := range shares {
			if err := system.VerifyShare(share); err != nil {
				t.Errorf("Share %d failed verification on iteration %d: %v", j, i, err)
			}
		}

		// Should be able to recover original secret
		recoveredSecret, err := system.RecoverSecret(shares[:3])
		if err != nil {
			t.Errorf("Failed to recover secret on iteration %d: %v", i, err)
		}

		processedOriginal := processSecretForTest(system, secret)
		if !compareBytes(recoveredSecret, processedOriginal) {
			t.Errorf("Recovered secret mismatch on iteration %d", i)
		}
	}
}

// Helper function to compare byte slices
func compareBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Helper function to replicate processSecret logic for testing
func processSecretForTest(system *PVSSSystem, secret []byte) []byte {
	// Replicate the same logic from PVSSSharer.processSecret
	if len(secret) > 32 {
		hash := sha256.Sum256(secret)
		return hash[:]
	}
	
	// For smaller secrets, pad with zeros if needed
	if len(secret) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(secret):], secret)
		return padded
	}
	
	return secret
}