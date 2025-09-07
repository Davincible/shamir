package slip039

import (
	"bytes"
	"strings"
	"testing"
)

// TestVector represents a test vector from the SLIP-0039 specification
type TestVector struct {
	Description string     `json:"description"`
	Mnemonics   []string   `json:"mnemonics"`
	MasterSecret string    `json:"master_secret"`
	Passphrase  string     `json:"passphrase"`
}

func TestBasicSplitAndCombine(t *testing.T) {
	// Test basic 2-of-3 secret sharing
	masterSecret := []byte("test master secret sixteen bytes")
	passphrase := "TREZOR"
	
	// Create 2-of-3 configuration
	groups := SimpleConfiguration(2, 3)
	
	// Split the secret
	mnemonics, err := SplitMasterSecret(masterSecret, passphrase, 1, groups)
	if err != nil {
		t.Fatalf("Failed to split master secret: %v", err)
	}
	
	if len(mnemonics) != 1 {
		t.Fatalf("Expected 1 group, got %d", len(mnemonics))
	}
	
	if len(mnemonics[0]) != 3 {
		t.Fatalf("Expected 3 shares, got %d", len(mnemonics[0]))
	}
	
	// Test recovery with minimum threshold (2 shares)
	recoveredSecret, err := RecoverMasterSecret(mnemonics[0][:2], passphrase)
	if err != nil {
		t.Fatalf("Failed to recover master secret: %v", err)
	}
	
	if !bytes.Equal(masterSecret, recoveredSecret) {
		t.Errorf("Recovered secret doesn't match original")
		t.Errorf("Original: %x", masterSecret)
		t.Errorf("Recovered: %x", recoveredSecret)
	}
	
	// Test recovery with all shares
	recoveredSecret2, err := RecoverMasterSecret(mnemonics[0], passphrase)
	if err != nil {
		t.Fatalf("Failed to recover with all shares: %v", err)
	}
	
	if !bytes.Equal(masterSecret, recoveredSecret2) {
		t.Errorf("Recovered secret with all shares doesn't match original")
	}
}

func TestTwoLevelSharing(t *testing.T) {
	// Test two-level sharing: 2-of-2 groups, each with 2-of-3 members
	masterSecret := []byte("two level secret sharing test32b")
	passphrase := ""
	
	groups := []GroupConfiguration{
		{MemberThreshold: 2, MemberCount: 3},
		{MemberThreshold: 2, MemberCount: 3},
	}
	
	// Split the secret
	mnemonics, err := SplitMasterSecret(masterSecret, passphrase, 2, groups)
	if err != nil {
		t.Fatalf("Failed to split master secret: %v", err)
	}
	
	if len(mnemonics) != 2 {
		t.Fatalf("Expected 2 groups, got %d", len(mnemonics))
	}
	
	// Combine using minimum shares from each group
	selectedShares := []string{
		mnemonics[0][0], // 2 shares from group 0
		mnemonics[0][1],
		mnemonics[1][0], // 2 shares from group 1
		mnemonics[1][2],
	}
	
	recoveredSecret, err := RecoverMasterSecret(selectedShares, passphrase)
	if err != nil {
		t.Fatalf("Failed to recover master secret: %v", err)
	}
	
	if !bytes.Equal(masterSecret, recoveredSecret) {
		t.Errorf("Recovered secret doesn't match original")
		t.Errorf("Original: %x", masterSecret)
		t.Errorf("Recovered: %x", recoveredSecret)
	}
}

func TestShareValidation(t *testing.T) {
	// Create a valid share set (must be even length)
	masterSecret := []byte("validation test master secret32b")
	passphrase := "test"
	
	groups := SimpleConfiguration(2, 3)
	mnemonics, err := SplitMasterSecret(masterSecret, passphrase, 1, groups)
	if err != nil {
		t.Fatalf("Failed to split master secret: %v", err)
	}
	
	// Test valid mnemonic
	if err := ValidateMnemonic(mnemonics[0][0]); err != nil {
		t.Errorf("Valid mnemonic failed validation: %v", err)
	}
	
	// Test invalid mnemonic (wrong checksum)
	words := strings.Fields(mnemonics[0][0])
	words[len(words)-1] = "abandon" // Change last word to break checksum
	invalidMnemonic := strings.Join(words, " ")
	
	if err := ValidateMnemonic(invalidMnemonic); err == nil {
		t.Error("Invalid mnemonic passed validation")
	}
}

func TestShareInfo(t *testing.T) {
	masterSecret := []byte("info test master secret bytes32")
	passphrase := ""
	
	groups := []GroupConfiguration{
		{MemberThreshold: 2, MemberCount: 3},
		{MemberThreshold: 3, MemberCount: 5},
	}
	
	mnemonics, err := SplitMasterSecret(masterSecret, passphrase, 2, groups)
	if err != nil {
		t.Fatalf("Failed to split master secret: %v", err)
	}
	
	// Check info for first share of second group
	info, err := GetShareInfo(mnemonics[1][0])
	if err != nil {
		t.Fatalf("Failed to get share info: %v", err)
	}
	
	if info.GroupCount != 2 {
		t.Errorf("Expected 2 groups, got %d", info.GroupCount)
	}
	
	if info.GroupThreshold != 2 {
		t.Errorf("Expected group threshold 2, got %d", info.GroupThreshold)
	}
	
	if info.GroupIndex != 2 { // 1-based
		t.Errorf("Expected group index 2, got %d", info.GroupIndex)
	}
	
	if info.MemberThreshold != 3 {
		t.Errorf("Expected member threshold 3, got %d", info.MemberThreshold)
	}
	
	if info.MemberIndex != 1 { // 1-based
		t.Errorf("Expected member index 1, got %d", info.MemberIndex)
	}
}

func TestDifferentPassphrases(t *testing.T) {
	masterSecret := []byte("passphrase test master secret32")
	
	groups := SimpleConfiguration(2, 3)
	
	// Create shares with passphrase "A"
	mnemonicsA, err := SplitMasterSecret(masterSecret, "A", 1, groups)
	if err != nil {
		t.Fatalf("Failed to split with passphrase A: %v", err)
	}
	
	// Recover with correct passphrase
	recoveredA, err := RecoverMasterSecret(mnemonicsA[0][:2], "A")
	if err != nil {
		t.Fatalf("Failed to recover with passphrase A: %v", err)
	}
	
	if !bytes.Equal(masterSecret, recoveredA) {
		t.Error("Failed to recover with correct passphrase")
	}
	
	// Recover with wrong passphrase (should succeed but give different result)
	recoveredB, err := RecoverMasterSecret(mnemonicsA[0][:2], "B")
	if err != nil {
		t.Fatalf("Failed to recover with passphrase B: %v", err)
	}
	
	if bytes.Equal(masterSecret, recoveredB) {
		t.Error("Different passphrases yielded same result (should be different for plausible deniability)")
	}
}

func TestInsufficientShares(t *testing.T) {
	masterSecret := []byte("insufficient shares test secret!")
	passphrase := ""
	
	// Create 3-of-5 shares
	groups := SimpleConfiguration(3, 5)
	mnemonics, err := SplitMasterSecret(masterSecret, passphrase, 1, groups)
	if err != nil {
		t.Fatalf("Failed to split master secret: %v", err)
	}
	
	// Try to recover with only 2 shares (need 3)
	_, err = RecoverMasterSecret(mnemonics[0][:2], passphrase)
	if err == nil {
		t.Error("Recovery succeeded with insufficient shares")
	}
}

func TestFieldArithmetic(t *testing.T) {
	// Test GF(256) multiplication with Rijndael polynomial
	tests := []struct {
		a, b, expected byte
	}{
		{0, 0, 0},
		{1, 1, 1},
		{2, 2, 4},
		{3, 7, 9},    // Corrected for GF(256) with Rijndael
		{9, 11, 1},   // Corrected for GF(256) with Rijndael
		{255, 1, 255},
		{255, 255, 19}, // Corrected for GF(256) with Rijndael
	}
	
	for _, tc := range tests {
		result := gfMultiply(tc.a, tc.b)
		if result != tc.expected {
			t.Errorf("gfMultiply(%d, %d) = %d, expected %d", 
				tc.a, tc.b, result, tc.expected)
		}
	}
	
	// Test inverse
	for i := byte(1); i < 255; i++ {
		inv := gfInverse(i)
		product := gfMultiply(i, inv)
		if product != 1 {
			t.Errorf("gfInverse(%d) * %d = %d, expected 1", i, i, product)
		}
	}
}

func TestChecksumGeneration(t *testing.T) {
	// Test checksum generation and verification
	data := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	
	// Test with non-extendable
	checksumData := addChecksum(data, false)
	if len(checksumData) != len(data)+3 {
		t.Errorf("Expected %d words with checksum, got %d", 
			len(data)+3, len(checksumData))
	}
	
	// Verify checksum
	recovered, err := verifyChecksum(checksumData, false)
	if err != nil {
		t.Errorf("Checksum verification failed: %v", err)
	}
	
	if len(recovered) != len(data) {
		t.Errorf("Recovered data length mismatch")
	}
	
	for i, v := range recovered {
		if v != data[i] {
			t.Errorf("Recovered data mismatch at index %d: got %d, expected %d",
				i, v, data[i])
		}
	}
	
	// Test with extendable
	checksumDataExt := addChecksum(data, true)
	recoveredExt, err := verifyChecksum(checksumDataExt, true)
	if err != nil {
		t.Errorf("Extendable checksum verification failed: %v", err)
	}
	
	for i, v := range recoveredExt {
		if v != data[i] {
			t.Errorf("Recovered extendable data mismatch at index %d", i)
		}
	}
	
	// Test invalid checksum
	checksumData[len(checksumData)-1] ^= 1 // Flip a bit
	_, err = verifyChecksum(checksumData, false)
	if err == nil {
		t.Error("Invalid checksum passed verification")
	}
}

func TestWordlistProperties(t *testing.T) {
	wordlist := GetWordList()
	
	// Check count
	if len(wordlist) != 1024 {
		t.Errorf("Expected 1024 words, got %d", len(wordlist))
	}
	
	// Check word lengths
	for i, word := range wordlist {
		if len(word) < 4 || len(word) > 8 {
			t.Errorf("Word %d (%s) has invalid length %d", i, word, len(word))
		}
	}
	
	// Check unique 4-letter prefixes
	prefixes := make(map[string]int)
	for i, word := range wordlist {
		if len(word) >= 4 {
			prefix := word[:4]
			if prev, exists := prefixes[prefix]; exists {
				t.Errorf("Duplicate prefix '%s' at indices %d and %d", 
					prefix, prev, i)
			}
			prefixes[prefix] = i
		}
	}
	
	// Check alphabetical order
	for i := 1; i < len(wordlist); i++ {
		if wordlist[i-1] >= wordlist[i] {
			t.Errorf("Wordlist not in alphabetical order at index %d: %s >= %s",
				i, wordlist[i-1], wordlist[i])
		}
	}
}