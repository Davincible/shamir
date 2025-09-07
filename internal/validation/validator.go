package validation

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

var (
	hexPattern  = regexp.MustCompile(`^[0-9a-fA-F]+$`)
	pathPattern = regexp.MustCompile(`^[mM](/\d+'?)+$`)
)

func ValidateHex(input string) error {
	input = strings.TrimSpace(input)
	if len(input) == 0 {
		return fmt.Errorf("hex string cannot be empty")
	}

	if len(input)%2 != 0 {
		return fmt.Errorf("hex string must have even length")
	}

	if !hexPattern.MatchString(input) {
		return fmt.Errorf("invalid hex characters")
	}

	return nil
}

func ValidateShare(share string) error {
	if err := ValidateHex(share); err != nil {
		return fmt.Errorf("invalid share format: %w", err)
	}

	data, err := hex.DecodeString(share)
	if err != nil {
		return fmt.Errorf("failed to decode share: %w", err)
	}

	if len(data) < 2 {
		return fmt.Errorf("share is too short")
	}

	return nil
}

func ValidateMnemonic(words string) error {
	words = strings.TrimSpace(words)
	if words == "" {
		return fmt.Errorf("mnemonic cannot be empty")
	}

	wordList := strings.Fields(words)
	wordCount := len(wordList)

	validCounts := []int{12, 15, 18, 21, 24}
	valid := false
	for _, count := range validCounts {
		if wordCount == count {
			valid = true
			break
		}
	}

	if !valid {
		return fmt.Errorf("mnemonic must have 12, 15, 18, 21, or 24 words (got %d)", wordCount)
	}

	for i, word := range wordList {
		if len(word) < 3 || len(word) > 8 {
			return fmt.Errorf("word %d has invalid length: %s", i+1, word)
		}

		for _, ch := range word {
			if ch < 'a' || ch > 'z' {
				return fmt.Errorf("word %d contains invalid characters: %s", i+1, word)
			}
		}
	}

	return nil
}

func ValidateDerivationPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("derivation path cannot be empty")
	}

	if !pathPattern.MatchString(path) {
		return fmt.Errorf("invalid derivation path format")
	}

	segments := strings.Split(path, "/")[1:]
	for i, segment := range segments {
		if segment == "" {
			return fmt.Errorf("empty segment at position %d", i)
		}
	}

	return nil
}

func ValidateSplitParams(parts, threshold int) error {
	if parts < 2 || parts > 255 {
		return fmt.Errorf("parts must be between 2 and 255 (got %d)", parts)
	}

	if threshold < 2 || threshold > parts {
		return fmt.Errorf("threshold must be between 2 and %d (got %d)", parts, threshold)
	}

	return nil
}

func ValidatePassphrase(passphrase string) error {
	if len(passphrase) > 256 {
		return fmt.Errorf("passphrase too long (max 256 characters)")
	}

	for i, ch := range passphrase {
		if ch == 0 {
			return fmt.Errorf("passphrase contains null character at position %d", i)
		}

		if ch > 0x10FFFF {
			return fmt.Errorf("passphrase contains invalid Unicode at position %d", i)
		}
	}

	return nil
}

func SanitizeInput(input string) string {
	input = strings.TrimSpace(input)

	input = strings.ReplaceAll(input, "\r\n", "\n")
	input = strings.ReplaceAll(input, "\r", "\n")

	lines := strings.Split(input, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}

	return strings.Join(lines, "\n")
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

func ValidateEntropySize(size int) bool {
	validSizes := []int{16, 20, 24, 28, 32}
	for _, valid := range validSizes {
		if size == valid {
			return true
		}
	}
	return false
}
