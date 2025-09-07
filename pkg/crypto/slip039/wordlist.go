package slip039

import (
	_ "embed"
	"fmt"
	"strings"
)

//go:embed wordlist.txt
var wordlistData string

var (
	// wordList contains the 1024 words used in SLIP-0039
	wordList []string
	// wordMap maps words to their indices
	wordMap map[string]int
)

func init() {
	// Initialize wordlist from embedded data
	wordList = strings.Split(strings.TrimSpace(wordlistData), "\n")
	
	if len(wordList) != 1024 {
		panic(fmt.Sprintf("SLIP-0039 wordlist must contain exactly 1024 words, got %d", len(wordList)))
	}
	
	// Build word to index map
	wordMap = make(map[string]int, 1024)
	for i, word := range wordList {
		wordMap[word] = i
	}
	
	// Validate wordlist properties
	validateWordlist()
}

// validateWordlist ensures the wordlist meets SLIP-0039 requirements
func validateWordlist() {
	// Check word lengths (4-8 characters)
	for i, word := range wordList {
		if len(word) < 4 || len(word) > 8 {
			panic(fmt.Sprintf("word %d (%s) has invalid length %d", i, word, len(word)))
		}
	}
	
	// Check unique 4-letter prefixes
	prefixes := make(map[string]bool)
	for i, word := range wordList {
		if len(word) < 4 {
			continue
		}
		prefix := word[:4]
		if prefixes[prefix] {
			panic(fmt.Sprintf("duplicate 4-letter prefix %s at word %d (%s)", prefix, i, word))
		}
		prefixes[prefix] = true
	}
}

// wordToIndex returns the index of a word in the wordlist
func wordToIndex(word string) (int, error) {
	word = strings.ToLower(strings.TrimSpace(word))
	
	// First try exact match
	if idx, ok := wordMap[word]; ok {
		return idx, nil
	}
	
	// If word is at least 4 characters, try prefix match
	if len(word) >= 4 {
		prefix := word[:4]
		for i, w := range wordList {
			if strings.HasPrefix(w, prefix) {
				return i, nil
			}
		}
	}
	
	return -1, fmt.Errorf("word '%s' not found in wordlist", word)
}

// indexToWord returns the word at the given index
func indexToWord(index int) (string, error) {
	if index < 0 || index >= 1024 {
		return "", fmt.Errorf("index %d out of range [0, 1023]", index)
	}
	return wordList[index], nil
}

// mnemonicToIndices converts a mnemonic phrase to a list of word indices
func mnemonicToIndices(mnemonic string) ([]int, error) {
	words := strings.Fields(strings.TrimSpace(mnemonic))
	if len(words) == 0 {
		return nil, fmt.Errorf("empty mnemonic")
	}
	
	indices := make([]int, len(words))
	for i, word := range words {
		idx, err := wordToIndex(word)
		if err != nil {
			return nil, fmt.Errorf("word %d: %w", i+1, err)
		}
		indices[i] = idx
	}
	
	return indices, nil
}

// indicesToMnemonic converts a list of word indices to a mnemonic phrase
func indicesToMnemonic(indices []int) (string, error) {
	words := make([]string, len(indices))
	for i, idx := range indices {
		word, err := indexToWord(idx)
		if err != nil {
			return "", fmt.Errorf("index %d: %w", i, err)
		}
		words[i] = word
	}
	
	return strings.Join(words, " "), nil
}

// GetWordList returns a copy of the wordlist
func GetWordList() []string {
	result := make([]string, len(wordList))
	copy(result, wordList)
	return result
}

// IsValidWord checks if a word is in the SLIP-0039 wordlist
func IsValidWord(word string) bool {
	_, err := wordToIndex(word)
	return err == nil
}