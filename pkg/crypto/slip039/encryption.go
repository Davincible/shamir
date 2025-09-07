package slip039

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// encrypt encrypts the master secret using a 4-round Feistel network
func encrypt(masterSecret []byte, passphrase string, iterationExponent byte, identifier uint16, extendable bool) ([]byte, error) {
	if len(masterSecret)%2 != 0 {
		return nil, fmt.Errorf("master secret length must be even")
	}
	
	n := len(masterSecret)
	halfN := n / 2
	
	// Split master secret into two halves
	l := make([]byte, halfN)
	r := make([]byte, halfN)
	copy(l, masterSecret[:halfN])
	copy(r, masterSecret[halfN:])
	
	// Perform 4 rounds of Feistel network
	for i := 0; i < 4; i++ {
		f := roundFunction(i, r, passphrase, iterationExponent, identifier, extendable, halfN)
		
		// Swap and XOR
		newL := r
		newR := make([]byte, halfN)
		for j := 0; j < halfN; j++ {
			newR[j] = l[j] ^ f[j]
		}
		
		l = newL
		r = newR
	}
	
	// Encrypted master secret is R || L
	encrypted := make([]byte, n)
	copy(encrypted[:halfN], r)
	copy(encrypted[halfN:], l)
	
	return encrypted, nil
}

// decrypt decrypts the encrypted master secret
func decrypt(encryptedMasterSecret []byte, passphrase string, iterationExponent byte, identifier uint16, extendable bool) ([]byte, error) {
	if len(encryptedMasterSecret)%2 != 0 {
		return nil, fmt.Errorf("encrypted master secret length must be even")
	}
	
	n := len(encryptedMasterSecret)
	halfN := n / 2
	
	// Split encrypted master secret into two halves
	l := make([]byte, halfN)
	r := make([]byte, halfN)
	copy(l, encryptedMasterSecret[:halfN])
	copy(r, encryptedMasterSecret[halfN:])
	
	// Perform 4 rounds of Feistel network in reverse order
	for i := 3; i >= 0; i-- {
		f := roundFunction(i, r, passphrase, iterationExponent, identifier, extendable, halfN)
		
		// Swap and XOR
		newL := r
		newR := make([]byte, halfN)
		for j := 0; j < halfN; j++ {
			newR[j] = l[j] ^ f[j]
		}
		
		l = newL
		r = newR
	}
	
	// Master secret is R || L
	masterSecret := make([]byte, n)
	copy(masterSecret[:halfN], r)
	copy(masterSecret[halfN:], l)
	
	return masterSecret, nil
}

// roundFunction implements the round function F(i, R) for the Feistel network
func roundFunction(round int, r []byte, passphrase string, iterationExponent byte, identifier uint16, extendable bool, outputLen int) []byte {
	// Build salt
	salt := buildSalt(r, identifier, extendable)
	
	// Build password
	password := buildPassword(round, passphrase)
	
	// Calculate iterations: 10000 * 2^e
	iterations := 10000 << iterationExponent
	
	// Derive key using PBKDF2
	return pbkdf2.Key(password, salt, iterations, outputLen, sha256.New)
}

// buildSalt constructs the salt for PBKDF2
func buildSalt(r []byte, identifier uint16, extendable bool) []byte {
	if extendable {
		// If extendable, salt is just R
		return r
	}
	
	// If not extendable, salt is "shamir" || id || R
	salt := make([]byte, 6+2+len(r))
	copy(salt[:6], []byte("shamir"))
	binary.BigEndian.PutUint16(salt[6:8], identifier)
	copy(salt[8:], r)
	
	return salt
}

// buildPassword constructs the password for PBKDF2
func buildPassword(round int, passphrase string) []byte {
	// Password is round number (1 byte) || passphrase
	password := make([]byte, 1+len(passphrase))
	password[0] = byte(round)
	copy(password[1:], []byte(passphrase))
	
	return password
}

// createDigest creates a digest for share verification
func createDigest(secret []byte, sharedRandom []byte) []byte {
	if len(sharedRandom) < 4 {
		panic("shared random must be at least 4 bytes")
	}
	
	// First 4 bytes of HMAC-SHA256(key=sharedRandom, msg=secret)
	h := hmac.New(sha256.New, sharedRandom)
	h.Write(secret)
	digest := h.Sum(nil)
	
	// Concatenate first 4 bytes of digest with the shared random
	result := make([]byte, len(sharedRandom))
	copy(result[:4], digest[:4])
	copy(result[4:], sharedRandom[4:])
	
	return result
}

// verifyDigest verifies the digest matches the secret
func verifyDigest(secret []byte, digest []byte) bool {
	if len(digest) < 4 {
		return false
	}
	
	// Extract shared random (all but first 4 bytes)
	sharedRandom := digest[4:]
	
	// Compute expected digest
	h := hmac.New(sha256.New, sharedRandom)
	h.Write(secret)
	expected := h.Sum(nil)
	
	// Compare first 4 bytes
	return hmac.Equal(digest[:4], expected[:4])
}