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
	// Build salt prefix
	saltPrefix := buildSaltPrefix(identifier, extendable)
	
	// Salt = salt_prefix + R (as per reference implementation)
	salt := make([]byte, len(saltPrefix)+len(r))
	copy(salt, saltPrefix)
	copy(salt[len(saltPrefix):], r)
	
	// Build password
	password := buildPassword(round, passphrase)
	
	// Calculate iterations: (10000 << e) // 4 = 2500 << e (as per reference implementation)
	iterations := 2500 << iterationExponent
	
	// Derive key using PBKDF2
	return pbkdf2.Key(password, salt, iterations, outputLen, sha256.New)
}

// buildSaltPrefix constructs the salt prefix for PBKDF2 (before R is appended)
func buildSaltPrefix(identifier uint16, extendable bool) []byte {
	if extendable {
		// If extendable, no salt prefix
		return []byte{}
	}
	
	// If not extendable, salt prefix is "shamir" || id
	saltPrefix := make([]byte, 6+2)
	copy(saltPrefix[:6], []byte("shamir"))
	binary.BigEndian.PutUint16(saltPrefix[6:8], identifier)
	
	return saltPrefix
}

// buildPassword constructs the password for PBKDF2
func buildPassword(round int, passphrase string) []byte {
	// Password is round number (1 byte) || passphrase
	password := make([]byte, 1+len(passphrase))
	password[0] = byte(round)
	copy(password[1:], []byte(passphrase))
	
	return password
}

// createDigest creates a digest for share verification according to SLIP-0039 spec
// D = first 4 bytes of HMAC-SHA256(key=R, msg=S) || R
func createDigest(secret []byte, R []byte) []byte {
	// First 4 bytes of HMAC-SHA256(key=R, msg=secret)
	h := hmac.New(sha256.New, R)
	h.Write(secret)
	hmacResult := h.Sum(nil)
	
	// Concatenate first 4 bytes of HMAC with R
	result := make([]byte, 4+len(R))
	copy(result[:4], hmacResult[:4])
	copy(result[4:], R)
	
	return result
}

// verifyDigest verifies the digest matches the secret according to SLIP-0039 spec
func verifyDigest(secret []byte, digest []byte) bool {
	if len(digest) < 4 {
		return false
	}
	
	// Extract R (all bytes after first 4)
	R := digest[4:]
	
	// Compute expected HMAC
	h := hmac.New(sha256.New, R)
	h.Write(secret)
	expected := h.Sum(nil)
	
	// Compare first 4 bytes of HMAC with first 4 bytes of digest
	return hmac.Equal(digest[:4], expected[:4])
}