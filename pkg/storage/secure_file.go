package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Davincible/shamir/pkg/secure"
	"golang.org/x/crypto/pbkdf2"
)

const (
	SaltSize   = 32
	NonceSize  = 12
	KeySize    = 32
	Iterations = 100000
)

type SecureStorage struct {
	filepath string
}

type EncryptedData struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func NewSecureStorage(filepath string) *SecureStorage {
	return &SecureStorage{
		filepath: filepath,
	}
}

func (s *SecureStorage) Save(data []byte, password []byte) error {
	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	key := pbkdf2.Key(password, salt, Iterations, KeySize, sha256.New)
	defer secure.Zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, data, nil)

	encrypted := EncryptedData{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	jsonData, err := json.Marshal(encrypted)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted data: %w", err)
	}

	dir := filepath.Dir(s.filepath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	if err := os.WriteFile(s.filepath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func (s *SecureStorage) Load(password []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	jsonData, err := os.ReadFile(s.filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var encrypted EncryptedData
	if err := json.Unmarshal(jsonData, &encrypted); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted data: %w", err)
	}

	key := pbkdf2.Key(password, encrypted.Salt, Iterations, KeySize, sha256.New)
	defer secure.Zero(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, encrypted.Nonce, encrypted.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func (s *SecureStorage) Exists() bool {
	_, err := os.Stat(s.filepath)
	return err == nil
}

func (s *SecureStorage) Delete() error {
	if !s.Exists() {
		return nil
	}

	data, err := os.ReadFile(s.filepath)
	if err != nil {
		return fmt.Errorf("failed to read file for secure deletion: %w", err)
	}

	if _, err := rand.Read(data); err != nil {
		return fmt.Errorf("failed to overwrite file: %w", err)
	}

	if err := os.WriteFile(s.filepath, data, 0600); err != nil {
		return fmt.Errorf("failed to overwrite file: %w", err)
	}

	return os.Remove(s.filepath)
}

type ShareStorage struct {
	storage *SecureStorage
}

type StoredShares struct {
	Shares    [][]byte          `json:"shares"`
	Threshold int               `json:"threshold"`
	Total     int               `json:"total"`
	Metadata  map[string]string `json:"metadata"`
}

func NewShareStorage(filepath string) *ShareStorage {
	return &ShareStorage{
		storage: NewSecureStorage(filepath),
	}
}

func (s *ShareStorage) SaveShares(shares [][]byte, threshold, total int, password []byte) error {
	stored := StoredShares{
		Shares:    shares,
		Threshold: threshold,
		Total:     total,
		Metadata:  make(map[string]string),
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return fmt.Errorf("failed to marshal shares: %w", err)
	}

	return s.storage.Save(data, password)
}

func (s *ShareStorage) LoadShares(password []byte) (*StoredShares, error) {
	data, err := s.storage.Load(password)
	if err != nil {
		return nil, err
	}

	var stored StoredShares
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("failed to unmarshal shares: %w", err)
	}

	return &stored, nil
}

func (s *ShareStorage) Exists() bool {
	return s.storage.Exists()
}

func (s *ShareStorage) Delete() error {
	return s.storage.Delete()
}
