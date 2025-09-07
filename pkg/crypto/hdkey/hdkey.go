package hdkey

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/tyler-smith/go-bip32"
)

const (
	HardenedKeyOffset = uint32(0x80000000)

	PurposeBIP44 = uint32(44)
	PurposeBIP49 = uint32(49)
	PurposeBIP84 = uint32(84)

	CoinTypeBitcoin  = uint32(0)
	CoinTypeEthereum = uint32(60)
	CoinTypeLitecoin = uint32(2)
)

type HDKey struct {
	key        *bip32.Key
	path       string
	isHardened bool
}

type DerivationPath struct {
	Purpose  uint32
	CoinType uint32
	Account  uint32
	Change   uint32
	Index    uint32
}

func NewMasterKey(seed []byte) (*HDKey, error) {
	if len(seed) < 16 {
		return nil, fmt.Errorf("seed must be at least 16 bytes")
	}

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	return &HDKey{
		key:  masterKey,
		path: "m",
	}, nil
}

func FromExtendedKey(xkey string) (*HDKey, error) {
	key, err := bip32.B58Deserialize(xkey)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize extended key: %w", err)
	}

	return &HDKey{
		key:  key,
		path: "",
	}, nil
}

func (h *HDKey) DerivePath(path string) (*HDKey, error) {
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "m/") && !strings.HasPrefix(path, "M/") {
		return nil, fmt.Errorf("path must start with 'm/' or 'M/'")
	}

	segments := strings.Split(path, "/")[1:]
	currentKey := h.key

	for _, segment := range segments {
		if segment == "" {
			continue
		}

		hardened := strings.HasSuffix(segment, "'") || strings.HasSuffix(segment, "h")
		if hardened {
			segment = strings.TrimSuffix(strings.TrimSuffix(segment, "'"), "h")
		}

		index, err := strconv.ParseUint(segment, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid path segment '%s': %w", segment, err)
		}

		childIndex := uint32(index)
		if hardened {
			childIndex += HardenedKeyOffset
		}

		newKey, err := currentKey.NewChildKey(childIndex)
		if err != nil {
			return nil, fmt.Errorf("failed to derive child key at index %d: %w", childIndex, err)
		}

		currentKey = newKey
	}

	return &HDKey{
		key:  currentKey,
		path: path,
	}, nil
}

func (h *HDKey) DeriveAccount(purpose, coinType, account uint32) (*HDKey, error) {
	path := fmt.Sprintf("m/%d'/%d'/%d'", purpose, coinType, account)
	return h.DerivePath(path)
}

func (h *HDKey) DeriveLedgerPath(account uint32) (*HDKey, error) {
	return h.DeriveAccount(PurposeBIP44, CoinTypeEthereum, account)
}

func (h *HDKey) DeriveAddress(change, index uint32) (*HDKey, error) {
	changeKey, err := h.key.NewChildKey(change)
	if err != nil {
		return nil, fmt.Errorf("failed to derive change key: %w", err)
	}

	addressKey, err := changeKey.NewChildKey(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive address key: %w", err)
	}

	path := fmt.Sprintf("%s/%d/%d", h.path, change, index)
	return &HDKey{
		key:  addressKey,
		path: path,
	}, nil
}

func (h *HDKey) PublicKey() []byte {
	return h.key.PublicKey().Key
}

func (h *HDKey) PublicKeyHex() string {
	return hex.EncodeToString(h.PublicKey())
}

func (h *HDKey) PrivateKey() []byte {
	return h.key.Key
}

func (h *HDKey) PrivateKeyHex() string {
	return hex.EncodeToString(h.PrivateKey())
}

func (h *HDKey) ExtendedPublicKey() string {
	return h.key.PublicKey().String()
}

func (h *HDKey) ExtendedPrivateKey() string {
	return h.key.String()
}

func (h *HDKey) Fingerprint() []byte {
	return h.key.FingerPrint
}

func (h *HDKey) ChainCode() []byte {
	return h.key.ChainCode
}

func (h *HDKey) Path() string {
	return h.path
}

func (h *HDKey) IsPrivate() bool {
	return h.key.IsPrivate
}

func ParseDerivationPath(path string) (*DerivationPath, error) {
	path = strings.TrimSpace(path)
	if !strings.HasPrefix(path, "m/") && !strings.HasPrefix(path, "M/") {
		return nil, fmt.Errorf("path must start with 'm/' or 'M/'")
	}

	segments := strings.Split(path, "/")[1:]
	if len(segments) < 3 {
		return nil, fmt.Errorf("incomplete derivation path")
	}

	dp := &DerivationPath{}

	for i, segment := range segments[:5] {
		if segment == "" {
			continue
		}

		hardened := strings.HasSuffix(segment, "'") || strings.HasSuffix(segment, "h")
		if hardened {
			segment = strings.TrimSuffix(strings.TrimSuffix(segment, "'"), "h")
		}

		value, err := strconv.ParseUint(segment, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid segment '%s': %w", segment, err)
		}

		switch i {
		case 0:
			dp.Purpose = uint32(value)
		case 1:
			dp.CoinType = uint32(value)
		case 2:
			dp.Account = uint32(value)
		case 3:
			dp.Change = uint32(value)
		case 4:
			dp.Index = uint32(value)
		}
	}

	return dp, nil
}

func (dp *DerivationPath) String() string {
	return fmt.Sprintf("m/%d'/%d'/%d'/%d/%d",
		dp.Purpose, dp.CoinType, dp.Account, dp.Change, dp.Index)
}

func GenerateMasterKey(seed []byte) ([]byte, []byte, error) {
	hmacKey := []byte("Bitcoin seed")
	mac := hmac.New(sha512.New, hmacKey)
	mac.Write(seed)
	result := mac.Sum(nil)

	privateKey := result[:32]
	chainCode := result[32:]

	return privateKey, chainCode, nil
}

func ValidatePath(path string) error {
	_, err := ParseDerivationPath(path)
	return err
}
