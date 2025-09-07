# Shamir - SLIP-0039 Secret Sharing Tool

A production-ready CLI application implementing **SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes**. Compatible with Trezor and other hardware wallets supporting the SLIP-0039 standard.

## 🔐 Features

### SLIP-0039 Standard (Default)
- **Hierarchical Secret Sharing**: Two-level sharing with groups and members
- **Mnemonic Encoding**: 20 or 33-word shares using custom 1024-word list
- **Passphrase Encryption**: Built-in encryption with plausible deniability
- **Hardware Wallet Compatible**: Works with Trezor Model T and similar devices
- **RS1024 Checksum**: Reed-Solomon error detection
- **Feistel Network**: 4-round encryption with PBKDF2-SHA256

### Additional Features
- **BIP32/BIP44 Key Derivation**: Full HD wallet support
- **BIP39 Mnemonic Generation**: Create standard seed phrases
- **Secure Memory Handling**: Automatic zeroing of sensitive data
- **Flexible Configuration**: Simple or advanced multi-group setups

## 📦 Installation

```bash
go install github.com/Davincible/shamir/cmd/shamir@latest
```

Or build from source:

```bash
git clone https://github.com/Davincible/shamir
cd shamir
go build ./cmd/shamir
```

## 🚀 Quick Start

### Generate and Split a Secret (SLIP-0039)

```bash
# Simple 2-of-3 sharing
shamir split --threshold 2 --shares 3 --length 32

# With passphrase protection
shamir split --threshold 3 --shares 5 --length 32 --passphrase "my secret"

# Advanced: Multiple groups (2 groups required, each with different thresholds)
shamir split --group-threshold 2 --groups "2/3,3/5"
```

### Recover a Secret

```bash
# Interactive recovery
shamir combine

# With passphrase
shamir combine --passphrase "my secret"

# From file
shamir combine --input shares.json
```

## 📖 Commands

### `split` - Create SLIP-0039 Shares

Splits a master secret into mnemonic shares using the SLIP-0039 standard.

**Options:**
- `--threshold, -t`: Minimum shares needed for recovery
- `--shares, -n`: Total number of shares to create
- `--length, -l`: Generate random secret (16 or 32 bytes)
- `--passphrase, -p`: Optional passphrase for encryption
- `--groups`: Advanced group configuration (e.g., "2/3,3/5")
- `--group-threshold`: Number of groups required (advanced mode)
- `--output, -o`: Save shares to JSON file

**Examples:**

```bash
# Basic 2-of-3 sharing
shamir split --threshold 2 --shares 3

# Generate 256-bit secret with 3-of-5 sharing
shamir split -t 3 -n 5 -l 32

# Two groups: need 2-of-3 from first AND 3-of-5 from second
shamir split --group-threshold 2 --groups "2/3,3/5"
```

### `combine` - Recover Secret from Shares

Combines SLIP-0039 mnemonic shares to recover the original secret.

**Options:**
- `--passphrase, -p`: Passphrase used during splitting
- `--input, -i`: Read shares from JSON file
- `--hex`: Output as hexadecimal only
- `--text`: Output as text only

**Examples:**

```bash
# Interactive recovery
shamir combine

# Recover with passphrase
shamir combine --passphrase "my secret"

# From saved file
shamir combine --input backup-shares.json
```

### `derive` - Derive HD Keys

Derive hierarchical deterministic keys from a recovered secret.

**Options:**
- `--path`: BIP32 derivation path
- `--show-private`: Display private key (use with caution)

**Examples:**

```bash
# Derive Ethereum address (Ledger path)
shamir derive --path "m/44'/60'/0'/0/0"

# Derive Bitcoin address
shamir derive --path "m/44'/0'/0'/0/0"
```

### `generate` - Create BIP39 Mnemonic

Generate a new BIP39 mnemonic phrase for wallet creation.

**Options:**
- `--words, -w`: Number of words (12, 15, 18, 21, or 24)

```bash
shamir generate --words 24
```

### `legacy` - Old Implementation

Access the previous non-standard Shamir implementation. Use only for recovering old shares.

```bash
# Recover old shares
shamir legacy combine

# Create old-style shares (not recommended)
shamir legacy split
```

## 🔒 Security Best Practices

### Share Distribution
1. **Physical Separation**: Store each share in a different physical location
2. **Trusted Parties**: Distribute shares to different trusted individuals
3. **Secure Storage**: Use safes, bank vaults, or safety deposit boxes
4. **No Digital Storage**: Avoid storing shares on computers or online

### Operational Security
1. **Air-Gapped Computer**: Run on an offline computer when possible
2. **Verify Recovery**: Always test recovery before distributing shares
3. **Secure Environment**: Use in a private, secure location
4. **Clear Terminal**: Clear terminal history after use

### Passphrase Usage
- Adds an extra layer of security
- Enables plausible deniability (different passphrases = different secrets)
- Should be memorable but strong
- Can be shared separately from shares

## 🏗️ Technical Architecture

### SLIP-0039 Implementation

```
pkg/crypto/slip039/
├── field.go           # GF(256) field arithmetic
├── wordlist.go        # 1024-word SLIP-0039 wordlist
├── checksum.go        # RS1024 Reed-Solomon checksum
├── encryption.go      # Feistel network encryption
├── share.go           # Share encoding/decoding
├── shamir.go          # Core secret sharing logic
└── slip039.go         # High-level API
```

### Cryptographic Details

- **Field**: GF(256) with Rijndael polynomial x⁸ + x⁴ + x³ + x + 1
- **Sharing**: Lagrange interpolation at x=255 for secret
- **Checksum**: RS1024 Reed-Solomon code over GF(1024)
- **Encryption**: 4-round Feistel with PBKDF2-SHA256
- **Iterations**: 10000 × 2^e (configurable exponent)

## 🧪 Examples

### Example 1: Personal Crypto Wallet Backup

```bash
# Generate a new 256-bit master secret and split into 3-of-5 shares
shamir split --threshold 3 --shares 5 --length 32 --passphrase "my_wallet_2024"

# Distribute shares to:
# - Share 1: Personal safe
# - Share 2: Bank safety deposit box
# - Share 3: Trusted family member
# - Share 4: Attorney
# - Share 5: Second secure location

# To recover (need any 3 shares):
shamir combine --passphrase "my_wallet_2024"
```

### Example 2: Multi-Signature Organization Setup

```bash
# Create 2-level sharing: need 2 of 3 groups
# Group 1 (Board): 2 of 3 members
# Group 2 (Executives): 3 of 5 members  
# Group 3 (IT): 1 of 2 members

shamir split \
  --group-threshold 2 \
  --groups "2/3,3/5,1/2" \
  --length 32 \
  --output company-shares.json
```

### Example 3: Hardware Wallet Recovery

```bash
# Split existing Trezor seed (entered interactively)
shamir split --threshold 2 --shares 3

# Later, recover and derive keys
shamir combine
shamir derive --path "m/44'/0'/0'/0/0"  # First Bitcoin address
```

## ⚠️ Important Notes

### SLIP-0039 vs Legacy Mode

| Feature | SLIP-0039 (Default) | Legacy Mode |
|---------|-------------------|--------------|
| Standard | SLIP-0039 | Proprietary |
| Compatibility | Trezor, Hardware Wallets | None |
| Share Format | Mnemonic Words | Hex/Base64 |
| Word Count | 20 or 33 words | N/A |
| Encryption | Built-in | None |
| Checksum | RS1024 | None |
| Groups | Supported | No |

### Migration from Legacy

If you have old shares created with previous versions:

1. Recover using legacy mode: `shamir legacy combine`
2. Create new SLIP-0039 shares: `shamir split`
3. Securely destroy old shares

### Compatibility

- **Hardware Wallets**: Trezor Model T, Trezor Safe 3
- **Standards**: SLIP-0039, BIP-32, BIP-39, BIP-44
- **Platforms**: Linux, macOS, Windows
- **Architecture**: AMD64, ARM64

## 🔧 Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/Davincible/shamir
cd shamir

# Build
go build ./cmd/shamir

# Run tests
go test ./...

# Run with race detector
go test -race ./...
```

### Testing

```bash
# Unit tests
go test ./pkg/crypto/slip039/...

# Integration tests
go test ./test/...

# Benchmarks
go test -bench=. ./pkg/crypto/slip039/...
```

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions are welcome! Please ensure:
- All tests pass
- Code follows Go best practices
- Security implications are considered
- Documentation is updated

## 🔗 References

- [SLIP-0039 Specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
- [BIP-39: Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP-32: Hierarchical Deterministic Wallets](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
- [BIP-44: Multi-Account Hierarchy](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)

## ⚡ Quick Reference

```bash
# Generate and split secret
shamir split -t 2 -n 3 -l 32

# Recover secret
shamir combine

# With passphrase
shamir split -t 2 -n 3 -l 32 -p "secret"
shamir combine -p "secret"

# Save to file
shamir split -t 2 -n 3 -l 32 -o shares.json
shamir combine -i shares.json

# Derive keys
shamir derive --path "m/44'/60'/0'/0/0"  # Ethereum
shamir derive --path "m/44'/0'/0'/0/0"   # Bitcoin

# Legacy mode (old shares only)
shamir legacy combine
```

## 🚨 Security Warning

This software handles cryptographic secrets that could result in permanent loss of cryptocurrency if used incorrectly. Always:

1. Test recovery before relying on shares
2. Store shares securely in separate locations
3. Use passphrases for additional security
4. Keep backups of share locations/holders
5. Understand the security implications

**USE AT YOUR OWN RISK**

---

*Implementing SLIP-0039 v1.0 - Compatible with Trezor and other hardware wallets*