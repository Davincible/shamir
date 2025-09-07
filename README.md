# Shamir - SLIP-0039 Secret Sharing Tool

A production-ready CLI application implementing **SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes**. Compatible with Trezor and other hardware wallets supporting the SLIP-0039 standard.

## 🔐 Features

- **Hierarchical Secret Sharing**: Two-level sharing with groups and members
- **Mnemonic Encoding**: 20 or 33-word shares using 1024-word list
- **Passphrase Encryption**: Built-in encryption with plausible deniability
- **Hardware Wallet Compatible**: Works with Trezor Model T and similar devices
- **RS1024 Checksum**: Reed-Solomon error detection
- **Secure Implementation**: Memory zeroing, constant-time operations

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

### Split a Secret

```bash
# Simple 2-of-3 sharing
shamir split --threshold 2 --shares 3 --length 32

# With passphrase protection
shamir split --threshold 3 --shares 5 --length 32 --passphrase "my secret"

# Advanced: Multiple groups
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

Splits a master secret into mnemonic shares.

**Options:**
- `--threshold, -t`: Minimum shares needed for recovery
- `--shares, -n`: Total number of shares to create
- `--length, -l`: Generate random secret (16 or 32 bytes)
- `--passphrase, -p`: Optional passphrase for encryption
- `--groups`: Advanced group configuration (e.g., "2/3,3/5")
- `--group-threshold`: Number of groups required
- `--secret`: Provide secret as hex string
- `--output, -o`: Save shares to JSON file

### `combine` - Recover Secret

Combines mnemonic shares to recover the original secret.

**Options:**
- `--passphrase, -p`: Passphrase used during splitting
- `--input, -i`: Read shares from JSON file
- `--hex`: Output as hexadecimal only
- `--text`: Output as text only

## 🔒 Security Best Practices

### Share Distribution
1. **Physical Separation**: Store each share in different locations
2. **Trusted Parties**: Distribute to different trusted individuals
3. **Secure Storage**: Use safes, bank vaults, or safety deposit boxes
4. **No Digital Storage**: Avoid storing shares on computers or online

### Operational Security
1. **Air-Gapped Computer**: Run on offline computer when possible
2. **Verify Recovery**: Test recovery before distributing shares
3. **Secure Environment**: Use in private location
4. **Clear Terminal**: Clear history after use

## 🏗️ Technical Details

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

### Cryptographic Specifications

- **Field**: GF(256) with Rijndael polynomial x⁸ + x⁴ + x³ + x + 1
- **Secret Sharing**: Lagrange interpolation at x=255
- **Checksum**: RS1024 Reed-Solomon code over GF(1024)
- **Encryption**: 4-round Feistel with PBKDF2-SHA256
- **Iterations**: 10000 × 2^e (default e=1, so 20000 iterations)

## 🧪 Examples

### Personal Wallet Backup

```bash
# Generate and split 256-bit secret into 3-of-5 shares
shamir split --threshold 3 --shares 5 --length 32 --passphrase "wallet2024"

# Distribute shares:
# - Share 1: Personal safe
# - Share 2: Bank deposit box
# - Share 3: Family member
# - Share 4: Attorney
# - Share 5: Second location

# To recover (need any 3 shares):
shamir combine --passphrase "wallet2024"
```

### Organization Multi-Signature

```bash
# Create 2-level sharing: need 2 of 3 groups
# Group 1: 2 of 3 board members
# Group 2: 3 of 5 executives
# Group 3: 1 of 2 IT admins

shamir split \
  --group-threshold 2 \
  --groups "2/3,3/5,1/2" \
  --length 32 \
  --output company-shares.json
```

## ⚡ Quick Reference

```bash
# Generate and split
shamir split -t 2 -n 3 -l 32

# Recover
shamir combine

# With passphrase
shamir split -t 2 -n 3 -l 32 -p "secret"
shamir combine -p "secret"

# Save/load file
shamir split -t 2 -n 3 -l 32 -o shares.json
shamir combine -i shares.json

# Advanced groups
shamir split --group-threshold 2 --groups "2/3,3/5"
```

## 📋 Share Format

Each share is a mnemonic of 20 words (128-bit secret) or 33 words (256-bit secret) containing:

- **Identifier**: Random 15-bit value (same for all shares)
- **Iteration Exponent**: PBKDF2 iteration count
- **Group Info**: Index, threshold, and count
- **Member Info**: Index and threshold
- **Share Data**: Encrypted secret fragment
- **Checksum**: RS1024 error detection

## 🔧 Development

### Building

```bash
# Build
go build ./cmd/shamir

# Test
go test ./...

# Test with race detection
go test -race ./...

# Benchmarks
go test -bench=. ./pkg/crypto/slip039/...
```

### Testing

```bash
# Unit tests
go test ./pkg/crypto/slip039/...

# Specific test
go test -run TestBasicSplitAndCombine ./pkg/crypto/slip039/

# Coverage
go test -cover ./pkg/crypto/slip039/
```

## ⚠️ Compatibility

- **Hardware Wallets**: Trezor Model T, Trezor Safe 3
- **Standards**: SLIP-0039, PBKDF2, HMAC-SHA256
- **Platforms**: Linux, macOS, Windows
- **Architecture**: AMD64, ARM64

## 🚨 Security Warning

This software handles cryptographic secrets. Incorrect use could result in permanent loss of funds.

**Always:**
1. Test recovery before relying on shares
2. Store shares in separate secure locations
3. Use passphrases for additional security
4. Keep backup of share locations
5. Understand the threshold requirements

**USE AT YOUR OWN RISK**

## 📄 License

MIT License - See LICENSE file for details

## 🔗 References

- [SLIP-0039 Specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
- [Trezor Documentation](https://docs.trezor.io/trezor-firmware/misc/slip0039.html)

---

*Implementing SLIP-0039 v1.0 - Compatible with Trezor hardware wallets*