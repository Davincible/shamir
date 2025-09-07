# Shamir - Advanced Secret Sharing Tool

A user-friendly CLI for secure secret sharing using **SLIP-0039** (Shamir's Secret Sharing) and **BIP-39** utilities. Split passwords, crypto wallets, and sensitive data into multiple shares for ultimate security.

## 🎯 Key Features

### User-Friendly
- **🧙 Interactive Wizards**: Step-by-step backup and restore guides
- **📚 Built-in Examples**: Learn with practical tutorials
- **✅ Share Validation**: Check compatibility before recovery
- **🎨 Colorized Output**: Clear, readable terminal interface

### Technically Robust
- **SLIP-0039 Standard**: Compatible with Trezor hardware wallets
- **BIP-39 Support**: Generate and manage crypto mnemonics
- **Hierarchical Sharing**: Advanced group-based secret splitting
- **Passphrase Protection**: Additional encryption layer
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

### 🎓 New Users - Start Here!

```bash
# See interactive examples and tutorials
shamir example

# Run the backup wizard (easiest way to start)
shamir backup --test

# Generate wallet addresses (MetaMask, Ledger, etc.)
shamir wallets --list
shamir wallets --preset ethereum --count 5

# Check if your shares work together
shamir check
```

### 💼 Common Use Cases

#### Backup a Crypto Wallet
```bash
# Interactive wizard for BIP-39 mnemonic
shamir backup

# Or directly: 3-of-5 shares with passphrase
shamir split -t 3 -n 5 --passphrase "secure"
```

#### Create Simple 2-of-3 Backup
```bash
# Generate random secret and split
shamir split --threshold 2 --shares 3 --length 32
```

#### Recover Your Secret
```bash
# Interactive restoration
shamir restore

# Or direct recovery
shamir combine
```

#### Verify Shares Before Recovery
```bash
# Check if shares are compatible
shamir check "share1..." "share2..."
```

## 📖 All Commands

### 🔥 New Advanced Features

#### `encrypt` / `decrypt` - File Encryption with Mnemonics
Use BIP-39 mnemonics as memorable encryption keys for files and text.
```bash
# Encrypt a file
shamir encrypt -i document.pdf -o document.pdf.enc

# Decrypt with mnemonic
shamir decrypt -i document.pdf.enc -o document.pdf

# Encrypt text with armor (base64)
echo "secret" | shamir encrypt --armor > secret.txt
```

#### `sign` - Message Signing with Wallet Presets
Sign messages with any wallet address to prove ownership.
```bash
# Sign with MetaMask address
shamir sign -m "I own this" --preset metamask

# Sign with specific wallet index
shamir sign -m "Proof" --preset bitcoin --index 5

# Verify signature
shamir sign --verify --signature "0x..." --public-key "0x..." -m "message"
```

#### `export` - Professional Share Export
Export shares in various formats for printing and storage.
```bash
# Beautiful HTML for printing
shamir export -i backup.json -o shares.html --format html

# CSV for organization
shamir export -i backup.json -o shares.csv --format csv

# Optimized for steel plates
shamir export -i backup.json --format metal
```

#### `qr` - QR Code Generation
Generate QR codes for easy share backup and transfer.
```bash
# Generate QR codes for all shares
shamir qr -i backup.json

# Large QR for printing
shamir qr -i backup.json --size large

# SVG for laser engraving
shamir qr -i backup.json --format svg
```

### 🧙 Interactive Commands (Recommended for Beginners)

#### `wallets` - Generate Wallet Addresses
User-friendly wallet address generation with presets for popular wallets.
```bash
shamir wallets --list                    # Show all presets
shamir wallets --preset ethereum --count 5  # Generate 5 ETH addresses
shamir wallets --preset bitcoin --count 3   # Generate BTC addresses
shamir wallets -i                        # Interactive mode
```

**Supported Wallets:**
- MetaMask, Ledger Live, Trezor
- Ethereum, Bitcoin (Legacy/SegWit/Native SegWit)
- Binance Smart Chain, Polygon, Avalanche
- Custom paths with `--path "m/44'/60'/0'/0/%d"`

#### `backup` - Interactive Backup Wizard
Step-by-step guide to backup secrets or mnemonics.
```bash
shamir backup          # Interactive mode
shamir backup --test   # Practice with test data
```

#### `restore` - Interactive Restore Wizard
Guided recovery from SLIP-0039 shares.
```bash
shamir restore
shamir restore --input backup-dir/
```

#### `check` - Verify Share Compatibility
Check if shares can be combined for recovery.
```bash
shamir check           # Interactive
shamir check "share1" "share2"  # Direct
```

#### `example` - Learn by Example
Practical tutorials for common scenarios.
```bash
shamir example         # Show all examples
shamir example wallet  # Crypto wallet backup
shamir example family  # Estate planning
```

### ⚙️ Core Commands

#### `split` - Create SLIP-0039 Shares

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

#### `combine` - Recover Secret

Combines mnemonic shares to recover the original secret.

**Options:**
- `--passphrase, -p`: Passphrase used during splitting
- `--input, -i`: Read shares from JSON file
- `--hex`: Output as hexadecimal only
- `--text`: Output as text only

### 🔧 BIP-39 Utilities

#### `generate` - Generate BIP-39 Mnemonic

Creates a new BIP-39 mnemonic phrase with optional key derivation.

**Options:**
- `--words, -w`: Number of words (12, 15, 18, 21, or 24)
- `--show-keys`: Display derived public key and address
- `--path`: Derivation path (e.g., "m/44'/60'/0'/0/0" for Ethereum)
- `--json, -j`: Output in JSON format

**Examples:**
```bash
# Generate with Ethereum address
shamir generate --show-keys

# Generate with Bitcoin address
shamir generate --path "m/44'/0'/0'/0/0"
```

#### `derive` - Derive HD Keys

Derives HD keys and addresses from a BIP-39 mnemonic.

**Options:**
- `--path, -p`: BIP-32 derivation path
- `--account, -a`: Account number for Ledger path
- `--show-private`: Show private key (dangerous!)
- `--json, -j`: Output in JSON format

**Features:**
- Automatically generates blockchain addresses
- Shows Ethereum addresses for path containing '/60/'
- Shows Bitcoin addresses for path containing '/0/'
- Displays extended public/private keys

#### `verify` - Verify Mnemonic

Verifies the validity of BIP-39 mnemonics or SLIP-0039 shares.

**Options:**
- `--type`: Mnemonic type (bip39 or slip039, auto-detected)

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

## 💡 Real-World Examples

### 🏠 Personal Use

#### Secure Password Manager Backup
```bash
# Interactive wizard (recommended)
shamir backup

# Choose option 2 (raw secret)
# Enter your master password
# Select "Simple 2-of-3"
# Store shares in different locations
```

#### Crypto Wallet Protection
```bash
# For existing BIP-39 mnemonic
shamir backup
# Choose option 1, enter your 12-24 words

# Quick 3-of-5 split
shamir split -t 3 -n 5 --passphrase "secure2024"
```

### 👨‍👩‍👧‍👦 Family & Estate Planning

```bash
# See detailed family example
shamir example family

# Quick setup: 2 groups needed
shamir split \
  --group-threshold 2 \
  --groups "1/2,2/3,1/1" \
  --passphrase
```

### 🏢 Business Use

```bash
# See corporate example
shamir example company

# Multi-department control
shamir split \
  --group-threshold 2 \
  --groups "2/3,2/4,1/2" \
  --output recovery-plan.json
```

## ⚡ Quick Reference

```bash
# 🎓 Learning
shamir example              # Show tutorials
shamir backup --test        # Practice mode

# 🔐 Basic Operations
shamir split -t 2 -n 3 -l 32      # Create 2-of-3 shares
shamir combine                     # Recover secret
shamir check                       # Verify shares

# 🛡️ With Passphrase
shamir split -t 2 -n 3 -p "pass"  # Split with passphrase
shamir combine -p "pass"           # Recover with passphrase

# 💾 File Operations
shamir split -o backup.json        # Save to file
shamir combine -i backup.json      # Load from file
shamir restore --input backup/     # Restore from directory

# 🏢 Advanced Groups
shamir split --group-threshold 2 --groups "2/3,3/5"

# 🪙 Crypto Tools
shamir generate --words 24 --show-keys    # BIP-39 with address
shamir wallets --preset metamask --count 5 # Generate addresses
shamir wallets --list                      # Show wallet presets
shamir derive --path "m/44'/60'/0'/0/0"   # Derive specific key
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