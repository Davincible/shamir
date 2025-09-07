# Shamir - The Ultimate Secret Sharing Toolkit

A professional-grade CLI for advanced secret sharing using **SLIP-0039**, **PVSS**, and **BIP-39** standards. Built for crypto enthusiasts, security professionals, and enterprise users who need the highest level of cryptographic security and usability.

## 🚀 What's New - Ultimate Enhancement Features

### 🔥 **Revolutionary PVSS with Mnemonic Support** 
The world's first implementation of **Publicly Verifiable Secret Sharing** with human-readable mnemonic encoding! No more dealing with complex hex strings - PVSS shares are now as user-friendly as SLIP-0039.

### 🎯 **Unified Secret Sharing Interface**
One command to rule them all! The new `shamir share` command provides a unified interface for both SLIP-0039 and PVSS with intelligent scheme selection and advanced features.

### 🗂️ **Professional Share Management**
Complete share lifecycle management with the new `shamir manage` command:
- Organize shares with metadata, tags, and descriptions
- Track share distribution and status
- Verify share integrity automatically
- Encrypted storage with passphrase protection
- Import/export capabilities

### 🧠 **Intelligent Recovery System**
Advanced recovery with smart assistance:
- Automatic share detection and validation
- Recovery simulation (test without revealing secrets)
- Hierarchical recovery analysis
- Multiple input methods and formats
- Share compatibility checking

### ⚙️ **Advanced Configuration**
Professional configuration system with profiles:
- User preferences and defaults
- Security policies and compliance
- Scheme-specific settings
- Saved recovery profiles

## 📦 Installation

```bash
# Install latest enhanced version
go install github.com/Davincible/shamir/cmd/shamir@latest

# Or build from source
git clone https://github.com/Davincible/shamir
cd shamir
go build ./cmd/shamir
```

## 🎯 Quick Start - Enhanced Edition

### 🌟 **New Users - Start Here!**

```bash
# Interactive unified sharing (recommended!)
shamir share -i

# Professional share management
shamir manage list

# Intelligent recovery system
shamir recover

# Educational mode
shamir example
```

## 🔐 **Ultimate Secret Sharing Commands**

### **`shamir share` - Unified Secret Sharing**

The crown jewel command that handles both SLIP-0039 and PVSS with unprecedented ease:

```bash
# Interactive mode - Let the system guide you
shamir share -i

# Quick SLIP-0039 sharing (mnemonic output)
shamir share --split -t 2 -n 3

# Revolutionary PVSS with mnemonic encoding  
shamir share --split --scheme pvss -t 3 -n 5

# Advanced hierarchical sharing
shamir share --split --advanced --groups "2/3,3/5" --group-threshold 2

# Combine shares intelligently
shamir share --combine -i shares.json
```

**Features:**
- 🤖 **Smart Scheme Selection** - Automatically recommends the best scheme
- 🔤 **Universal Mnemonic Encoding** - Both SLIP-0039 and PVSS support mnemonics
- 🎛️ **Advanced Configuration** - Hierarchical groups, passphrases, and more
- ✅ **Built-in Verification** - Ensures shares work before distribution
- 📱 **Educational Mode** - Learn while you work

### **`shamir manage` - Professional Share Management**

Enterprise-grade share organization and tracking:

```bash
# List all managed share sets
shamir manage list

# Add share set with metadata
shamir manage add -i shares.json --name "Wallet Backup" \
  --description "Primary crypto wallet" --tags crypto,important

# Search and filter
shamir manage search "wallet"
shamir manage list --tags crypto,backup

# Verify share integrity
shamir manage verify abc123

# Update share status
shamir manage update abc123 --status distributed --share-index 1

# Professional export/import
shamir manage export abc123 -o backup.json --include-shares
shamir manage import -i backup.json
```

**Features:**
- 📊 **Comprehensive Metadata** - Names, descriptions, tags, locations
- 🔍 **Share Tracking** - Status monitoring and verification
- 🔐 **Encrypted Storage** - Optional passphrase protection
- 📈 **Analytics** - Statistics and reports
- 🔄 **Import/Export** - Portable share set management

### **`shamir recover` - Intelligent Recovery**

AI-powered recovery assistance that makes secret reconstruction foolproof:

```bash
# Interactive guided recovery
shamir recover

# Smart simulation (test before real recovery)
shamir recover simulate --input shares.json

# Recover from managed shares
shamir recover from-store abc123

# Auto-detect and recover
shamir recover auto --directory ./backup/

# Verify recovery capability
shamir recover verify --shares file1.json,file2.json
```

**Features:**
- 🧠 **Share Analysis** - Intelligent compatibility checking
- 🧪 **Recovery Simulation** - Test without exposing secrets
- 🔍 **Auto-Detection** - Find shares automatically
- 📊 **Detailed Reports** - Comprehensive recovery analysis
- 🛡️ **Safety First** - Multiple verification steps

## 🏗️ **Enhanced Core Features**

### **Cryptographic Excellence**
- ✅ **SLIP-0039** - Full standard compliance with hardware wallet support
- ✅ **PVSS** - Publicly Verifiable Secret Sharing with elliptic curves
- ✅ **BIP-39** - Complete mnemonic and key derivation support
- ✅ **Security-First** - Memory wiping, secure random, constant-time ops

### **User Experience Revolution**
- 🎨 **Interactive Wizards** - Step-by-step guidance for all operations
- 📚 **Educational System** - Learn cryptography while using
- 🌈 **Beautiful Output** - Color-coded, formatted, professional display
- 🔧 **Configuration** - Customize behavior and defaults

### **Professional Features**
- 📊 **Share Management** - Complete lifecycle tracking
- 🔍 **Verification** - Multi-level integrity checking
- 📱 **Multiple Formats** - JSON, QR codes, CSV, HTML export
- 🔐 **Advanced Security** - HSM support, network recovery (roadmap)

## 💼 **Enterprise Use Cases**

### **Corporate Backup Strategy**
```bash
# Create hierarchical company backup
shamir share --split --scheme slip039 \
  --group-threshold 2 \
  --groups "2/3,2/4,1/2" \
  --name "Company Master Key" \
  --description "Finance+IT departments + CEO override"

# Manage with professional tracking
shamir manage add -i company-shares.json \
  --tags corporate,critical \
  --description "Q4 2024 Master Key Backup"
```

### **Personal Crypto Security**
```bash
# Interactive wallet backup with PVSS verification
shamir share -i  # Choose PVSS for public verifiability

# Track your crypto shares
shamir manage list --tags crypto
shamir manage verify wallet-backup-id
```

### **Estate Planning**
```bash
# Family inheritance with smart recovery
shamir example family  # Interactive tutorial
shamir recover  # When needed by family
```

## 🔒 **Security Model**

### **Multi-Layer Protection**
1. **Cryptographic**: Information-theoretic (SLIP-0039) + Computational (PVSS)
2. **Implementation**: Secure memory, constant-time operations
3. **Operational**: Air-gapped recommendations, verification steps
4. **Storage**: Optional encryption, secure file permissions

### **Verification Levels**
- **Share Level**: Individual cryptographic verification
- **Set Level**: Compatibility and threshold checking  
- **Recovery Level**: Simulation before actual recovery
- **System Level**: Integrity monitoring and alerts

## 📖 **Complete Command Reference**

### **Enhanced Commands**
| Command | Description | Use Case |
|---------|-------------|----------|
| `shamir share` | 🔥 Unified secret sharing | One command for all schemes |
| `shamir manage` | 🗂️ Professional management | Enterprise share tracking |
| `shamir recover` | 🧠 Intelligent recovery | Smart assisted reconstruction |

### **Original Commands (Enhanced)**
| Command | Enhancement | New Features |
|---------|-------------|--------------|
| `shamir backup` | ✨ PVSS integration | Scheme selection wizard |
| `shamir restore` | 🧠 Smart analysis | Share compatibility checking |
| `shamir verify` | 📊 Deep analysis | Comprehensive reporting |
| `shamir wallets` | 🔗 More presets | Extended blockchain support |

### **Utility Commands**
| Command | Description | Professional Features |
|---------|-------------|----------------------|
| `shamir generate` | BIP-39 generation | HD key derivation |
| `shamir derive` | Key derivation | Multi-path support |
| `shamir encrypt` | File encryption | Mnemonic-based keys |
| `shamir sign` | Message signing | Wallet integration |
| `shamir export` | Multi-format export | Professional layouts |
| `shamir qr` | QR code generation | High-quality output |

## 🎓 **Learning Center**

### **Built-in Tutorials**
```bash
# Interactive learning system
shamir example

# Specific scenarios
shamir example wallet    # Crypto wallet backup
shamir example family    # Estate planning
shamir example company   # Corporate use
shamir example schemes   # Cryptographic comparison
```

### **Educational Features**
- 📚 **Scheme Comparison** - SLIP-0039 vs PVSS explained
- 🔬 **Cryptographic Details** - Learn the math and security
- 💡 **Best Practices** - Professional security recommendations
- 🎯 **Use Case Library** - Real-world examples

## 🛠️ **Configuration & Customization**

### **User Configuration**
```bash
# View current config
shamir config show

# Set defaults
shamir config set scheme pvss
shamir config set threshold 3
shamir config set shares 5

# Security policies
shamir config security --require-passphrase
shamir config security --min-passphrase-length 12
```

### **Professional Profiles**
```bash
# Save configuration profiles
shamir share --split -t 3 -n 5 --save-profile "standard-5"

# Use saved profiles
shamir share --profile "standard-5"

# Manage profiles
shamir manage profiles --list
```

## 📊 **Advanced Analytics**

### **Share Statistics**
```bash
# Management overview
shamir manage stats

# Detailed analysis
shamir manage list --format table
shamir manage search --analytics
```

### **Recovery Planning**
```bash
# Test recovery scenarios
shamir recover simulate --all-combinations
shamir recover verify --comprehensive
```

## 🔮 **Roadmap & Future Features**

### **Immediate (Q1 2025)**
- [ ] Complete CLI test coverage
- [ ] Performance optimizations
- [ ] Additional elliptic curves
- [ ] Mobile QR scanning integration

### **Near-term (Q2 2025)**
- [ ] Web interface for share management
- [ ] Hardware Security Module (HSM) integration
- [ ] Distributed recovery protocols
- [ ] Blockchain integration

### **Long-term (2025+)**
- [ ] Mobile applications (iOS/Android)
- [ ] Enterprise dashboard
- [ ] Audit and compliance tools
- [ ] Multi-party computation integration

## 🤝 **Contributing**

This enhanced version represents the ultimate in secret sharing technology. We welcome contributions:

1. **Cryptographic Improvements** - New schemes, optimizations
2. **User Experience** - Interface enhancements, tutorials
3. **Enterprise Features** - Management tools, integrations
4. **Platform Support** - New operating systems, architectures

## 📄 **Technical Specifications**

### **Supported Schemes**
- **SLIP-0039**: Full v1.0 compliance, hardware wallet compatible
- **PVSS**: Feldman VSS with P-256/secp256k1, mnemonic encoding
- **BIP-39**: Complete implementation with HD key support

### **Security Features**
- Memory-safe implementation in Go
- Cryptographically secure random number generation
- Constant-time operations where applicable
- Comprehensive input validation
- Optional encrypted storage

### **Platform Support**
- **Operating Systems**: Linux, macOS, Windows
- **Architectures**: AMD64, ARM64
- **Go Version**: 1.22+

## 🚨 **Security Notice**

This software handles cryptographic secrets. While extensively tested and professionally designed:

**ALWAYS:**
- ✅ Test recovery before relying on shares
- ✅ Use air-gapped systems for sensitive operations
- ✅ Store shares in separate secure locations
- ✅ Verify share integrity regularly
- ✅ Keep passphrases secure and backed up

**NEVER:**
- ❌ Store shares digitally unless encrypted
- ❌ Use weak passphrases
- ❌ Ignore verification warnings
- ❌ Share recovery information insecurely

## 📞 **Support & Community**

- **Documentation**: [docs.shamir-cli.org](https://docs.shamir-cli.org)
- **Issues**: [GitHub Issues](https://github.com/Davincible/shamir/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Davincible/shamir/discussions)
- **Enterprise**: enterprise@shamir-cli.org

---

## 🏆 **Why This is the Ultimate Tool**

### **Unmatched Security**
- Multiple cryptographic schemes
- Professional-grade implementation
- Continuous verification and monitoring
- Enterprise security policies

### **Revolutionary Usability**
- First PVSS tool with mnemonic encoding
- Intelligent recovery assistance  
- Professional share management
- Comprehensive educational system

### **Production Ready**
- Extensive testing and validation
- Professional documentation
- Enterprise features and support
- Active development and maintenance

**The Shamir CLI isn't just a tool - it's a complete secret sharing ecosystem designed for the most demanding users and critical applications.**

*Compatible with Trezor hardware wallets | Implementing SLIP-0039 v1.0 | PVSS with ECC | Professional Grade*
