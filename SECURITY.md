# Security Policy

## 🔒 Security Model

This document outlines the security considerations, threat model, and best practices for the Shamir wallet backup tool.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability, please:

1. **DO NOT** open a public issue
2. Email security details to: [security@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide updates every 72 hours.

## Cryptographic Implementation

### Algorithms Used

- **Shamir's Secret Sharing**: HashiCorp Vault implementation
- **Mnemonic Generation**: BIP39 standard
- **Key Derivation**: BIP32/BIP44 HD wallet standard
- **Encryption**: AES-256-GCM for storage
- **Key Stretching**: PBKDF2 with 100,000 iterations
- **Random Generation**: crypto/rand (system CSPRNG)

### Security Properties

#### Confidentiality
- Secrets are split using Shamir's Secret Sharing
- Individual shares reveal no information about the secret
- Storage uses AES-256-GCM authenticated encryption

#### Integrity
- GCM mode provides authenticated encryption
- Share verification ensures data integrity
- Mnemonic checksums validate word lists

#### Availability
- Threshold reconstruction ensures redundancy
- Multiple shares can be lost without data loss
- No single point of failure

## Threat Model

### In Scope Threats

1. **Physical Loss**
   - Mitigation: Multiple shares in different locations
   
2. **Partial Compromise**
   - Mitigation: Threshold scheme requires minimum shares
   
3. **Memory Forensics**
   - Mitigation: Secure zeroing of sensitive data
   
4. **Timing Attacks**
   - Mitigation: Constant-time comparison operations
   
5. **Weak Randomness**
   - Mitigation: System CSPRNG via crypto/rand

### Out of Scope Threats

1. **Compromised System**
   - If the system is compromised during generation or reconstruction, secrets may be exposed
   
2. **Physical Access to Threshold Shares**
   - Physical security of shares is user's responsibility
   
3. **Social Engineering**
   - Users must protect share locations and access
   
4. **Quantum Computing**
   - Current cryptographic primitives are not quantum-resistant

## Security Best Practices

### For Users

#### Generation Phase
```bash
# Use air-gapped computer when possible
# Disconnect from network
# Use fresh OS installation
# Generate with high entropy
shamir generate --words 24
```

#### Splitting Phase
```bash
# Use higher thresholds for valuable assets
shamir split --parts 7 --threshold 5

# Never store all shares together
# Use geographically distributed locations
```

#### Storage Recommendations
- **Bank Safety Deposit Boxes**: For critical shares
- **Home Safe**: For convenience shares
- **Trusted Family/Friends**: With legal documentation
- **Lawyer/Notary**: For estate planning

#### Reconstruction Phase
```bash
# Use clean, air-gapped system
# Verify share authenticity before use
# Test with non-critical wallet first
shamir combine --interactive
```

### For Developers

#### Code Security
```go
// Always zero sensitive data
defer secure.Zero(sensitiveData)

// Use constant-time comparisons
if secure.ConstantTimeCompare(a, b) {
    // Handle match
}

// Validate all inputs
if err := validation.ValidateMnemonic(input); err != nil {
    return err
}
```

#### Testing Security
```bash
# Run security-focused tests
go test -tags=security ./...

# Check for common vulnerabilities
gosec ./...

# Verify no secrets in code
gitleaks detect
```

## Memory Security

### Secure Allocation
- Sensitive data uses SecureBytes wrapper
- Automatic zeroing on scope exit
- No string operations on secrets

### Example Usage
```go
secret := secure.NewSecureBytes(32)
defer secret.Destroy()

// Use secret.Get() for operations
data := secret.Get()
// Process data
secure.Zero(data)
```

## Cryptographic Verification

### Share Verification
```bash
# Verify individual share
shamir verify <share-hex>

# Test reconstruction with minimum shares
shamir combine --interactive --verify
```

### Mnemonic Validation
- Checksum verification on all mnemonics
- Word list validation against BIP39
- Entropy requirements enforced

## Audit Trail

### Version 1.0.0
- Initial security review
- Cryptographic implementation verified
- Memory handling audited
- Input validation comprehensive

## Security Checklist

Before using in production:

- [ ] Generated on air-gapped system
- [ ] Tested reconstruction with subset
- [ ] Shares stored in separate locations
- [ ] Physical security measures in place
- [ ] Recovery procedure documented
- [ ] Legal considerations addressed
- [ ] Backup of share locations secured
- [ ] Passphrase (if used) separately secured

## Incident Response

In case of suspected compromise:

1. **Immediate Actions**
   - Transfer funds to new wallet
   - Regenerate all shares
   - Review access logs

2. **Investigation**
   - Identify compromised shares
   - Determine attack vector
   - Document timeline

3. **Remediation**
   - Update security measures
   - Redistribute new shares
   - Update documentation

## Compliance

This tool aims to comply with:
- NIST cryptographic standards
- BIP39/32/44 specifications
- Industry best practices

## Updates and Patches

Security updates are released as:
- **Critical**: Within 24 hours
- **High**: Within 7 days
- **Medium**: Within 30 days
- **Low**: Next regular release

Subscribe to security announcements via GitHub watch.

## Contact

For security concerns, contact:
- Email: [security@example.com]
- PGP Key: [Available on request]

## Acknowledgments

We thank the security researchers and cryptographers whose work makes this tool possible:
- Adi Shamir (Secret Sharing)
- Bitcoin Core developers (BIP standards)
- Go crypto maintainers
- Security community contributors