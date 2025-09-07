# Migration to SLIP-0039 as Default

## Summary of Changes

This document outlines the major changes made to make SLIP-0039 the default secret sharing implementation in the Shamir tool.

## What Changed

### 1. **SLIP-0039 is Now Default**
- The `shamir split` and `shamir combine` commands now use SLIP-0039 by default
- Creates mnemonic shares (20 or 33 words) instead of hex/base64
- Full hardware wallet compatibility (Trezor, etc.)
- Built-in encryption and hierarchical sharing

### 2. **Legacy Mode for Old Implementation**
- Old Shamir implementation moved to `shamir legacy` subcommands
- Use `shamir legacy split` and `shamir legacy combine` for old behavior
- Only recommended for recovering existing shares

### 3. **New Features with SLIP-0039**
- **Mnemonic Format**: Human-readable word shares
- **Passphrase Encryption**: Built-in with plausible deniability
- **Two-Level Sharing**: Groups and members for complex setups
- **Hardware Compatibility**: Works with Trezor Model T
- **Standard Compliance**: Full SLIP-0039 specification

## Migration Guide

### For Users with Existing Shares

If you have shares created with the old version:

1. **Recover your secret** using legacy mode:
   ```bash
   shamir legacy combine
   ```

2. **Create new SLIP-0039 shares**:
   ```bash
   shamir split --threshold 2 --shares 3
   ```

3. **Securely destroy** old shares

### For New Users

Simply use the default commands:

```bash
# Create shares (SLIP-0039)
shamir split --threshold 2 --shares 3 --length 32

# Recover secret
shamir combine
```

## Command Comparison

### Old Commands (Now Legacy)
```bash
# Old way (non-standard)
shamir legacy split --parts 3 --threshold 2
shamir legacy combine

# Output: Hex/Base64 shares
```

### New Commands (SLIP-0039 Default)
```bash
# New way (SLIP-0039 standard)
shamir split --shares 3 --threshold 2
shamir combine

# Output: Mnemonic word shares
```

## Benefits of SLIP-0039

1. **Industry Standard**: Compatible with hardware wallets
2. **Human-Readable**: Mnemonic words instead of hex strings
3. **Error Detection**: RS1024 checksum prevents mistakes
4. **Encryption**: Built-in passphrase protection
5. **Flexibility**: Support for complex multi-group setups
6. **Future-Proof**: Widely adopted standard

## Examples

### Simple 2-of-3 Sharing
```bash
# Generate and split a 256-bit secret
shamir split -t 2 -n 3 -l 32

# Output: 3 mnemonic shares (20 words each for 128-bit, 33 words for 256-bit)
```

### With Passphrase
```bash
# Split with passphrase
shamir split -t 2 -n 3 -l 32 -p "my secret"

# Combine with same passphrase
shamir combine -p "my secret"
```

### Advanced Multi-Group
```bash
# Require 2 of 3 groups, each with different thresholds
shamir split --group-threshold 2 --groups "2/3,3/5,1/2"
```

## Backward Compatibility

- Old shares **cannot** be used with new commands
- New shares **cannot** be used with legacy commands
- Must migrate by recovering and re-splitting

## Testing the Migration

1. **Test legacy recovery** (if you have old shares):
   ```bash
   shamir legacy combine
   ```

2. **Create new SLIP-0039 shares**:
   ```bash
   shamir split -t 2 -n 3 -l 16
   ```

3. **Test recovery**:
   ```bash
   shamir combine
   ```

## FAQ

**Q: Can I convert old shares to SLIP-0039 without the secret?**
A: No, you must recover the secret first, then create new shares.

**Q: Are SLIP-0039 shares longer?**
A: Yes, they are 20 or 33 words instead of hex strings, but they're human-readable and more secure.

**Q: Can I still create old-style shares?**
A: Yes, using `shamir legacy split`, but it's not recommended.

**Q: Will my Trezor work with these shares?**
A: Yes, SLIP-0039 shares are fully compatible with Trezor Model T and newer.

**Q: What if I forget which type of shares I have?**
A: SLIP-0039 shares are mnemonic words. Old shares are hex/base64 strings.

## Support

For issues or questions:
- GitHub Issues: https://github.com/Davincible/shamir/issues
- Documentation: See README.md

## Security Note

When migrating:
1. Work in a secure, offline environment
2. Verify new shares work before destroying old ones
3. Never store both old and new shares together
4. Clear terminal history after migration

---

*Migration completed to SLIP-0039 v1.0 standard*