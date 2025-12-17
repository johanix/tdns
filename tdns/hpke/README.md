# HPKE Key Distribution - Testing Guide

## Environment Setup

Before testing, you need to fix your Go environment. The issue is that GOPATH and GOROOT are set to the same directory.

### Quick Fix (for current session):
```bash
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org
```

### Permanent Fix:
Add to your `~/.zshrc` or `~/.bashrc`:
```bash
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org
```

You may also need to fix the GOPATH/GOROOT issue. Check with:
```bash
go env GOPATH
go env GOROOT
```

They should be different directories. If they're the same, you may need to reinstall Go or set them correctly.

## Testing Methods

### Method 1: Run Go Tests

```bash
cd /Users/johani/src/git/tdns
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org
go test ./hpke -v
```

This will run all tests in `hpke_test.go`:
- `TestGenerateKeyPair` - Tests keypair generation
- `TestEncryptDecrypt` - Tests basic encryption/decryption
- `TestEncryptDecryptWithEphemeralKey` - Tests with ephemeral keys
- `TestEncryptDecryptLargeData` - Tests with larger data (simulating DNSSEC keys)

### Method 2: Run Standalone Test Program

```bash
cd /Users/johani/src/git/tdns
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org
go run cmd/hpke-test/main.go
```

This runs a comprehensive test that:
1. Generates HPKE keypairs
2. Encrypts and decrypts simple messages
3. Encrypts and decrypts larger data (simulating DNSSEC private keys)
4. Tests multiple encryptions
5. Tests distribution ID generation

### Method 3: Manual Testing in Go REPL

You can also test interactively using a simple Go program:

```go
package main

import (
    "fmt"
    "github.com/johanix/tdns/hpke"
)

func main() {
    // Generate keypair
    pub, priv, _ := hpke.GenerateKeyPair()
    
    // Encrypt
    plaintext := []byte("test message")
    ciphertext, ephemeral, _ := hpke.Encrypt(pub, nil, plaintext)
    
    // Decrypt
    decrypted, _ := hpke.Decrypt(priv, ephemeral, ciphertext)
    
    fmt.Printf("Original: %s\n", string(plaintext))
    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

## Expected Output

When tests run successfully, you should see:

```
=== HPKE Function Tests ===

Test 1: Generate HPKE keypair
  Public key (hex):  [32 hex bytes]
  Private key (hex): [32 hex bytes]
  ✓ Keypair generated successfully

Test 2: Encrypt and decrypt simple message
  Plaintext: "Hello, HPKE! This is a test message."
  Ciphertext (base64): [base64 string]
  Ephemeral pub key (hex): [32 hex bytes]
  Decrypted: "Hello, HPKE! This is a test message."
  ✓ Encryption/decryption successful

Test 3: Encrypt and decrypt larger data
  Data size: 1024 bytes
  Encrypted size: [size] bytes
  ✓ Large data encryption/decryption successful

Test 4: Multiple encryptions
  ✓ Message 1 encrypted/decrypted successfully
  ✓ Message 2 encrypted/decrypted successfully
  ✓ Message 3 encrypted/decrypted successfully

Test 5: Generate distribution IDs
  Distribution ID 1: [32 hex chars]
  Distribution ID 2: [32 hex chars]
  ...
  ✓ Distribution ID generation successful

=== All tests passed! ===
```

## What the Tests Verify

1. **Keypair Generation**: X25519 keypairs are 32 bytes each
2. **Encryption**: Plaintext can be encrypted to ciphertext
3. **Decryption**: Ciphertext can be decrypted back to original plaintext
4. **Round-trip**: Encrypt → Decrypt preserves data integrity
5. **Large Data**: Works with data sizes typical of DNSSEC private keys
6. **Multiple Operations**: Same keypair can be used multiple times
7. **Distribution IDs**: Unique IDs are generated correctly

## Troubleshooting

### "package X is not in std" errors
This indicates a Go environment configuration issue. Check:
- `go env GOPATH` and `go env GOROOT` should be different
- Standard library should be in `$GOROOT/src`
- May need to reinstall Go or fix environment variables

### "GOPROXY list is not the empty string, but contains no entries"
Set `GOPROXY=https://proxy.golang.org,direct` and `GOSUMDB=sum.golang.org`

### "missing GOSUMDB"
Set `GOSUMDB=sum.golang.org`

## Next Steps

Once tests pass:
1. Review the HPKE wrapper implementation in `hpke_wrapper.go`
2. Check RRtype implementations in `rrtypes.go`
3. Verify EDNS(0) option handling in `edns0.go`
4. Proceed with KDC/KRS daemon implementation

