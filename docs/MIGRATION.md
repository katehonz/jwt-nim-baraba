# Migration Guide: JWT for Nim v2.0

## Overview

JWT for Nim v2.0 introduces significant security enhancements, modern cryptographic improvements, and breaking changes for better security. This guide will help you migrate from v0.x to v2.0 smoothly.

## Table of Contents

- [Breaking Changes](#breaking-changes)
- [New Features](#new-features)
- [Security Improvements](#security-improvements)
- [Code Migration](#code-migration)
- [Configuration Changes](#configuration-changes)
- [Testing and Validation](#testing-and-validation)
- [Troubleshooting](#troubleshooting)

## Breaking Changes

### 1. Nim Version Requirement

**v0.x:** `requires "nim >= 0.19.0"`
**v2.0:** `requires "nim >= 2.2.0"`

**Action Required:**
```bash
# Update Nim to 2.2.0 or later
choosenim update self
choosenim install 2.2.0
```

### 2. Algorithm Security Changes

**v0.x:** All algorithms available, including insecure ones
**v2.0:** Enhanced security validation, 'none' algorithm blocked

**Impact:**
```nim
# v0.x - This was allowed
let token = %*{"alg": "none", "typ": "JWT"}.toHeader()

# v2.0 - This raises SecurityError
try:
  let token = %*{"alg": "none", "typ": "JWT"}.toHeader()
except SecurityError:
  echo "Algorithm not allowed for security reasons"
```

### 3. Enhanced Key Validation

**v0.x:** Basic key validation
**v2.0:** Strict key size and format validation

**Impact:**
```nim
# v2.0 now enforces minimum key sizes
# RSA keys must be ≥ 2048 bits
# HMAC keys must be ≥ 32 bytes and ≤ 8192 bytes
# EC curves are validated
```

### 4. Time Validation Changes

**v0.x:** Basic time validation
**v2.0:** Enhanced time validation with security margins

**Changes:**
- Clock skew tolerance: 30 seconds for `nbf` claims
- Future tolerance: 5 minutes for `iat` claims
- More precise time validation

### 5. Deprecated API Changes

**v0.x:** `newSeqUninitialized()` used internally
**v2.0:** `newSeqUninit()` used (modern Nim)

**Impact:** Internal only, no user code changes required

## New Features

### 1. PSS Algorithm Framework

**New:** Framework support for PSS algorithms (PS256, PS384, PS512)

```nim
# v2.0 - PSS algorithms recognized (implementation pending)
case algorithm:
of PS256, PS384, PS512:
  echo "PSS algorithm detected - framework ready"
```

### 2. Enhanced Security Utilities

**New:** `secureCompare()` for timing-safe comparison
```nim
# v2.0 - Constant-time comparison
let isEqual = secureCompare(signature1, signature2)
```

**New:** `isSecureAlgorithm()` for algorithm validation
```nim
# v2.0 - Security checking
if not isSecureAlgorithm(algorithm):
  raise SecurityError("Insecure algorithm not allowed")
```

**New:** `getHashStrength()` for algorithm strength information
```nim
# v2.0 - Get hash strength
let bits = getHashStrength(HS256)  # Returns: 256
```

### 3. Improved Error Handling

**New:** `SecurityError` exception type
```nim
# v2.0 - Better error categorization
try:
  token.verify(secret, algorithm)
except InvalidToken:
  echo "Token format or claims invalid"
except UnsupportedAlgorithm:
  echo "Algorithm not supported"
except SecurityError:
  echo "Security validation failed"
```

### 4. Enhanced Token Verification

**New:** Comprehensive security checks in `verify()`
```nim
# v2.0 - Enhanced verification with multiple security checks
let isValid = token.verify(secret, algorithm)
# Now includes:
# - Algorithm matching validation
# - 'none' algorithm rejection
# - Time-based claim validation
# - Secure signature verification
```

## Security Improvements

### 1. Constant-Time Operations

**v2.0:** Implemented timing-safe comparison to prevent timing attacks

```nim
# v0.x - Vulnerable to timing attacks
if signature == expectedSignature:  # Not timing safe

# v2.0 - Library uses constant-time comparison internally
verifySignature(data, signature, secret, algorithm)  # Timing safe
```

### 2. Memory Security

**v2.0:** Secure memory cleanup on failure

```nim
# v2.0 - Sensitive data cleared on errors
try:
  let signature = signString(data, privateKey, RS256)
except:
  # Memory automatically cleared on failure
  # Reduces risk of sensitive data leakage
```

### 3. Input Validation

**v2.0:** Comprehensive input validation

```nim
# v2.0 - Enhanced validation
# - Empty data rejection
# - Key size validation
# - Format validation
# - Boundary checking
```

### 4. Algorithm Security

**v2.0:** Enhanced algorithm security

```nim
# v2.0 - Security improvements
# - Automatic 'none' algorithm rejection
# - Algorithm validation in headers
# - Minimum key size enforcement
# - Secure defaults
```

## Code Migration

### Basic Token Creation

**v0.x:**
```nim
import jwt, json, tables

var token = toJWT(%*{
  "header": {"alg": "HS256", "typ": "JWT"},
  "claims": {"sub": "1234567890", "name": "John Doe"}
})

token.sign("secret")
echo $token
```

**v2.0:**
```nim
import jwt, json, tables

var token = toJWT(%*{
  "header": {"alg": "HS256", "typ": "JWT"},
  "claims": {"sub": "1234567890", "name": "John Doe"}
})

token.sign("secret")  # Enhanced security automatically applied
echo $token
```

*No changes required - v2.0 maintains backward compatibility for basic operations.*

### Token Verification

**v0.x:**
```nim
let token = tokenString.toJWT()
let isValid = token.verify("secret", HS256)
```

**v2.0:**
```nim
let token = tokenString.toJWT()
let isValid = token.verify("secret", HS256)  # Now includes enhanced security checks
```

*No code changes required, but verification is now more secure.*

### Error Handling

**v0.x:**
```nim
try:
  let token = tokenString.toJWT()
  if token.verify("secret", HS256):
    echo "Valid token"
except InvalidToken:
  echo "Invalid token"
```

**v2.0:**
```nim
try:
  let token = tokenString.toJWT()
  if token.verify("secret", HS256):
    echo "Valid token"
except InvalidToken:
  echo "Invalid token format or claims"
except SecurityError:
  echo "Security validation failed"
except UnsupportedAlgorithm:
  echo "Algorithm not supported"
```

*Recommended to handle new exception types for better error handling.*

### Custom Security Validation

**v0.x:**
```nim
# Manual security checks required
if token.header.alg == "none":
  raise newException(ValueError, "None algorithm not allowed")
```

**v2.0:**
```nim
# Automatic security validation
# Library handles 'none' algorithm rejection
# Additional custom validation can be added:

if not isSecureAlgorithm(token.header.alg):
  raise SecurityError("Insecure algorithm")

let hashStrength = getHashStrength(token.header.alg)
if hashStrength < 256:
  echo "Warning: Using weak hash algorithm"
```

### RSA Key Usage

**v0.x:**
```nim
# Basic RSA usage
let token = signedToken
let isValid = token.verify(publicKeyPem, RS256)
```

**v2.0:**
```nim
# Enhanced RSA with key validation
let token = signedToken
let isValid = token.verify(publicKeyPem, RS256)  # Now validates key size ≥ 2048 bits

# Additional security checks
if getHashStrength(RS256) != 256:
  echo "Unexpected hash strength"
```

## Configuration Changes

### Package Dependencies

**v0.x:**
```nim
# jwt.nimble
version = "0.2"
requires "nim >= 0.19.0"
requires "bearssl"
```

**v2.0:**
```nim
# jwt.nimble
version = "2.0.0"
requires "nim >= 2.2.0"
requires "bearssl >= 0.6"
```

**Action Required:** Update your project's jwt.nimble dependency

### Build Configuration

**v2.0:** No additional build configuration required, but recommended for security:

```nim
# In your project's .nimble file or build script
# Enable security-focused compiler options
# --checks:on --warnings:on

# For production
# -d:release --opt:size
```

## Testing and Validation

### Migration Testing Checklist

#### 1. Basic Functionality
```nim
# Test basic token creation and verification
test "basic token creation":
  var token = toJWT(testData)
  token.sign(testSecret)
  check $token != ""

test "basic token verification":
  let token = tokenString.toJWT()
  check token.verify(testSecret, HS256)
```

#### 2. Algorithm Security
```nim
# Test algorithm validation
test "algorithm validation":
  check isSecureAlgorithm(HS256) == true
  check isSecureAlgorithm(NONE) == false

test "hash strength":
  check getHashStrength(HS256) == 256
  check getHashStrength(HS512) == 512
```

#### 3. Security Features
```nim
# Test security improvements
test "none algorithm rejection":
  expect SecurityError:
    discard %*{"alg": "none", "typ": "JWT"}.toHeader()

test "key size validation":
  expect ValueError:
    token.sign("")  # Empty key rejected
```

#### 4. Error Handling
```nim
# Test new exception types
test "exception handling":
  try:
    let invalidToken = "invalid".toJWT()
    fail("Should have raised InvalidToken")
  except InvalidToken:
    check true
  except:
    fail("Wrong exception type")
```

### Performance Testing

**v2.0:** Measure performance impact:

```nim
import times

proc benchmarkVerification(iterations: int) =
  let start = cpuTime()
  
  for i in 0..<iterations:
    let token = tokenString.toJWT()
    discard token.verify(secret, HS256)
  
  let elapsed = cpuTime() - start
  echo "Verified $1 tokens in $2 seconds" % [$iterations, $elapsed]
  echo "Average: $1 ms per token" % [$(elapsed * 1000.0 / iterations)]
```

### Security Testing

**v2.0:** Test security improvements:

```nim
test "timing attack protection":
  # Test that verification time is consistent regardless of input
  let validToken = validTokenString.toJWT()
  let invalidToken = "invalid.token.here".toJWT()
  
  let startValid = cpuTime()
  discard validToken.verify(secret, HS256)
  let timeValid = cpuTime() - startValid
  
  let startInvalid = cpuTime()
  discard invalidToken.verify(secret, HS256)
  let timeInvalid = cpuTime() - startInvalid
  
  # Times should be similar (within reasonable tolerance)
  let difference = abs(timeValid - timeInvalid)
  check difference < 0.1  # Less than 100ms difference
```

## Troubleshooting

### Common Migration Issues

#### 1. Compilation Errors

**Issue:** `Error: undeclared identifier: 'newSeqUninitialized'`
**Solution:** This is an internal change, should not affect user code. Ensure you're using v2.0.0 or later.

#### 2. Algorithm Validation Errors

**Issue:** `SecurityError: Algorithm 'none' is not allowed`
**Solution:** Update code to use secure algorithms. The 'none' algorithm is now blocked for security.

**Before:**
```nim
let header = %*{"alg": "none", "typ": "JWT"}
```

**After:**
```nim
let header = %*{"alg": "HS256", "typ": "JWT"}
```

#### 3. Key Size Validation

**Issue:** `ValueError: Invalid key size for HMAC` or `RSA key size too small`
**Solution:** Use appropriate key sizes:

```nim
# HMAC: minimum 32 bytes
let hmacKey = "your-32-byte-secret-key-here-1234567890"  # 44+ characters

# RSA: minimum 2048 bits
# Generate with: openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
```

#### 4. Time Validation Issues

**Issue:** `InvalidToken: Token is expired` or `Token cannot be used yet`
**Solution:** Account for new time validation tolerances:

```nim
# Add clock skew tolerance to time-based claims
let now = getTime()
claims["nbf"] = newTimeClaim(now - 1.minutes)  # Account for clock skew
claims["exp"] = newTimeClaim(now + 30.minutes)  # Reasonable expiration
```

#### 5. Dependency Issues

**Issue:** BearSSL version conflicts
**Solution:** Update BearSSL dependency:

```bash
# Update to latest BearSSL
nimble refresh
nimble install bearssl@#head
```

### Performance Considerations

#### v2.0 Performance Impact
- **Memory:** Slightly increased due to security enhancements
- **CPU:** Minimal impact from constant-time comparisons
- **Network:** No impact (same token sizes)
- **Storage:** No impact

#### Optimization Recommendations

**1. Use Appropriate Algorithms**
```nim
# For high-performance scenarios
let algorithm = ES256  # Faster than RSA
# or
let algorithm = HS256  # Fastest for symmetric keys
```

**2. Optimize Token Claims**
```nim
# Use short claim keys
claims["uid"] = newStringClaim(userId)    # Instead of "userId"
claims["exp"] = newTimeClaim(expires)     # Standard claims are optimized
```

**3. Appropriate Expiration Times**
```nim
# Short tokens for better security and performance
claims["exp"] = newTimeClaim(getTime() + 15.minutes)  # Access token
claims["exp"] = newTimeClaim(getTime() + 7.days)      # Refresh token
```

### Getting Help

#### Migration Resources
- **Documentation:** `/docs/API.md` for complete API reference
- **Security Guide:** `/docs/SECURITY.md` for security best practices
- **Examples:** `/examples/` directory for usage examples

#### Support Channels
- **GitHub Issues:** Report migration problems
- **Nim Community:** Ask questions in Nim forums
- **Security:** Report security vulnerabilities privately

#### Professional Support
- Consider professional security audit for production migrations
- Test in staging environment before production deployment
- Monitor logs for unusual activity after migration

## Conclusion

JWT for Nim v2.0 provides significantly enhanced security while maintaining backward compatibility for most use cases. The migration process is straightforward for basic operations, with optional enhancements available for improved security.

### Key Takeaways
1. **Update Nim to 2.2.0+** - Required for v2.0
2. **Review key sizes** - Ensure minimum security requirements
3. **Update error handling** - Handle new exception types
4. **Test thoroughly** - Validate all functionality works as expected
5. **Monitor security** - Take advantage of new security features

### Benefits of Migration
- ✅ Enhanced security against timing attacks
- ✅ Better key validation and memory security
- ✅ Improved error handling and debugging
- ✅ Modern cryptographic best practices
- ✅ Enterprise-grade security features
- ✅ Compliance with security standards

The migration to v2.0 future-proofs your JWT implementation with modern security standards while maintaining the familiar API you're used to.