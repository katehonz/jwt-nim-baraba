# JWT for Nim - API Documentation

## Overview

This document provides comprehensive API documentation for the JWT (JSON Web Token) implementation in Nim 2.2.0 with enhanced security features.

## Table of Contents

- [Core Types](#core-types)
- [Token Creation](#token-creation)
- [Token Signing](#token-signing)
- [Token Verification](#token-verification)
- [Token Parsing](#token-parsing)
- [Time-based Claims](#time-based-claims)
- [Security Functions](#security-functions)
- [Error Handling](#error-handling)

## Core Types

### JWT Object

```nim
type
  JWT* = object
    headerB64: string          ## Base64URL encoded header
    claimsB64: string          ## Base64URL encoded claims
    header*: JsonNode          ## Parsed JWT header
    claims*: TableRef[string, Claim]  ## Parsed JWT claims
    signature*: seq[byte]      ## Token signature
```

### Signature Algorithms

```nim
type
  SignatureAlgorithm* = enum
    NONE = "none"              ## No signature (insecure, blocked by default)
    HS256 = "HS256"            ## HMAC using SHA-256
    HS384 = "HS384"            ## HMAC using SHA-384
    HS512 = "HS512"            ## HMAC using SHA-512
    RS256 = "RS256"            ## RSASSA-PKCS1-v1_5 using SHA-256
    RS384 = "RS384"            ## RSASSA-PKCS1-v1_5 using SHA-384
    RS512 = "RS512"            ## RSASSA-PKCS1-v1_5 using SHA-512
    ES256 = "ES256"            ## ECDSA using P-256 and SHA-256
    ES384 = "ES384"            ## ECDSA using P-384 and SHA-384
    ES512 = "ES512"            ## ECDSA using P-521 and SHA-512
    PS256 = "PS256"            ## RSASSA-PSS using SHA-256 (framework ready)
    PS384 = "PS384"            ## RSASSA-PSS using SHA-384 (framework ready)
    PS512 = "PS512"            ## RSASSA-PSS using SHA-512 (framework ready)
```

### Exceptions

```nim
type
  InvalidToken* = object of ValueError    ## Invalid JWT token
  UnsupportedAlgorithm* = object of ValueError  ## Unsupported algorithm
  SecurityError* = object of ValueError  ## Security-related error
```

## Token Creation

### initJWT

Creates a new JWT token from parsed components.

```nim
proc initJWT*(header: JsonNode, claims: TableRef[string, Claim], 
             signature: seq[byte] = @[]): JWT
```

**Parameters:**
- `header`: JSON node containing JWT header
- `claims`: Table of claims
- `signature`: Optional signature bytes (default: empty)

**Returns:** Complete JWT object

**Example:**
```nim
import jwt, json, tables

let header = %*{"alg": "HS256", "typ": "JWT"}
let claims = newTable[string, Claim]()
claims["sub"] = newStringClaim("1234567890")
claims["name"] = newStringClaim("John Doe")

let token = initJWT(header, claims)
```

### toJWT

Parses JWT from string representation.

```nim
proc toJWT*(s: string): JWT
proc toJWT*(node: JsonNode): JWT
```

**Parameters:**
- `s`: JWT string in format "header.payload.signature"
- `node`: JSON object with "header" and "claims" fields

**Returns:** Parsed JWT object

**Example:**
```nim
let jwtString = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
let token = jwtString.toJWT()
```

## Token Signing

### sign

Signs a token with a secret key.

```nim
proc sign*(token: var JWT, secret: string)
```

**Parameters:**
- `token`: JWT token to sign (will be modified)
- `secret`: Secret key for HMAC or private key for RSA/ECDSA

**Security Notes:**
- For HMAC algorithms: secret must be at least 32 bytes
- For RSA/ECDSA: secret must be PEM-formatted private key
- Minimum RSA key size: 2048 bits
- Invalid keys are rejected with descriptive error messages

**Example:**
```nim
var token = initJWT(header, claims)
token.sign("your-secret-key-here")
echo $token  # Outputs complete JWT string
```

### signString

Low-level string signing function.

```nim
proc signString*(toSign: string, secret: string, 
                algorithm: SignatureAlgorithm = HS256): seq[byte]
```

**Parameters:**
- `toSign`: Data to sign
- `secret`: Secret key or private key
- `algorithm`: Signature algorithm to use

**Returns:** Signature as byte sequence

## Token Verification

### verify

Comprehensive token verification with security checks.

```nim
proc verify*(token: JWT, secret: string, alg: SignatureAlgorithm): bool
```

**Parameters:**
- `token`: JWT token to verify
- `secret`: Secret key for HMAC or public key for RSA/ECDSA
- `alg`: Expected algorithm

**Security Checks Performed:**
1. Algorithm matching (prevents algorithm confusion attacks)
2. 'none' algorithm rejection
3. Signature verification with constant-time comparison
4. Time-based claim validation (exp, nbf, iat)
5. Clock skew tolerance (30 seconds for nbf, 5 minutes for iat)

**Returns:** `true` if token is valid, `false` otherwise

**Example:**
```nim
let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature".toJWT()
let isValid = token.verify("your-secret-key-here", HS256)
if isValid:
  echo "Token is valid"
else:
  echo "Token is invalid or expired"
```

### verifySignature

Low-level signature verification.

```nim
proc verifySignature*(data: string, signature: seq[byte], secret: string,
                     alg: SignatureAlgorithm): bool
```

**Parameters:**
- `data`: Original signed data
- `signature`: Signature to verify
- `secret`: Secret key or public key
- `alg`: Signature algorithm used

**Returns:** `true` if signature is valid

## Token Parsing

### toString / $ operator

Converts JWT token to string representation.

```nim
proc toString*(token: JWT): string
proc `$`*(token: JWT): string
```

**Returns:** JWT string in format "header.payload.signature"

**Example:**
```nim
let token = initJWT(header, claims)
token.sign("secret")
echo token.toString()  # or just: echo token
```

### % operator

Converts JWT to JSON node.

```nim
proc `%`*(token: JWT): JsonNode
```

**Returns:** JSON string containing the complete JWT

## Time-based Claims

### verifyTimeClaims

Validates time-based claims with security margins.

```nim
proc verifyTimeClaims*(token: JWT)
```

**Validated Claims:**
- `exp` (Expiration Time): Token must not be expired
- `nbf` (Not Before): Token cannot be used before this time
- `iat` (Issued At): Token must not be issued too far in future

**Security Features:**
- 30-second tolerance for clock skew on `nbf`
- 5-minute future tolerance for `iat`
- Raises `InvalidToken` on validation failure

**Example:**
```nim
import times, jwt

var token = initJWT(header, claims)
token.claims["exp"] = newTimeClaim(getTime() + 1.hours)

# Will raise InvalidToken if token is expired
try:
  token.verifyTimeClaims()
  echo "Time claims are valid"
except InvalidToken:
  echo "Time claims validation failed"
```

## Security Functions

### isSecureAlgorithm

Checks if an algorithm meets modern security standards.

```nim
proc isSecureAlgorithm*(alg: SignatureAlgorithm): bool
```

**Returns:** `true` for all supported algorithms except `NONE`

**Example:**
```nim
assert isSecureAlgorithm(HS256) == true
assert isSecureAlgorithm(NONE) == false
```

### getHashStrength

Gets the bit strength of the hash function.

```nim
proc getHashStrength*(alg: SignatureAlgorithm): int
```

**Returns:** Hash strength in bits (256, 384, 512, or 0 for NONE)

**Example:**
```nim
assert getHashStrength(HS256) == 256
assert getHashStrength(HS512) == 512
```

### secureCompare

Constant-time comparison to prevent timing attacks.

```nim
proc secureCompare*(a, b: openarray[byte]): bool
proc secureCompare*(a, b: string): bool
```

**Returns:** `true` if inputs are equal, `false` otherwise

## Error Handling

### Exception Hierarchy

```nim
ValueError
├── InvalidToken          # Invalid JWT token format or claims
├── UnsupportedAlgorithm   # Algorithm not supported
└── SecurityError         # Security-related validation failure
```

### Common Error Scenarios

```nim
# Invalid token format
try:
  let token = "invalid-token".toJWT()
except InvalidToken:
  echo "Invalid token format"

# Unsupported algorithm
try:
  let token = %*{"alg": "unsupported", "typ": "JWT"}.toHeader()
except UnsupportedAlgorithm:
  echo "Algorithm not supported"

# Security validation failure
try:
  verifyTimeClaims(expiredToken)
except InvalidToken:
  echo "Token is expired"
```

## Best Practices

### 1. Always Use HTTPS
JWT tokens contain sensitive information and should always be transmitted over secure channels.

### 2. Use Strong Keys
- HMAC: Minimum 32 bytes (256 bits)
- RSA: Minimum 2048 bits
- ECDSA: Use recommended curves (P-256, P-384, P-521)

### 3. Set Proper Expiration
```nim
# Set reasonable expiration times
claims["exp"] = newTimeClaim(getTime() + 15.minutes)  # Access tokens
claims["exp"] = newTimeClaim(getTime() + 7.days)      # Refresh tokens
```

### 4. Include Relevant Claims
```nim
claims["iss"] = newStringClaim("your-app")    # Issuer
claims["aud"] = newStringClaim("your-audience")  # Audience
claims["sub"] = newStringClaim("user-id")    # Subject
claims["jti"] = newStringClaim(generateUUID())  # JWT ID for replay prevention
```

### 5. Use Appropriate Algorithms
- HMAC for symmetric key scenarios
- RSA for asymmetric key scenarios with key rotation
- ECDSA for performance-critical applications

### 6. Implement Proper Error Handling
```nim
proc handleJWT(tokenString: string): bool =
  try:
    let token = tokenString.toJWT()
    return token.verify(secret, expectedAlgorithm)
  except InvalidToken as e:
    echo "Invalid token: ", e.msg
    return false
  except SecurityError as e:
    echo "Security error: ", e.msg
    return false
  except:
    echo "Unexpected error"
    return false
```