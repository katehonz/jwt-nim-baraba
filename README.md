# jwt-nim-baraba

[![Build Status](https://github.com/yglukhov/nim-jwt/workflows/CI/badge.svg?branch=master)](https://github.com/yglukhov/nim-jwt/actions?query=branch%3Amaster)

A JSON Web Token library for Nim 2.0+ using BearSSL for cryptographic operations.

## Features

- RFC 7519 compliant JWT implementation
- Algorithms: HS256/384/512, RS256/384/512, ES256/384/512
- Constant-time signature comparison (timing attack protection)
- BearSSL backend for all cryptographic operations
- Secure memory cleanup on failure
- Time-based claim validation with clock skew tolerance

## Requirements

- Nim >= 2.0.0
- BearSSL cryptographic library

## Installation

```bash
nimble install jwt
```

Or from source:

```bash
git clone https://github.com/katehonz/jwt-nim-baraba.git
cd jwt-nim-baraba
nimble install -y
```

## Quick Start

### HMAC (symmetric)

```nim
import jwt, json, times, tables

let header = %*{"alg": "HS256", "typ": "JWT"}

var claims = newTable[string, Claim]()
claims["sub"] = newStringClaim("1234567890")
claims["name"] = newStringClaim("John Doe")
claims["iat"] = newTimeClaim(getTime())
claims["exp"] = newTimeClaim(getTime() + 1.hours)

var token = initJWT(header, claims)
token.sign("your-256-bit-secret")

echo $token

let isValid = token.verify("your-256-bit-secret", HS256)
```

### RSA (asymmetric)

```nim
import jwt, json, times, tables

let privateKey = readFile("private_key.pem")
let publicKey = readFile("public_key.pem")

let header = %*{"alg": "RS256", "typ": "JWT", "kid": "key-001"}

var claims = newTable[string, Claim]()
claims["iss"] = newStringClaim("auth-server.com")
claims["sub"] = newStringClaim("user-12345")
claims["exp"] = newTimeClaim(getTime() + 15.minutes)

var token = initJWT(header, claims)
token.sign(privateKey)

let isValid = token.verify(publicKey, RS256)
```

### ECDSA

```nim
import jwt, json, times, tables

let privateKey = readFile("ec_private.pem")
let publicKey = readFile("ec_public.pem")

let header = %*{"alg": "ES256", "typ": "JWT"}
var claims = newTable[string, Claim]()
claims["sub"] = newStringClaim("user-12345")
claims["exp"] = newTimeClaim(getTime() + 15.minutes)

var token = initJWT(header, claims)
token.sign(privateKey)

let isValid = token.verify(publicKey, ES256)
```

## Supported Algorithms

| Algorithm | Type  | Hash    | Status          |
|-----------|-------|---------|-----------------|
| HS256     | HMAC  | SHA-256 | Supported       |
| HS384     | HMAC  | SHA-384 | Supported       |
| HS512     | HMAC  | SHA-512 | Supported       |
| RS256     | RSA   | SHA-256 | Supported       |
| RS384     | RSA   | SHA-384 | Supported       |
| RS512     | RSA   | SHA-512 | Supported       |
| ES256     | ECDSA | SHA-256 | Supported       |
| ES384     | ECDSA | SHA-384 | Supported       |
| ES512     | ECDSA | SHA-512 | Supported       |
| PS256     | PSS   | SHA-256 | Not implemented |
| PS384     | PSS   | SHA-384 | Not implemented |
| PS512     | PSS   | SHA-512 | Not implemented |
| none      | -     | -       | Rejected        |

## Security

- HMAC keys must be at least 32 bytes
- The `none` algorithm is always rejected
- Signature comparison uses constant-time operations
- Time claims (`exp`, `nbf`, `iat`) are validated with clock skew tolerance
- Sensitive data is zeroed in memory on failure

For key generation:

```bash
# RSA 2048-bit
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem

# ECDSA P-256
openssl ecparam -genkey -name prime256v1 -noout -out ec_private.pem
openssl ec -in ec_private.pem -pubout -out ec_public.pem
```

## Examples

- [basic_jwt.nim](examples/basic_jwt.nim) - HMAC token creation and verification
- [rsa_jwt.nim](examples/rsa_jwt.nim) - RSA signing
- [web_api_auth.nim](examples/web_api_auth.nim) - API authentication pattern
- [security_best_practices.nim](examples/security_best_practices.nim) - Token blacklisting, key rotation

Run examples:

```bash
nim c -r examples/basic_jwt.nim
nim c -r examples/rsa_jwt.nim
nim c -r examples/web_api_auth.nim
```

## Testing

```bash
nimble test
```

## API Reference

See [docs/API.md](docs/API.md) for the complete API reference.

## License

MIT - see [LICENSE](LICENSE).
