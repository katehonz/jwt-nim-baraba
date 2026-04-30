## Security

This library implements JWT (RFC 7519) with BearSSL as the cryptographic backend.

### Security Features

- **Constant-time comparison** - Signature verification uses constant-time byte comparison to prevent timing attacks
- **Minimum key sizes** - HMAC keys must be >= 32 bytes; `none` algorithm is always rejected
- **Secure memory** - Sensitive buffers (digests, keys) are zeroed after use on failure paths
- **Time claim validation** - `exp`, `nbf`, and `iat` are validated with configurable clock skew tolerance (30s for nbf, 5min for iat)
- **Algorithm pinning** - `verify()` requires the caller to specify the expected algorithm, preventing algorithm confusion attacks

### What This Library Does NOT Do

- **Audience (`aud`) validation** - Must be done by the application
- **Issuer (`iss`) validation** - Must be done by the application
- **Token blacklisting / revocation** - Must be implemented at the application layer
- **Key rotation** - Use `kid` header claim and manage keys in your application

### Recommendations

- Use HS256 for symmetric scenarios, RS256 or ES256 for asymmetric
- Keep access token lifetime short (15 minutes or less)
- Use HTTPS for all token transport
- Store secrets outside source code (environment variables, secret managers)
- Rotate keys periodically and use `kid` to identify which key signed a token
