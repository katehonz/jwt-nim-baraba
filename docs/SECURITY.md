# JWT Security Guidelines

## Overview

This document provides comprehensive security guidelines for using JWT tokens safely in production environments. Following these guidelines will help protect your application from common security vulnerabilities.

## Table of Contents

- [Algorithm Selection](#algorithm-selection)
- [Key Management](#key-management)
- [Token Security](#token-security)
- [Transport Security](#transport-security)
- [Storage Security](#storage-security)
- [Common Attacks and Mitigations](#common-attacks-and-mitigations)
- [Security Best Practices](#security-best-practices)
- [Compliance and Standards](#compliance-and-standards)

## Algorithm Selection

### Recommended Algorithms

#### HMAC (Symmetric)
- **HS256** - HMAC using SHA-256: Good balance of security and performance
- **HS384** - HMAC using SHA-384: Higher security for sensitive data
- **HS512** - HMAC using SHA-512: Maximum security, slightly slower

**Use Cases:**
- Service-to-service authentication
- Internal APIs where key sharing is secure
- High-performance scenarios

#### RSA (Asymmetric)
- **RS256** - RSA PKCS#1 signature with SHA-256
- **RS384** - RSA PKCS#1 signature with SHA-384
- **RS512** - RSA PKCS#1 signature with SHA-512

**Use Cases:**
- Public-facing APIs
- Third-party integrations
- Scenarios requiring key rotation without service restart

#### ECDSA (Asymmetric)
- **ES256** - ECDSA using P-256 and SHA-256
- **ES384** - ECDSA using P-384 and SHA-384
- **ES512** - ECDSA using P-521 and SHA-512

**Use Cases:**
- Mobile applications
- IoT devices with limited computational resources
- Performance-critical applications

### Algorithm Security Levels

| Algorithm | Security Level | Key Size | Performance | Recommended |
|-----------|----------------|----------|-------------|-------------|
| HS256 | High | 256+ bits | Excellent | ✅ |
| HS384 | Very High | 384+ bits | Good | ✅ |
| HS512 | Maximum | 512+ bits | Good | ✅ |
| RS256 | High | 2048+ bits | Fair | ✅ |
| RS384 | Very High | 3072+ bits | Poor | ⚠️ |
| RS512 | Maximum | 4096+ bits | Poor | ⚠️ |
| ES256 | High | 256 bits | Excellent | ✅ |
| ES384 | Very High | 384 bits | Good | ✅ |
| ES512 | Maximum | 521 bits | Good | ✅ |
| NONE | ❌ INSECURE | N/A | Excellent | ❌ |

### Algorithm Recommendations by Use Case

#### Web APIs
```nim
# Recommended: RS256 for standard web APIs
let algorithm = RS256

# Alternative: ES256 for mobile apps
let algorithm = ES256
```

#### Microservices
```nim
# Recommended: HS256 for internal service communication
let algorithm = HS256

# Alternative: ES256 for performance-critical services
let algorithm = ES256
```

#### Banking/Financial
```nim
# Recommended: RS384 or ES384 for high-security requirements
let algorithm = RS384  # or ES384
```

## Key Management

### Key Generation

#### HMAC Keys
```nim
import random, strutils

proc generateHMACKey(length: int = 32): string =
  ## Generate cryptographically secure HMAC key
  var bytes = newSeq[byte](length)
  randomBytes(bytes)
  result = bytes.encodeHex()

# Generate 32-byte (256-bit) key
let secretKey = generateHMACKey(32)
```

#### RSA Keys
```bash
# Generate 2048-bit RSA private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

#### ECDSA Keys
```bash
# Generate P-256 EC private key
openssl ecparam -name prime256v1 -genkey -noout -out ec_private_key.pem

# Extract public key
openssl ec -in ec_private_key.pem -pubout -out ec_public_key.pem
```

### Key Security Requirements

#### HMAC Keys
- **Minimum Length:** 32 bytes (256 bits)
- **Maximum Length:** 8192 bytes (security limit)
- **Generation:** Cryptographically secure random number generator
- **Storage:** Encrypted at rest
- **Rotation:** Every 90 days for high-security applications

#### RSA Keys
- **Minimum Size:** 2048 bits
- **Recommended Size:** 3072 bits for new deployments
- **Maximum Size:** 4096 bits (practical limit)
- **Format:** PEM encoding with PKCS#8 structure
- **Protection:** Password-protected when possible

#### ECDSA Keys
- **Recommended Curves:** P-256, P-384, P-521
- **Curve Selection:** Based on security requirements
- **Format:** PEM encoding
- **Performance:** Better than RSA for equivalent security levels

### Key Rotation Strategy

#### 1. Key Identifier (kid) Claim
```nim
# Include key identifier in header
let header = %*{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "2023-12-key-001"  # Unique key identifier
}
```

#### 2. Graceful Transition
```nim
# Support multiple keys during transition
proc verifyWithKeyRotation(token: JWT, tokenString: string): bool =
  let keyId = token.header{"kid"}.getStr("")
  
  case keyId:
  of "old-key-id":
    return token.verify(OLD_PUBLIC_KEY, RS256)
  of "new-key-id":
    return token.verify(NEW_PUBLIC_KEY, RS256)
  else:
    return false  # Unknown key
```

#### 3. Key Rotation Timeline
- **Phase 1:** Deploy new key alongside old key (both active)
- **Phase 2:** Start signing with new key only
- **Phase 3:** Verify with both keys (transition period)
- **Phase 4:** Decommission old key after all tokens expire

## Token Security

### Required Claims

#### Standard Claims
```nim
# Always include these standard claims
claims["iss"] = newStringClaim("your-domain.com")     # Issuer
claims["sub"] = newStringClaim("user-12345")          # Subject
claims["aud"] = newStringClaim("your-app-name")      # Audience
claims["exp"] = newTimeClaim(getTime() + 1.hours)    # Expiration
claims["iat"] = newTimeClaim(getTime())              # Issued At
claims["jti"] = newStringClaim(generateUUID())        # JWT ID
```

#### Security Claims
```nim
# Additional security claims
claims["nbf"] = newTimeClaim(getTime() - 5.minutes)  # Not Before
claims["auth_time"] = newTimeClaim(authTime)          # Authentication Time
claims["nonce"] = newStringClaim(randomNonce())       # Anti-replay nonce
```

### Claim Security Guidelines

#### Expiration (exp)
- **Access Tokens:** 15 minutes to 1 hour
- **Refresh Tokens:** 7 days to 30 days
- **Session Tokens:** 24 hours with sliding expiration

#### Issued At (iat)
- Always include `iat` claim
- Verify token wasn't issued in future (5-minute tolerance)
- Use for detecting clock manipulation

#### JWT ID (jti)
- Must be cryptographically random (UUID v4)
- Store used JWT IDs to prevent replay attacks
- Implement cleanup mechanism for expired JWT IDs

#### Audience (aud)
- Always validate audience claim
- Single audience for specific applications
- Array of audiences for multi-tenant systems

### Token Size Considerations

#### Maximum Token Size
- **HTTP Header Limit:** 8KB (practical limit)
- **Recommended Size:** < 1KB for performance
- **URL Size Limit:** 2048 characters for URL usage

#### Size Optimization
```nim
# Use short claim keys
claims["uid"] = newStringClaim(userId)    # Instead of "userId"
claims["exp"] = newTimeClaim(expires)      # Standard claims are short

# Limit payload data
claims["data"] = newStringClaim(minimalData)  # Avoid large objects
```

## Transport Security

### HTTPS Requirements

#### Mandatory HTTPS
```nim
# Never transmit JWT tokens over unencrypted connections
proc validateTransport(headers: HttpHeaders): bool =
  let scheme = headers.getOrDefault("x-forwarded-proto", "http")
  return scheme == "https"
```

#### Certificate Validation
- Always validate SSL certificates
- Use certificate pinning for mobile apps
- Implement proper certificate chain validation

### Header Security

#### Authorization Header
```nim
# Standard Authorization header format
let headers = newHttpHeaders({
  "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
})

# Never use query parameters for sensitive tokens
# BAD: /api/users?token=eyJhbGciOiJIUzI1NiIs...
```

#### Cookie Security
```nim
# If using cookies, set security flags
Set-Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; 
  HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600
```

## Storage Security

### Client-Side Storage

#### Browser Storage Options

**localStorage** ⚠️
```nim
# Risks: XSS attacks, accessible to JavaScript
# Use only for non-sensitive data with proper XSS protection
```

**sessionStorage** ⚠️
```nim
# Risks: XSS attacks, cleared on tab close
# Slightly better than localStorage
```

**HttpOnly Cookies** ✅
```nim
# Recommended for authentication tokens
# Protected from XSS, automatic transmission
```

#### Secure Cookie Configuration
```nim
# Secure cookie attributes
Set-Cookie: jwt_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...;
  HttpOnly;        # Prevent JavaScript access
  Secure;          # HTTPS only
  SameSite=Strict; # CSRF protection
  Path=/;          # Limit to specific paths
  Max-Age=3600     # Short lifetime
```

### Server-Side Storage

#### Token Blacklisting
```nim
type
  TokenBlacklist = object
    usedTokens: HashSet[string]
    expiry: Time

proc addToBlacklist(blacklist: var TokenBlacklist, jti: string, exp: Time) =
  blacklist.usedTokens.incl(jti)
  # Clean up expired entries periodically
```

#### Session Storage
```nim
# Store minimal session data server-side
type
  Session = object
    userId: string
    createdAt: Time
    lastActivity: Time
    jti: string  # Link to JWT ID
```

## Common Attacks and Mitigations

### 1. Algorithm Confusion Attack

#### Vulnerability
```nim
# Vulnerable: Accepting any algorithm
let token = maliciousToken.toJWT()
if token.verify(publicKey, token.header.alg):  # Dangerous!
```

#### Mitigation
```nim
# Safe: Specify expected algorithm
let token = maliciousToken.toJWT()
if token.verify(publicKey, RS256):  # Specific algorithm only!
```

### 2. None Algorithm Attack

#### Vulnerability
```nim
# Tokens with "alg": "none" bypass signature verification
```

#### Mitigation
```nim
# Library automatically rejects 'none' algorithm
# Additional validation in application logic
if token.header.alg == NONE:
  raise SecurityError("None algorithm not allowed")
```

### 3. Token Replay Attack

#### Vulnerability
```nim
# Captured tokens can be replayed
```

#### Mitigation
```nim
# Implement JWT ID tracking
proc checkReplay(jti: string, exp: Time): bool =
  if blacklist.contains(jti):
    return false  # Already used
  
  blacklist.add(jti)
  return true

# Include short expiration
claims["exp"] = newTimeClaim(getTime() + 5.minutes)
claims["jti"] = newStringClaim(generateUUID())
```

### 4. Timing Attack

#### Vulnerability
```nim
# String comparison leaks information
if signature == expectedSignature:  # Vulnerable
```

#### Mitigation
```nim
# Library uses constant-time comparison
# Additional protection in custom code
proc constantTimeCompare(a, b: string): bool =
  if a.len != b.len: return false
  var result = 0
  for i in 0..<a.len:
    result = result or (int(a[i]) xor int(b[i]))
  return result == 0
```

### 5. Man-in-the-Middle Attack

#### Vulnerability
```nim
# Intercepting JWT tokens over unencrypted connections
```

#### Mitigation
```nim
# Enforce HTTPS
proc validateSecureConnection(request: HttpRequest): bool =
  return request.headers.getOrDefault("x-forwarded-proto") == "https"
  # Or check connection properties directly
```

## Security Best Practices

### 1. Defense in Depth

#### Multiple Layers of Security
```nim
# 1. HTTPS encryption
# 2. JWT signature verification
# 3. Token expiration validation
# 4. Audience verification
# 5. Replay attack prevention
# 6. Rate limiting
# 7. IP validation (optional)
```

### 2. Principle of Least Privilege

#### Minimal Token Claims
```nim
# Include only necessary claims
claims["sub"] = newStringClaim(userId)
claims["scope"] = newStringClaim("read:posts")  # Minimal scope
claims["exp"] = newTimeClaim(getTime() + 15.minutes)  # Short lifetime

# Avoid sensitive data in tokens
# BAD: claims["ssn"] = newStringClaim("123-45-6789")
# BAD: claims["credit_card"] = newStringClaim("4111-1111-1111-1111")
```

### 3. Audit Logging

#### Security Event Logging
```nim
proc logSecurityEvent(event: string, userId: string, ip: string, tokenJti: string) =
  let logEntry = %*{
    "timestamp": getTime().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'"),
    "event": event,
    "userId": userId,
    "ip": ip,
    "jti": tokenJti,
    "userAgent": request.headers.getOrDefault("user-agent")
  }
  
  logger.info(logEntry.pretty)

# Log important events
logSecurityEvent("token_verified", userId, clientIP, jti)
logSecurityEvent("token_expired", userId, clientIP, jti)
logSecurityEvent("invalid_token", "unknown", clientIP, "unknown")
```

### 4. Monitoring and Alerting

#### Security Metrics
```nim
# Monitor for suspicious patterns
proc detectSuspiciousActivity(ip: string, failedAttempts: int): bool =
  # Rate limiting
  if failedAttempts > 10:
    return true
  
  # Unusual geographic locations
  if isUnusualLocation(ip):
    return true
  
  # Token flood attempts
  if isTokenFlood(ip):
    return true
```

### 5. Regular Security Audits

#### Security Checklist
- [ ] Token expiration times are appropriate
- [ ] Algorithm validation is implemented
- [ ] HTTPS is enforced
- [ ] Sensitive claims are excluded
- [ ] Replay protection is in place
- [ ] Key rotation procedures exist
- [ ] Audit logging is comprehensive
- [ ] Error handling doesn't leak information
- [ ] Rate limiting is implemented
- [ ] Security headers are configured

## Compliance and Standards

### OWASP JWT Security Cheat Sheet

This implementation follows OWASP recommendations:
- ✅ Algorithm validation
- ✅ None algorithm rejection
- ✅ Proper key management
- ✅ Token expiration
- ✅ Replay attack prevention
- ✅ Secure transmission

### Industry Standards Compliance

#### RFC 7519 (JWT)
- Complete JWT standard compliance
- All standard claims supported
- Proper header and claim validation

#### RFC 7515 (JWS)
- JSON Web Signature implementation
- Multiple algorithm support
- Secure signing and verification

#### Security Standards
- NIST SP 800-63B Digital Identity Guidelines
- ISO/IEC 27001 Information Security Management
- GDPR data protection considerations

### Data Protection

#### Personal Data in JWTs
```nim
# Avoid storing personal data in JWTs
# Use tokens for authentication/authorization only
# Store personal data server-side with token reference

# Instead of:
claims["firstName"] = newStringClaim("John")
claims["lastName"] = newStringClaim("Doe")
claims["email"] = newStringClaim("john@example.com")

# Use:
claims["sub"] = newStringClaim(userId)  # Reference only
claims["scope"] = newStringClaim("profile:read")
```

## Emergency Response

### Security Incident Response

#### Token Compromise
1. **Immediate Action:**
   - Rotate all signing keys
   - Invalidate all active tokens
   - Enable enhanced monitoring

2. **Investigation:**
   - Analyze access logs
   - Identify affected accounts
   - Determine breach scope

3. **Recovery:**
   - Force password changes
   - Issue new tokens
   - Update security procedures

#### Key Compromise
```nim
# Emergency key rotation procedure
proc emergencyKeyRotation(): tuple[oldKey, newKey: string] =
  # Generate new keys immediately
  result.newKey = generateNewKey()
  
  # Add old key to revoked list
  revokedKeys.add(currentKey)
  
  # Update current key
  currentKey = result.newKey
  result.oldKey = currentKey
```

### Security Updates

#### Regular Maintenance
- Monthly security reviews
- Quarterly key rotations
- Annual penetration testing
- Continuous dependency updates

#### Security Patching
- Monitor for JWT library updates
- Subscribe to security advisories
- Test patches in staging environment
- Deploy patches promptly

This security guide provides a comprehensive framework for secure JWT implementation. Always consider your specific threat model and compliance requirements when implementing JWT in production environments.