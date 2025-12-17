# JWT for Nim Usage Examples

This directory contains practical examples demonstrating various JWT usage patterns and security best practices.

## Available Examples

### 1. Basic JWT Example
**File:** `basic_jwt.nim`

Demonstrates core JWT functionality:
- Token creation with custom claims
- HMAC signing and verification
- Basic claim extraction

**Run:**
```bash
nim c -r examples/basic_jwt.nim
```

### 2. RSA Signature Example
**File:** `rsa_jwt.nim`

Shows asymmetric key cryptography:
- RSA key usage with PEM formatted keys
- Key identifiers for rotation
- Algorithm security information

**Run:**
```bash
nim c -r examples/rsa_jwt.nim
```

### 3. Web API Authentication
**File:** `web_api_auth.nim`

Realistic web API authentication scenario:
- User login and password authentication
- Access and refresh token separation
- Protected API endpoint simulation
- Token refresh mechanism

**Run:**
```bash
nim c -r examples/web_api_auth.nim
```

### 4. Security Best Practices
**File:** `security_best_practices.nim`

Advanced security features and patterns:
- Secure key generation
- Token blacklisting for replay protection
- Key rotation with key identifiers
- Comprehensive security validation
- Attack scenario demonstrations

**Run:**
```bash
nim c -r examples/security_best_practices.nim
```

## Usage Instructions

### Prerequisites

All examples require:
- Nim 2.2.0 or later
- JWT for Nim library installed
- BearSSL dependency

```bash
# Install JWT library
nimble install jwt

# Ensure Nim 2.2.0+
choosenim install 2.2.0
```

### Running Examples

1. **Navigate to project root:**
   ```bash
   cd /path/to/jwt-nim-baraba
   ```

2. **Compile and run specific example:**
   ```bash
   nim c -r examples/basic_jwt.nim
   ```

3. **Run all examples:**
   ```bash
   # Basic example
   nim c -r examples/basic_jwt.nim && echo ""
   
   # RSA example
   nim c -r examples/rsa_jwt.nim && echo ""
   
   # Web API example
   nim c -r examples/web_api_auth.nim && echo ""
   
   # Security example
   nim c -r examples/security_best_practices.nim
   ```

### Customizing Examples

#### Change Algorithm
```nim
# In any example, change the algorithm
let algorithm = RS384  # Instead of HS256
```

#### Modify Token Claims
```nim
# Add custom claims to any example
claims["department"] = newStringClaim("engineering")
claims["role"] = newStringClaim("admin")
claims["permissions"] = newStringClaim("read:users write:users")
```

#### Adjust Expiration Times
```nim
# Change token lifetimes
claims["exp"] = newTimeClaim(getTime() + 5.minutes)  # Shorter
claims["exp"] = newTimeClaim(getTime() + 24.hours)  # Longer
```

## Example Output Samples

### Basic JWT Example Output
```
=== Basic JWT Example ===
Token created: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNzAxMjM0NTY3LCJleHAiOjE3MDEyMzgxNjd9.signature

Token valid: true
Subject: 1234567890
Name: John Doe
Expires: 2023-11-28 10:30:00
```

### Web API Authentication Output
```
=== Web API Authentication Example ===

=== Login Endpoint ===
Username: admin
User authenticated: admin@example.com
Access Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiI...
Refresh Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwidHlwZSI6InJlZnJlc2gifQ.signature...

=== Protected API Call ===
User ID: 1
Username: admin
Email: admin@example.com
Scope: read:profile write:profile
Token Type: access
API call successful!
```

### Security Best Practices Output
```
=== JWT Security Best Practices Example ===
Generated secure HMAC key: aB3d5F7h9JkLmNoPqRsTuVwXyZaBcDeF...

=== Security Scenario 1: Valid Token ===
Created valid token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ5b3VyLXNlY3VyZS1hcHAuY29tIiwic3ViIjoidXNlci0xMjMiLCJhdWQiOiJhcGkuZXhhbXBsZS5jb20i...
Token validation successful for user: user-123
  Algorithm: HS256 (256 bits)
  Audience: api.example.com
  Key ID: key-2023-12-001
  JWT ID: jti-1701234567-aB3d5F7h9

Verification result: true

=== Security Scenario 2: Replay Attack ===
Replay attempt result: false
Security Alert: Token replay detected
```

## Security Notes for Examples

### Production Usage
These examples are for educational purposes. In production:

1. **Store keys securely** - Use environment variables, secure storage, or key management services
2. **Use HTTPS** - Never transmit JWT tokens over unencrypted connections
3. **Implement rate limiting** - Prevent brute force attacks on authentication endpoints
4. **Add logging and monitoring** - Track token usage and security events
5. **Use database storage** - Store user data securely, don't rely on tokens for sensitive information

### Key Security Practices Demonstrated

✅ **Algorithm Validation** - Rejects insecure algorithms  
✅ **Token Expiration** - Uses appropriate expiration times  
✅ **Replay Protection** - Implements token blacklisting  
✅ **Key Rotation** - Supports key rotation with identifiers  
✅ **Input Validation** - Comprehensive validation of inputs  
✅ **Error Handling** - Secure error handling without information leakage  
✅ **Constant-time Operations** - Protection against timing attacks  

### Common Mistakes Avoided

❌ **Hardcoded secrets** in production code  
❌ **Long-lived tokens** without refresh mechanism  
❌ **Missing audience validation**  
❌ **No replay protection**  
❌ **Insecure algorithm usage**  
❌ **Missing time validation**  
❌ **Information leakage in error messages**  

## Learning Path

### Beginner
1. Start with `basic_jwt.nim` to understand core concepts
2. Learn about token structure and basic signing/verification
3. Understand different algorithm types

### Intermediate
1. Study `rsa_jwt.nim` for asymmetric cryptography
2. Learn about key management and rotation
3. Understand security considerations for different algorithms

### Advanced
1. Analyze `web_api_auth.nim` for real-world implementation
2. Study `security_best_practices.nim` for comprehensive security
3. Learn about attack vectors and mitigation strategies
4. Understand compliance requirements and auditing

## Troubleshooting

### Common Issues

**Compilation Errors:**
```bash
# Ensure Nim 2.2.0+ is installed
choosenim install 2.2.0

# Check JWT library installation
nimble list jwt
```

**Runtime Errors:**
- "Invalid token": Check token format and ensure it's not corrupted
- "Security error": Review algorithm usage and key formats
- "ValueError": Verify key sizes and formats

**Performance Issues:**
- Use HS256 for symmetric key scenarios (faster)
- Use ES256 for asymmetric key scenarios (faster than RSA)
- Keep token payloads small for better performance

### Getting Help

- Check the [API Documentation](../docs/API.md)
- Review the [Security Guidelines](../docs/SECURITY.md)
- Consult the [Migration Guide](../docs/MIGRATION.md) if upgrading
- Create an issue on GitHub for specific problems

## Contributing

Have an idea for a new example? Please:

1. Create a new `.nim` file with clear documentation
2. Include security best practices
3. Add proper error handling
4. Update this README with your example description
5. Submit a pull request

Examples should demonstrate:
- Specific JWT use cases
- Security best practices
- Common implementation patterns
- Educational value for the community