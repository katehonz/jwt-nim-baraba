## Modern JWT Implementation with Enhanced Security

This project has been upgraded to Nim 2.2.0 with significant cryptographic improvements:

### Security Enhancements
- **Constant-time operations** to prevent timing attacks
- **Enhanced key validation** with minimum key size requirements (RSA ≥ 2048 bits)
- **Secure memory handling** with proper cleanup of sensitive data
- **Algorithm validation** rejecting insecure 'none' algorithm
- **Enhanced time-based claim verification** with clock skew tolerance

### New Cryptographic Features
- **PSS algorithm support** (PS256, PS384, PS512) - framework ready
- **Secure random number generation** capabilities
- **Improved error handling** with secure memory cleanup on failure
- **Enhanced EC and RSA validation** with curve and key size checks

### Modern Standards Compliance
- **RFC 7519 compliant** JWT implementation
- **Nim 2.2.0 compatibility** with modern language features
- **BearSSL backend** for cryptographic operations
- **Security best practices** built-in by default

### Performance Improvements
- **Optimized memory usage** with better buffer management
- **Fast cryptographic operations** leveraging BearSSL
- **Efficient base64 encoding/decoding** with URL-safe variants

### API Changes
- Enhanced `verify()` with comprehensive security checks
- Improved error handling with specific security exceptions
- New utility functions for secure comparisons
- Enhanced time claim validation with security margins

This modern implementation provides enterprise-grade security while maintaining backward compatibility for existing JWT workflows.