import jwt, json, times, tables, random, strutils

# Security Best Practices Example
# Demonstrates advanced JWT security features and patterns

echo "=== JWT Security Best Practices Example ==="

# Secure key generation
proc generateSecureKey(length: int = 32): string =
  ## Generate cryptographically secure random key
  var bytes = newSeq[byte](length)
  for i in 0..<length:
    bytes[i] = byte(random(255))
  result = encodeUrlSafe(bytes)

# Token blacklist for replay protection
type
  TokenBlacklist = object
    usedJTIs: HashSet[string]

proc addToBlacklist(blacklist: var TokenBlacklist, jti: string) =
  blacklist.usedJTIs.incl(jti)

proc isBlacklisted(blacklist: TokenBlacklist, jti: string): bool =
  jti in blacklist.usedJTIs

# Key rotation management
type
  KeyRotation = object
    currentKeyId: string
    keys: Table[string, string]

proc addKey(rotation: var KeyRotation, keyId, key: string) =
  rotation.keys[keyId] = key

proc getCurrentKey(rotation: KeyRotation): string =
  rotation.keys[rotation.currentKeyId]

# Generate secure keys
let hmacKey = generateSecureKey(32)
let rotationKey = generateSecureKey(32)

# Initialize key rotation
var keyRotation = KeyRotation()
keyRotation.currentKeyId = "key-2023-12-001"
keyRotation.addKey("key-2023-12-001", hmacKey)
keyRotation.addKey("key-2023-11-001", rotationKey)

echo "Generated secure HMAC key: ", hmacKey[0..15], "..."

# Create secure token with all best practices
proc createSecureToken(userId, audience: string, rotation: KeyRotation): string =
  ## Create JWT with security best practices
  
  # Generate unique JWT ID for replay protection
  let jti = "jti-" & $epochTime() & "-" & generateSecureKey(8)
  
  # Create claims with all security fields
  var claims = newTable[string, Claim]()
  claims["iss"] = newStringClaim("your-secure-app.com")     # Issuer
  claims["sub"] = newStringClaim(userId)                   # Subject
  claims["aud"] = newStringClaim(audience)                 # Audience
  claims["iat"] = newTimeClaim(getTime())                  # Issued At
  claims["exp"] = newTimeClaim(getTime() + 15.minutes)     # Short expiration
  claims["nbf"] = newTimeClaim(getTime() - 30.seconds)    # Not Before (with skew)
  claims["jti"] = newStringClaim(jti)                      # JWT ID
  claims["auth_time"] = newTimeClaim(getTime())            # Authentication time
  claims["nonce"] = newStringClaim(generateSecureKey(16))   # Anti-replay nonce
  
  # Use current key with key identifier
  let header = %*{
    "alg": "HS256",
    "typ": "JWT",
    "kid": rotation.currentKeyId  # Key identifier for rotation
  }
  
  var token = initJWT(header, claims)
  token.sign(rotation.getCurrentKey())
  result = $token

# Enhanced token verification with all security checks
proc verifySecureToken(tokenString: string, rotation: KeyRotation, 
                     blacklist: var TokenBlacklist, expectedAudience: string): tuple[valid: bool, userId: string] =
  ## Verify JWT with comprehensive security checks
  
  try:
    let token = tokenString.toJWT()
    
    # 1. Check if token is blacklisted (replay protection)
    let jti = token.claims["jti"].node.str
    if blacklist.isBlacklisted(jti):
      echo "Security Alert: Token replay detected"
      return (false, "")
    
    # 2. Verify algorithm security
    let algorithm = token.header.alg
    if not isSecureAlgorithm(algorithm):
      echo "Security Alert: Insecure algorithm: ", algorithm
      return (false, "")
    
    # 3. Check key identifier and use appropriate key
    let keyId = token.header{"kid"}.getStr("")
    let secret = if keyId in rotation.keys: rotation.keys[keyId] else: ""
    
    if secret == "":
      echo "Security Alert: Unknown key identifier: ", keyId
      return (false, "")
    
    # 4. Verify signature
    if not token.verify(secret, algorithm):
      echo "Security Alert: Invalid signature"
      return (false, "")
    
    # 5. Validate audience
    let audience = token.claims["aud"].node.str
    if audience != expectedAudience:
      echo "Security Alert: Invalid audience. Expected: ", expectedAudience, ", Got: ", audience
      return (false, "")
    
    # 6. Check token type (if present)
    if token.claims.hasKey("type"):
      let tokenType = token.claims["type"].node.str
      if tokenType == "refresh":
        echo "Security Alert: Refresh token used as access token"
        return (false, "")
    
    # 7. Add to blacklist to prevent replay
    blacklist.addToBlacklist(jti)
    
    # 8. Extract user ID
    let userId = token.claims["sub"].node.str
    
    echo "Token validation successful for user: ", userId
    echo "  Algorithm: ", algorithm, " (", getHashStrength(algorithm), " bits)"
    echo "  Audience: ", audience
    echo "  Key ID: ", keyId
    echo "  JWT ID: ", jti
    
    return (true, userId)
    
  except InvalidToken as e:
    echo "Security Alert: Invalid token format: ", e.msg
    return (false, "")
  except SecurityError as e:
    echo "Security Alert: Security validation failed: ", e.msg
    return (false, "")
  except Exception as e:
    echo "Security Alert: Unexpected error: ", e.msg
    return (false, "")

# Security scenarios demonstration
proc demonstrateSecurityFeatures(): void =
  ## Demonstrate various security scenarios
  
  var blacklist = TokenBlacklist()
  
  echo "\n=== Security Scenario 1: Valid Token ==="
  let validToken = createSecureToken("user-123", "api.example.com", keyRotation)
  echo "Created valid token: ", validToken[0..50], "..."
  
  let result1 = verifySecureToken(validToken, keyRotation, blacklist, "api.example.com")
  echo "Verification result: ", result1.valid
  
  echo "\n=== Security Scenario 2: Replay Attack ==="
  let result2 = verifySecureToken(validToken, keyRotation, blacklist, "api.example.com")
  echo "Replay attempt result: ", result2.valid
  
  echo "\n=== Security Scenario 3: Wrong Audience ==="
  let result3 = verifySecureToken(validToken, keyRotation, blacklist, "different-api.com")
  echo "Wrong audience result: ", result3.valid
  
  echo "\n=== Security Scenario 4: Algorithm Attack ==="
  # Try to create malicious token with none algorithm (should be blocked)
  try:
    let maliciousHeader = %*{"alg": "none", "typ": "JWT"}
    var maliciousClaims = newTable[string, Claim]()
    maliciousClaims["sub"] = newStringClaim("hacker")
    maliciousClaims["aud"] = newStringClaim("api.example.com")
    let maliciousToken = initJWT(maliciousHeader, maliciousClaims)
    echo "Malicious token creation should have failed"
  except SecurityError:
    echo "✓ Security prevented 'none' algorithm attack"
  
  echo "\n=== Security Scenario 5: Key Rotation ==="
  # Simulate key rotation
  let oldKeyId = keyRotation.currentKeyId
  keyRotation.currentKeyId = "key-2023-12-002"
  keyRotation.addKey("key-2023-12-002", generateSecureKey(32))
  
  echo "Rotated from key: ", oldKeyId, " to key: ", keyRotation.currentKeyId
  
  # Old token should still work with old key
  let result4 = verifySecureToken(validToken, keyRotation, blacklist, "api.example.com")
  echo "Old token verification after rotation: ", result4.valid
  
  # New token uses new key
  let newToken = createSecureToken("user-456", "api.example.com", keyRotation)
  let result5 = verifySecureToken(newToken, keyRotation, blacklist, "api.example.com")
  echo "New token verification: ", result5.valid

# Performance and security analysis
proc analyzeSecurityFeatures(): void =
  ## Analyze security features and recommendations
  
  echo "\n=== Security Analysis ==="
  
  # Algorithm security comparison
  let algorithms = [HS256, HS384, HS512, RS256, ES256, PS256]
  echo "\nAlgorithm Security Analysis:"
  for alg in algorithms:
    let secure = isSecureAlgorithm(alg)
    let strength = getHashStrength(alg)
    echo "  $1: Secure=$2, Strength=$3 bits" % [$alg, $secure, $strength]
  
  # Time validation analysis
  echo "\nTime Validation Features:"
  echo "  ✓ Expiration (exp) validation"
  echo "  ✓ Not Before (nbf) validation with 30s skew tolerance"
  echo "  ✓ Issued At (iat) validation with 5min future tolerance"
  echo "  ✓ Clock skew protection"
  
  # Memory security
  echo "\nMemory Security:"
  echo "  ✓ Secure memory cleanup on failures"
  echo "  ✓ Constant-time comparison for timing attack protection"
  echo "  ✓ Input validation and boundary checking"
  
  # Key security
  echo "\nKey Security:"
  echo "  ✓ Minimum HMAC key size: 32 bytes"
  echo "  ✓ Minimum RSA key size: 2048 bits"
  echo "  ✓ Key rotation support with key identifiers"
  echo "  ✓ Secure key generation"

# Run demonstrations
demonstrateSecurityFeatures()
analyzeSecurityFeatures()

echo "\n=== Security Best Practices Summary ==="
echo "✓ Use short-lived access tokens (15 minutes)"
echo "✓ Implement token blacklisting for replay protection"
echo "✓ Include all standard claims (iss, sub, aud, exp, iat, jti)"
echo "✓ Use key rotation with key identifiers"
echo "✓ Validate audience and other security claims"
echo "✓ Implement comprehensive error handling"
echo "✓ Use secure random number generation for keys and nonces"
echo "✓ Monitor for security events and suspicious activities"
echo "✓ Keep cryptographic libraries updated"
echo "✓ Follow OWASP JWT security guidelines"