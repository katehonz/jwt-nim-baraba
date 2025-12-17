import jwt, json, times, tables

# RSA Signature Example
# Demonstrates asymmetric key cryptography with RSA keys

echo "=== RSA JWT Example ==="

# RSA Keys (in production, load from secure files)
# These are example keys - generate your own with OpenSSL
let rsaPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7VJTUt9Us8cKB
x6VbZ3KXR5MXi0TmD3U8FRXG0pG1bKpn2y9HdYcGpYfBt3QcP4WwOCnKjXR3xZq
HvZyq8OwYlV4Cb1v1J9vNQxzKpGjxJ3L8QD2R8YmXoP3v9hT7Zy5mF2kQ1L6XhT
8vH9YfX7vK3oP2hQ3v9yT8oH7YqL6oP3rQ9xL8Yv5vH6T2oK9vL3pQ8yH7vX4
K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8
K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8
AgMBAAECggEBAK3b9OvKJx8qK6QyG5z3u6vL5vQ2x8zK6p9vL8yK5oQ3vX6K8pL7
oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7
oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7
oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7
oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7
oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7
QKBgQD6v9L5oK8pQ2yH3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3v
X8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8
K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8
K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8
KBgQDTL9yH5oQ3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5o
P2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP
2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5o
P2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5o
AkEA5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH
8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8o
Q5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8o
JBAN9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5v
X7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7
K9pL2yH3vX8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7
CQQCK5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3
vX8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3v
X8K5oP2rQ8vL9yH5oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3v
AkEA3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5
oT3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5o
T3vX6K8pL7oQ2yH5vX8K9oP3vL6yH8oQ5vX7K9pL2yH3vX8K5oP2rQ8vL9yH5oT3
-----END PRIVATE KEY-----
"""

let rsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCgcelW2dy
l0eTF4tE5g91PBUVxtKQtWyqZ9svR3WHBqWHwbd0HD+FsDgpyo10d8Wah78cqvDs
GJVeAm9b9SfbzUMcymRo8Sdy/EA9kfGJl6D97/YU+2cuZhdpINS+l4U/Lx/XH17y
yt6D9oUN7/ck/KB+2Ki+qD60PcS/GL+bx+k9qCvby96UPMh+b1+CuaD9q0PLy/ch
+aE971+ivKS+6ENsh+1/FvaD97y8vKb8OHb1+ivKS+6ENsh+1/FvaD97y8vKb8OH
b1+ivKS+6ENsh+1/FvaD97y8vKb8OHb1+ivKS+6ENsh+1/FvaD97y8vKb8OHwID
AQAB
-----END PUBLIC KEY-----
"""

# Create token header with RSA algorithm
let header = %*{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "2023-12-rsa-key-001"  # Key identifier for rotation
}

# Create claims with additional security fields
var claims = newTable[string, Claim]()
claims["iss"] = newStringClaim("your-auth-server.com")
claims["sub"] = newStringClaim("user-12345")
claims["aud"] = newStringClaim("your-api.com")
claims["iat"] = newTimeClaim(getTime())
claims["exp"] = newTimeClaim(getTime() + 1.hours)
claims["jti"] = newStringClaim("unique-token-id-123")

# Initialize and sign token with RSA private key
var token = initJWT(header, claims)
token.sign(rsaPrivateKey)

echo "RSA Token created:"
echo $token
echo ""

# Verify token with RSA public key
let isValid = token.verify(rsaPublicKey, RS256)
echo "RSA Token valid: ", isValid

if isValid:
  let parsedToken = ($token).toJWT()
  echo "Issuer: ", parsedToken.claims["iss"].node.str
  echo "Subject: ", parsedToken.claims["sub"].node.str
  echo "Audience: ", parsedToken.claims["aud"].node.str
  echo "Key ID: ", parsedToken.claims["jti"].node.str
  echo ""

echo "=== Algorithm Security Info ==="
echo "Hash strength: ", getHashStrength(RS256), " bits"
echo "Algorithm secure: ", isSecureAlgorithm(RS256)
echo ""