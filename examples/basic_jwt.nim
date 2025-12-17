import jwt, json, times, tables

# Basic JWT creation and verification example
# Demonstrates core functionality with HMAC signing

echo "=== Basic JWT Example ==="

# Create token header
let header = %*{
  "alg": "HS256",
  "typ": "JWT"
}

# Create token claims
var claims = newTable[string, Claim]()
claims["sub"] = newStringClaim("1234567890")
claims["name"] = newStringClaim("John Doe")
claims["iat"] = newTimeClaim(getTime())
claims["exp"] = newTimeClaim(getTime() + 1.hours)

# Initialize and sign token
var token = initJWT(header, claims)
token.sign("your-256-bit-secret")

echo "Token created: ", $token

# Verify token
let isValid = token.verify("your-256-bit-secret", HS256)
echo "Token valid: ", isValid

# Parse and read claims
let parsedToken = ($token).toJWT()
echo "Subject: ", parsedToken.claims["sub"].node.str
echo "Name: ", parsedToken.claims["name"].node.str
echo "Expires: ", parsedToken.claims["exp"].getClaimTime()
echo ""