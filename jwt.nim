import json, strutils, tables, times
import bearssl

from jwt/private/crypto import bearHMAC, bearSignRSPem, bearSignECPem, bearVerifyRSPem, bearVerifyECPem

import jwt/private/[claims, jose, utils]

type
  InvalidToken* = object of ValueError

  JWT* = object
    headerB64: string
    claimsB64: string
    header*: JsonNode
    claims*: TableRef[string, Claim]
    signature*: seq[byte]

export claims
export jose

proc splitToken(s: string): seq[string] =
  let parts = s.split(".")
  if parts.len != 3:
    raise newException(InvalidToken, "Invalid token")
  result = parts

proc initJWT*(header: JsonNode, claims: TableRef[string, Claim], signature: seq[byte] = @[]): JWT =
  JWT(
    headerB64: header.toBase64,
    claimsB64: claims.toBase64,
    header: header,
    claims: claims,
    signature: signature
  )

# Load up a b64url string to JWT
proc toJWT*(s: string): JWT =
  var parts = splitToken(s)
  let
    headerB64 = parts[0]
    claimsB64 = parts[1]
    headerJson = parseJson(decodeUrlSafeAsString(headerB64))
    claimsJson = parseJson(decodeUrlSafeAsString(claimsB64))
    signature = decodeUrlSafe(parts[2])

  JWT(
    headerB64: headerB64,
    claimsB64: claimsB64,
    header: headerJson.toHeader(),
    claims: claimsJson.toClaims(),
    signature: signature
  )

proc toJWT*(node: JsonNode): JWT =
  initJWT(node["header"].toHeader, node["claims"].toClaims)

# Encodes the raw signature to b64url
proc signatureToB64(token: JWT): string =
  assert token.signature.len != 0
  result = encodeUrlSafe(token.signature)

proc loaded*(token: JWT): string =
  token.headerB64 & "." & token.claimsB64

proc parsed*(token: JWT): string =
  result = token.header.toBase64 & "." & token.claims.toBase64

# Enhanced string signing with security improvements
proc signString*(toSign: string, secret: string, algorithm: SignatureAlgorithm = HS256): seq[byte] =
  ## Sign data with enhanced security and validation
  if toSign.len == 0:
    raise newException(ValueError, "Cannot sign empty data")
  
  if secret.len == 0:
    raise newException(ValueError, "Secret key cannot be empty")

  template hsSign(meth: typed): seq[byte] =
    crypto.bearHMAC(addr meth, secret, toSign)

  template rsSign(hc, oid: typed, hashLen: int): seq[byte] =
    crypto.bearSignRSPem(toSign, secret, addr hc, oid, hashLen)

  template ecSign(hc: typed): seq[byte] =
    crypto.bearSignECPem(toSign, secret, addr hc)
  
  case algorithm
  of HS256:
    return hsSign(sha256Vtable)
  of HS384:
    return hsSign(sha384Vtable)
  of HS512:
    return hsSign(sha512Vtable)
  of RS256:
    return rsSign(sha256Vtable, HASH_OID_SHA256, sha256SIZE)
  of RS384:
    return rsSign(sha384Vtable, HASH_OID_SHA384, sha384SIZE)
  of RS512:
    return rsSign(sha512Vtable, HASH_OID_SHA512, sha512SIZE)
  of ES256:
    return ecSign(sha256Vtable)
  of ES384:
    return ecSign(sha384Vtable)
  of ES512:
    return ecSign(sha512Vtable)
  of PS256, PS384, PS512:
    # Note: PSS algorithms would require additional BearSSL support
    raise newException(UnsupportedAlgorithm, "PSS algorithms not yet implemented")
  of NONE:
    raise newException(SecurityError, "Cannot sign with 'none' algorithm")


# Enhanced signature verification with timing attacks protection
proc verifySignature*(data: string, signature: seq[byte], secret: string,
    alg: SignatureAlgorithm): bool =
  ## Verify signature with enhanced security and timing protection
  if data.len == 0 or signature.len == 0 or secret.len == 0:
    return false

  case alg
  of HS256, HS384, HS512:
    try:
      let dataSignature = signString(data, secret, alg)
      # Use constant-time comparison for HMAC verification
      result = secureCompare(dataSignature, signature)
    except:
      result = false
  of RS256:
    result = crypto.bearVerifyRSPem(data, secret, signature, addr sha256Vtable, HASH_OID_SHA256, sha256SIZE)
  of RS384:
    result = crypto.bearVerifyRSPem(data, secret, signature, addr sha384Vtable, HASH_OID_SHA384, sha384SIZE)
  of RS512:
    result = crypto.bearVerifyRSPem(data, secret, signature, addr sha512Vtable, HASH_OID_SHA512, sha512SIZE)
  of ES256:
    result = crypto.bearVerifyECPem(data, secret, signature, addr sha256Vtable, sha256SIZE)
  of ES384:
    result = crypto.bearVerifyECPem(data, secret, signature, addr sha384Vtable, sha384SIZE)
  of ES512:
    result = crypto.bearVerifyECPem(data, secret, signature, addr sha512Vtable, sha512SIZE)
  of PS256, PS384, PS512:
    # Note: PSS algorithms would require additional BearSSL support
    return false
  of NONE:
    return false


proc sign*(token: var JWT, secret: string) =
  assert token.signature.len == 0
  token.signature = signString(token.parsed, secret, token.header.alg)

# Enhanced token verification with security improvements
proc verify*(token: JWT, secret: string, alg: SignatureAlgorithm): bool =
  ## Verify JWT token with comprehensive security checks
  # Security: Check algorithm matches expected algorithm
  if token.header.alg != alg:
    return false
    
  # Security: Reject 'none' algorithm
  if alg == NONE:
    return false
    
  # Security: Verify signature with timing protection
  if not verifySignature(token.loaded, token.signature, secret, alg):
    return false
    
  # Security: Verify time-based claims
  try:
    let now = getTime()
    
    # Security: Check not-before claim with small tolerance
    if token.claims.hasKey("nbf"):
      let nbf = token.claims["nbf"].getClaimTime
      # Add 30 second tolerance for clock skew
      let tolerance = initTimeInterval(seconds = 30)
      if now + tolerance < nbf:
        return false

    # Security: Check expiration claim with security margin
    if token.claims.hasKey("exp"):
      let exp = token.claims["exp"].getClaimTime
      if now > exp:
        return false
        
    # Security: Check issued-at claim (iat) - should not be too far in future
    if token.claims.hasKey("iat"):
      let iat = token.claims["iat"].getClaimTime
      # Reject tokens issued more than 5 minutes in future
      let futureTolerance = initTimeInterval(minutes = 5)
      if iat > now + futureTolerance:
        return false

    return true
  except:
    return false
      


proc toString*(token: JWT): string =
  token.header.toBase64 & "." & token.claims.toBase64 & "." & token.signatureToB64


proc `$`*(token: JWT): string =
  token.toString


proc `%`*(token: JWT): JsonNode =
  let s = $token
  %s

proc verifyTimeClaims*(token: JWT) =
  ## Enhanced time-based claims verification with security margins
  let now = getTime()
  
  # Security: Check not-before claim with small tolerance
  if token.claims.hasKey("nbf"):
    let nbf = token.claims["nbf"].getClaimTime
    # Add 30 second tolerance for clock skew
    let tolerance = initTimeInterval(seconds = 30)
    if now + tolerance < nbf:
      raise newException(InvalidToken, "Token cannot be used yet")

  # Security: Check expiration claim with security margin
  if token.claims.hasKey("exp"):
    let exp = token.claims["exp"].getClaimTime
    if now > exp:
      raise newException(InvalidToken, "Token is expired")
      
  # Security: Check issued-at claim (iat) - should not be too far in future
  if token.claims.hasKey("iat"):
    let iat = token.claims["iat"].getClaimTime
    # Reject tokens issued more than 5 minutes in future
    let futureTolerance = initTimeInterval(minutes = 5)
    if iat > now + futureTolerance:
      raise newException(InvalidToken, "Token was issued too far in the future")
