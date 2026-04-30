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

proc signatureToB64(token: JWT): string =
  assert token.signature.len != 0
  result = encodeUrlSafe(token.signature)

proc loaded*(token: JWT): string =
  token.headerB64 & "." & token.claimsB64

proc parsed*(token: JWT): string =
  result = token.header.toBase64 & "." & token.claims.toBase64

proc signString*(toSign: string, secret: string, algorithm: SignatureAlgorithm = HS256): seq[byte] =
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
  of HS256: return hsSign(sha256Vtable)
  of HS384: return hsSign(sha384Vtable)
  of HS512: return hsSign(sha512Vtable)
  of RS256: return rsSign(sha256Vtable, HASH_OID_SHA256, sha256SIZE)
  of RS384: return rsSign(sha384Vtable, HASH_OID_SHA384, sha384SIZE)
  of RS512: return rsSign(sha512Vtable, HASH_OID_SHA512, sha512SIZE)
  of ES256: return ecSign(sha256Vtable)
  of ES384: return ecSign(sha384Vtable)
  of ES512: return ecSign(sha512Vtable)
  of PS256, PS384, PS512:
    raise newException(UnsupportedAlgorithm, "PSS algorithms not yet implemented")
  of NONE:
    raise newException(SecurityError, "Cannot sign with 'none' algorithm")

proc verifySignature*(data: string, signature: seq[byte], secret: string,
    alg: SignatureAlgorithm): bool =
  if data.len == 0 or signature.len == 0 or secret.len == 0:
    return false

  case alg
  of HS256, HS384, HS512:
    try:
      let dataSignature = signString(data, secret, alg)
      result = secureCompare(dataSignature, signature)
    except CatchableError:
      result = false
  of RS256: result = crypto.bearVerifyRSPem(data, secret, signature, addr sha256Vtable, HASH_OID_SHA256, sha256SIZE)
  of RS384: result = crypto.bearVerifyRSPem(data, secret, signature, addr sha384Vtable, HASH_OID_SHA384, sha384SIZE)
  of RS512: result = crypto.bearVerifyRSPem(data, secret, signature, addr sha512Vtable, HASH_OID_SHA512, sha512SIZE)
  of ES256: result = crypto.bearVerifyECPem(data, secret, signature, addr sha256Vtable, sha256SIZE)
  of ES384: result = crypto.bearVerifyECPem(data, secret, signature, addr sha384Vtable, sha384SIZE)
  of ES512: result = crypto.bearVerifyECPem(data, secret, signature, addr sha512Vtable, sha512SIZE)
  of PS256, PS384, PS512: return false
  of NONE: return false

proc sign*(token: var JWT, secret: string) =
  assert token.signature.len == 0
  token.signature = signString(token.parsed, secret, token.header.alg)

proc verify*(token: JWT, secret: string, alg: SignatureAlgorithm): bool =
  if token.header.alg != alg:
    return false
  if alg == NONE:
    return false
  if not verifySignature(token.loaded, token.signature, secret, alg):
    return false
  try:
    let now = getTime()
    if token.claims.hasKey("nbf"):
      let nbf = token.claims["nbf"].getClaimTime
      let tolerance = initTimeInterval(seconds = 30)
      if now + tolerance < nbf:
        return false
    if token.claims.hasKey("exp"):
      let exp = token.claims["exp"].getClaimTime
      if now > exp:
        return false
    if token.claims.hasKey("iat"):
      let iat = token.claims["iat"].getClaimTime
      let futureTolerance = initTimeInterval(minutes = 5)
      if iat > now + futureTolerance:
        return false
    return true
  except CatchableError:
    return false

proc toString*(token: JWT): string =
  token.header.toBase64 & "." & token.claims.toBase64 & "." & token.signatureToB64

proc `$`*(token: JWT): string =
  token.toString

proc `%`*(token: JWT): JsonNode =
  let s = $token
  %s

proc verifyTimeClaims*(token: JWT) =
  let now = getTime()
  if token.claims.hasKey("nbf"):
    let nbf = token.claims["nbf"].getClaimTime
    let tolerance = initTimeInterval(seconds = 30)
    if now + tolerance < nbf:
      raise newException(InvalidToken, "Token cannot be used yet")
  if token.claims.hasKey("exp"):
    let exp = token.claims["exp"].getClaimTime
    if now > exp:
      raise newException(InvalidToken, "Token is expired")
  if token.claims.hasKey("iat"):
    let iat = token.claims["iat"].getClaimTime
    let futureTolerance = initTimeInterval(minutes = 5)
    if iat > now + futureTolerance:
      raise newException(InvalidToken, "Token was issued too far in the future")
