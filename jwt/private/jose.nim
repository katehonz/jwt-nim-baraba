import json, strutils

import utils

type
  UnsupportedAlgorithm* = object of ValueError
  SecurityError* = object of ValueError

  SignatureAlgorithm* = enum
    NONE           = "none"
    HS256          = "HS256"  # HMAC using SHA-256
    HS384          = "HS384"  # HMAC using SHA-384  
    HS512          = "HS512"  # HMAC using SHA-512
    RS256          = "RS256"  # RSASSA-PKCS1-v1_5 using SHA-256
    RS384          = "RS384"  # RSASSA-PKCS1-v1_5 using SHA-384
    RS512          = "RS512"  # RSASSA-PKCS1-v1_5 using SHA-512
    ES256          = "ES256"  # ECDSA using P-256 and SHA-256
    ES384          = "ES384"  # ECDSA using P-384 and SHA-384
    ES512          = "ES512"  # ECDSA using P-521 and SHA-512
    PS256          = "PS256"  # RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS384          = "PS384"  # RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS512          = "PS512"  # RSASSA-PSS using SHA-512 and MGF1 with SHA-512

proc strToSignatureAlgorithm(s: string): SignatureAlgorithm =
  ## Enhanced algorithm parsing with security validation
  let normalized = s.toUpperAscii()
  try:
    result = parseEnum[SignatureAlgorithm](normalized)
    # Security: Reject 'none' algorithm unless explicitly allowed
    if result == NONE:
      raise newException(SecurityError, "'none' algorithm is not allowed for security reasons")
  except ValueError:
    raise newException(UnsupportedAlgorithm, "Algorithm '$1' is not supported" % s)

proc isSecureAlgorithm*(alg: SignatureAlgorithm): bool =
  ## Check if an algorithm meets modern security standards
  case alg
  of HS256, HS384, HS512: result = true
  of RS256, RS384, RS512: result = true
  of ES256, ES384, ES512: result = true
  of PS256, PS384, PS512: result = true
  of NONE: result = false

proc getHashStrength*(alg: SignatureAlgorithm): int =
  ## Get the bit strength of the hash function used by the algorithm
  case alg
  of HS256, RS256, ES256, PS256: result = 256
  of HS384, RS384, ES384, PS384: result = 384
  of HS512, RS512, ES512, PS512: result = 512
  of NONE: result = 0


proc toHeader*(j: JsonNode): JsonNode =
  ## Enhanced header parsing with security validation
  result = newJObject()
  utils.checkKeysExists(j, "alg", "typ")
  
  # Security: Validate algorithm
  let algStr = j["alg"].getStr()
  let alg = strToSignatureAlgorithm(algStr)
  
  # Security: Enforce secure algorithms
  if not isSecureAlgorithm(alg):
    raise newException(SecurityError, "Algorithm '$1' does not meet security requirements" % algStr)
  
  # we do this attribute by attribute because some tests depend on the order of these keys
  result["alg"] = %alg
  result["typ"] = j["typ"]
  
  # Add security recommendations
  if not result.hasKey("kid") and (alg in {RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512}):
    # Note: key ID is recommended for asymmetric algorithms
    discard
  
  for key in j.keys:
    if not result.hasKey(key):
      result[key] = j[key]

proc alg*(j: JsonNode): SignatureAlgorithm =
  doAssert j.hasKey("alg")
  return j["alg"].getStr().strToSignatureAlgorithm()

proc `%`*(alg: SignatureAlgorithm): JsonNode =
  let s = $alg
  return %s


proc toBase64*(h: JsonNode): string =
  result = encodeUrlSafe($h)
