import json, strutils

import utils

type
  UnsupportedAlgorithm* = object of ValueError
  SecurityError* = object of ValueError

  SignatureAlgorithm* = enum
    NONE           = "none"
    HS256          = "HS256"
    HS384          = "HS384"
    HS512          = "HS512"
    RS256          = "RS256"
    RS384          = "RS384"
    RS512          = "RS512"
    ES256          = "ES256"
    ES384          = "ES384"
    ES512          = "ES512"
    PS256          = "PS256"
    PS384          = "PS384"
    PS512          = "PS512"

proc strToSignatureAlgorithm(s: string): SignatureAlgorithm =
  let normalized = s.toUpperAscii()
  try:
    result = parseEnum[SignatureAlgorithm](normalized)
    if result == NONE:
      raise newException(SecurityError, "'none' algorithm is not allowed")
  except ValueError:
    raise newException(UnsupportedAlgorithm, "Algorithm '$1' is not supported" % s)

proc isSecureAlgorithm*(alg: SignatureAlgorithm): bool =
  case alg
  of HS256, HS384, HS512: result = true
  of RS256, RS384, RS512: result = true
  of ES256, ES384, ES512: result = true
  of PS256, PS384, PS512: result = true
  of NONE: result = false

proc getHashStrength*(alg: SignatureAlgorithm): int =
  case alg
  of HS256, RS256, ES256, PS256: result = 256
  of HS384, RS384, ES384, PS384: result = 384
  of HS512, RS512, ES512, PS512: result = 512
  of NONE: result = 0

proc toHeader*(j: JsonNode): JsonNode =
  result = newJObject()
  utils.checkKeysExists(j, "alg", "typ")

  let algStr = j["alg"].getStr()
  let alg = strToSignatureAlgorithm(algStr)

  if not isSecureAlgorithm(alg):
    raise newException(SecurityError, "Algorithm '$1' does not meet security requirements" % algStr)

  result["alg"] = %alg
  result["typ"] = j["typ"]

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
