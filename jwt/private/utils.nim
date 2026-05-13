import json, strutils, volatile

from base64 import nil


proc checkJsonNodeKind*(node: JsonNode, kind: JsonNodeKind) =
  # Check that a given JsonNode has a given kind, raise ValueError if not
  if node.kind != kind:
    raise newException(ValueError, "Invalid kind")


proc checkKeysExists*(node: JsonNode, keys: varargs[string]) =
  for key in keys:
    if not node.hasKey(key):
      raise newException(KeyError, "$# is not present." % key)

proc encodeUrlSafe*(s: openarray[byte]): string =
  when (NimMajor >= 1 and (NimMinor >= 1 or NimPatch >= 2)) or NimMajor >= 2:
    result = base64.encode(s)
  else:
    result = base64.encode(s, newLine="")
  while result.endsWith("="):
    result.setLen(result.len - 1)
  result = result.replace('+', '-').replace('/', '_')

proc encodeUrlSafe*(s: openarray[char]): string {.inline.} =
  encodeUrlSafe(s.toOpenArrayByte(s.low, s.high))

proc decodeUrlSafeAsString*(s: string): string =
  var s = s.replace('-', '+').replace('_', '/')
  while s.len mod 4 > 0:
    s &= "="
  base64.decode(s)

proc decodeUrlSafe*(s: string): seq[byte] =
  let decoded = decodeUrlSafeAsString(s)
  result = newSeq[byte](decoded.len)
  if decoded.len > 0:
    copyMem(addr result[0], unsafeAddr decoded[0], decoded.len)

proc toUtf*(s: seq[byte]): string =
  result = newString(s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)

# Enhanced security utilities for modern cryptographic operations

proc secureCompare*(a, b: openarray[byte]): bool =
  ## Constant-time comparison to prevent timing attacks
  if a.len != b.len:
    return false

  var diff = 0
  for i in 0..<a.len:
    diff = diff or (int(a[i]) xor int(b[i]))

  diff == 0

proc secureCompare*(a, b: string): bool =
  ## Constant-time string comparison
  if a.len != b.len:
    return false
  
  secureCompare(a.toOpenArrayByte(0, a.high), b.toOpenArrayByte(0, b.high))

proc zeroMem*(data: pointer, size: int) =
  ## Secure memory clearing using volatile stores to prevent
  ## compiler optimization from eliminating the zeroing.
  var p = cast[ptr UncheckedArray[byte]](data)
  for i in 0..<size:
    volatileStore(addr p[i], 0'u8)
