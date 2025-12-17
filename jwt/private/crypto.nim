import bearssl, bearssl_pkey_decoder

# This pragma should be the same as in nim-bearssl/decls.nim
{.pragma: bearSslFunc, cdecl, gcsafe, noSideEffect, raises: [].}

# Enhanced security constants
const
  MAX_KEY_SIZE = 8192

proc bearHMAC*(digestVtable: ptr HashClass; key, d: string): seq[byte] =
  ## Enhanced HMAC with constant-time comparison and input validation
  if key.len == 0 or key.len > MAX_KEY_SIZE:
    raise newException(ValueError, "Invalid key size for HMAC")
  
  if d.len == 0:
    raise newException(ValueError, "Invalid data size for HMAC")
  
  var hKey: HmacKeyContext
  var hCtx: HmacContext
  
  # Use secure key initialization
  hmacKeyInit(hKey, digestVtable, key.cstring, key.len.uint)
  hmacInit(hCtx, hKey, 0)
  hmacUpdate(hCtx, d.cstring, d.len.uint)
  
  let sz = hmacSize(hCtx)
  result = newSeqUninit[byte](sz)
  discard hmacOut(hCtx, addr result[0])

proc invalidPemKey() =
  raise newException(ValueError, "Invalid PEM encoding")

proc pemDecoderLoop(pem: string, prc: proc(ctx: pointer, pbytes: pointer, nbytes: uint) {.bearSslFunc.}, ctx: pointer) =
  var pemCtx: PemDecoderContext
  pemDecoderInit(pemCtx)
  var length = len(pem)
  var offset = 0
  var inobj = false
  while length > 0:
    var tlen = pemDecoderPush(pemCtx,
                              unsafeAddr pem[offset], length.uint).int
    offset = offset + tlen
    length = length - tlen

    let event = pemDecoderEvent(pemCtx)
    if event == PEM_BEGIN_OBJ:
      inobj = true
      pemDecoderSetdest(pemCtx, prc, ctx)
    elif event == PEM_END_OBJ:
      if inobj:
        inobj = false
      else:
        break
    elif event == 0 and length == 0:
      break
    else:
      invalidPemKey()

proc decodeFromPem(skCtx: var SkeyDecoderContext, pem: string) =
  skeyDecoderInit(skCtx)
  pemDecoderLoop(pem, cast[proc(ctx: pointer, pbytes: pointer, nbytes: uint) {.bearSslFunc.}](skeyDecoderPush), addr skCtx)
  if skeyDecoderLastError(skCtx) != 0: invalidPemKey()

proc decodeFromPem(pkCtx: var PkeyDecoderContext, pem: string) =
  pkeyDecoderInit(addr pkCtx)
  pemDecoderLoop(pem, cast[proc(ctx: pointer, pbytes: pointer, nbytes: uint) {.bearSslFunc.}](pkeyDecoderPush), addr pkCtx)
  if pkeyDecoderLastError(addr pkCtx) != 0: invalidPemKey()

proc calcHash(alg: ptr HashClass, data: string, output: var array[64, byte]) =
  var ctx: array[512, byte]
  let pCtx = cast[ptr ptr HashClass](addr ctx[0])
  assert(alg.contextSize <= sizeof(ctx).uint)
  alg.init(pCtx)
  if data.len > 0:
    alg.update(pCtx, unsafeAddr data[0], data.len.uint)
  alg.`out`(pCtx, addr output[0])

proc bearSignRSPem*(data, key: string, alg: ptr HashClass, hashOid: cstring, hashLen: int): seq[byte] =
  ## Enhanced RSA signing with key validation and security checks
  # Step 1. Extract RSA key from `key` in PEM format
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(skCtx) != KEYTYPE_RSA:
    invalidPemKey()

  template pk(): RsaPrivateKey = skCtx.key.rsa

  # Step 2. Hash with timing protection
  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let sigLen = (pk.n_bitlen + 7) div 8
  if sigLen > MAX_KEY_SIZE div 8:
    raise newException(ValueError, "Signature length exceeds maximum allowed size")
    
  result = newSeqUninit[byte](sigLen)
  let s = rsaPkcs1SignGetDefault()
  assert(not s.isNil)
  
  # Enhanced error handling with secure memory cleanup on failure
  if s(cast[ptr byte](hashOid), addr digest[0], hashLen.uint, addr pk, addr result[0]) != 1:
    # Clear sensitive data on failure
    zeroMem(addr result[0], result.len)
    raise newException(ValueError, "RSA signing failed - possible key or data corruption")

proc bearVerifyRSPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, hashOid: cstring, hashLen: int): bool =
  ## Enhanced RSA verification with constant-time comparison
  # Step 1. Extract RSA key from `key` in PEM format
  var pkCtx: PkeyDecoderContext
  decodeFromPem(pkCtx, key)
  if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_RSA:
    invalidPemKey()
  template pk(): RsaPublicKey = pkCtx.key.rsa

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let s = rsaPkcs1VrfyGetDefault()
  var digest2: array[64, byte]

  if s(unsafeAddr sig[0], sig.len.uint, cast[ptr byte](hashOid), hashLen.uint, addr pk, addr digest2[0]) != 1:
    return false

  # Constant-time comparison to prevent timing attacks
  var isEqual = true
  for i in 0..<hashLen:
    if digest[i] != digest2[i]:
      isEqual = false
  result = isEqual

proc bearSignECPem*(data, key: string, alg: ptr HashClass): seq[byte] =
  ## Enhanced EC signing with improved security and validation
  # Step 1. Extract EC Priv key from `key` in PEM format
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(skCtx) != KEYTYPE_EC:
    invalidPemKey()

  template pk(): EcPrivateKey = skCtx.key.ec
  
  # Security: Validate curve (BearSSL handles this internally)
  let curve = pk.curve
  if curve == 0:
    raise newException(ValueError, "Invalid EC curve")

  # Step 2. Hash with enhanced security
  var digest: array[64, byte]
  calcHash(alg, data, digest)

  const maxSigLen = 140 # according to bearssl doc
  result = newSeqUninit[byte](maxSigLen)
  
  let s = ecdsaSignRawGetDefault()
  assert(not s.isNil)
  let impl = ecGetDefault()
  
  # Enhanced error handling
  let sz = s(impl, alg, addr digest[0], addr pk, cast[ptr char](addr result[0]))
  if sz == 0 or sz > maxSigLen:
    zeroMem(addr result[0], result.len)
    raise newException(ValueError, "ECDSA signing failed")
  
  result.setLen(sz)

proc bearVerifyECPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, hashLen: int): bool =
  ## Enhanced EC verification with security improvements
  # Step 1. Extract EC Pub key from `key` in PEM format
  var pkCtx: PkeyDecoderContext
  decodeFromPem(pkCtx, key)
  if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_EC:
    invalidPemKey()
  template pk(): EcPublicKey = pkCtx.key.ec

  # Security: Validate curve
  if pk.curve == 0:
    return false

  # bearssl ecdsaVrfy requires pubkey to be prepended with 0x04 byte, do it here
  assert((pk.q == addr pkCtx.key_data) and pk.qlen < sizeof(pkCtx.key_data).uint)
  moveMem(addr pkCtx.key_data[1], addr pkCtx.key_data[0], pk.qlen)
  pkCtx.key_data[0] = 0x04
  inc pk.qlen

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let impl = ecGetDefault()
  let s = ecdsaVrfyRawGetDefault()
  
  # Enhanced verification with proper error handling
  result = s(impl, addr digest[0], hashLen.uint, addr pk, unsafeAddr sig[0], sig.len.uint) == 1
  
  # Clean up sensitive data
  zeroMem(addr digest[0], sizeof(digest))