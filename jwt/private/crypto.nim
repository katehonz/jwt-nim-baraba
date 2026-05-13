import bearssl, bearssl_pkey_decoder
import utils

{.pragma: bearSslFunc, cdecl, gcsafe, noSideEffect, raises: [].}

const
  MAX_KEY_SIZE = 8192
  MIN_HMAC_KEY_SIZE = 32
  MIN_RSA_KEY_SIZE = 2048

proc bearHMAC*(digestVtable: ptr HashClass; key, d: string): seq[byte] =
  if key.len < MIN_HMAC_KEY_SIZE:
    raise newException(ValueError, "HMAC key must be at least " & $MIN_HMAC_KEY_SIZE & " bytes")
  if key.len > MAX_KEY_SIZE:
    raise newException(ValueError, "HMAC key exceeds maximum size")
  if d.len == 0:
    raise newException(ValueError, "Invalid data size for HMAC")

  var hKey: HmacKeyContext
  var hCtx: HmacContext
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
  if alg.contextSize > sizeof(ctx).uint:
    raise newException(ValueError, "Hash context size exceeds buffer capacity")
  alg.init(pCtx)
  if data.len > 0:
    alg.update(pCtx, unsafeAddr data[0], data.len.uint)
  alg.`out`(pCtx, addr output[0])

proc bearSignRSPem*(data, key: string, alg: ptr HashClass, hashOid: cstring, hashLen: int): seq[byte] =
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(skCtx) != KEYTYPE_RSA:
    invalidPemKey()

  template pk(): RsaPrivateKey = skCtx.key.rsa

  if pk.nBitlen < MIN_RSA_KEY_SIZE.uint32:
    raise newException(ValueError, "RSA key must be at least " & $MIN_RSA_KEY_SIZE & " bits")

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let sigLen = (pk.n_bitlen + 7) div 8
  if sigLen > MAX_KEY_SIZE div 8:
    raise newException(ValueError, "Signature length exceeds maximum allowed size")

  result = newSeqUninit[byte](sigLen)
  let s = rsaPkcs1SignGetDefault()
  if s.isNil:
    raise newException(ValueError, "RSA signing implementation not available")

  if s(cast[ptr byte](hashOid), addr digest[0], hashLen.uint, addr pk, addr result[0]) != 1:
    zeroMem(addr result[0], result.len)
    raise newException(ValueError, "RSA signing failed")

proc bearVerifyRSPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, hashOid: cstring, hashLen: int): bool =
  var pkCtx: PkeyDecoderContext
  decodeFromPem(pkCtx, key)
  if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_RSA:
    invalidPemKey()
  template pk(): RsaPublicKey = pkCtx.key.rsa

  if pk.nlen.uint * 8 < MIN_RSA_KEY_SIZE.uint:
    raise newException(ValueError, "RSA key must be at least " & $MIN_RSA_KEY_SIZE & " bits")

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let s = rsaPkcs1VrfyGetDefault()
  if s.isNil:
    return false
  var digest2: array[64, byte]

  if s(unsafeAddr sig[0], sig.len.uint, cast[ptr byte](hashOid), hashLen.uint, addr pk, addr digest2[0]) != 1:
    return false

  result = secureCompare(digest.toOpenArray(0, hashLen - 1), digest2.toOpenArray(0, hashLen - 1))

proc bearSignECPem*(data, key: string, alg: ptr HashClass): seq[byte] =
  var skCtx: SkeyDecoderContext
  decodeFromPem(skCtx, key)
  if skeyDecoderKeyType(skCtx) != KEYTYPE_EC:
    invalidPemKey()

  template pk(): EcPrivateKey = skCtx.key.ec

  let curve = pk.curve
  if curve == 0:
    raise newException(ValueError, "Invalid EC curve")

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  const maxSigLen = 140
  result = newSeqUninit[byte](maxSigLen)

  let s = ecdsaSignRawGetDefault()
  if s.isNil:
    raise newException(ValueError, "ECDSA signing implementation not available")
  let impl = ecGetDefault()

  let sz = s(impl, alg, addr digest[0], addr pk, cast[ptr char](addr result[0]))
  if sz == 0 or sz > maxSigLen:
    zeroMem(addr result[0], result.len)
    raise newException(ValueError, "ECDSA signing failed")

  result.setLen(sz)

proc bearVerifyECPem*(data, key: string, sig: openarray[byte], alg: ptr HashClass, hashLen: int): bool =
  var pkCtx: PkeyDecoderContext
  decodeFromPem(pkCtx, key)
  if pkeyDecoderKeyType(addr pkCtx) != KEYTYPE_EC:
    invalidPemKey()
  template pk(): EcPublicKey = pkCtx.key.ec

  if pk.curve == 0:
    return false

  if pk.qlen >= sizeof(pkCtx.key_data).uint:
    return false
  moveMem(addr pkCtx.key_data[1], addr pkCtx.key_data[0], pk.qlen)
  pkCtx.key_data[0] = 0x04
  inc pk.qlen

  var digest: array[64, byte]
  calcHash(alg, data, digest)

  let impl = ecGetDefault()
  let s = ecdsaVrfyRawGetDefault()

  result = s(impl, addr digest[0], hashLen.uint, addr pk, unsafeAddr sig[0], sig.len.uint) == 1

  zeroMem(addr digest[0], sizeof(digest))
