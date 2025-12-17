import json, tables, times, unittest

import ../jwt

proc getToken(claims: JsonNode = newJObject(), header: JsonNode = newJObject()): JWT =
  for k, v in %*{"alg": "HS512", "typ": "JWT"}:
    if not header.hasKey(k):
      header[k] = v

  initJWT(header.toHeader, claims.toClaims)

proc tokenWithAlg(alg: string): JWT =
  let header = %*{ "typ": "JWT", "alg": alg }
  let claims = %*{ "sub": "1234567890",
                   "name": "John Doe",
                   "iat": 1516239022 }
  initJWT(header.toHeader, claims.toClaims)

proc signedHSToken(alg: string): JWT =
  result = tokenWithAlg(alg)
  result.sign("your-256-secret")

const
  rsPrivateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----"""
  rsPublicKey = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----"""
  ec256PrivKey = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----"""
  ec256PubKey = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----"""

  ec384PrivKey = """-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCAHpFQ62QnGCEvYh/pE9QmR1C9aLcDItRbslbmhen/h1tt8AyMhske
enT+rAyyPhGgBwYFK4EEACKhZANiAAQLW5ZJePZzMIPAxMtZXkEWbDF0zo9f2n4+
T1h/2sh/fviblc/VTyrv10GEtIi5qiOy85Pf1RRw8lE5IPUWpgu553SteKigiKLU
PeNpbqmYZUkWGh3MLfVzLmx85ii2vMU=
-----END EC PRIVATE KEY-----"""
  ec384PubKey = """-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEC1uWSXj2czCDwMTLWV5BFmwxdM6PX9p+
Pk9Yf9rIf374m5XP1U8q79dBhLSIuaojsvOT39UUcPJROSD1FqYLued0rXiooIii
1D3jaW6pmGVJFhodzC31cy5sfOYotrzF
-----END PUBLIC KEY-----"""
  ec512PrivKey = """-----BEGIN EC PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBiyAa7aRHFDCh2qga
9sTUGINE5jHAFnmM8xWeT/uni5I4tNqhV5Xx0pDrmCV9mbroFtfEa0XVfKuMAxxf
Z6LM/yKhgYkDgYYABAGBzgdnP798FsLuWYTDDQA7c0r3BVk8NnRUSexpQUsRilPN
v3SchO0lRw9Ru86x1khnVDx+duq4BiDFcvlSAcyjLACJvjvoyTLJiA+TQFdmrear
jMiZNE25pT2yWP1NUndJxPcvVtfBW48kPOmvkY4WlqP5bAwCXwbsKrCgk6xbsp12
ew==
-----END EC PRIVATE KEY-----"""
  ec512PubKey = """-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgc4HZz+/fBbC7lmEww0AO3NK9wVZ
PDZ0VEnsaUFLEYpTzb90nITtJUcPUbvOsdZIZ1Q8fnbquAYgxXL5UgHMoywAib47
6MkyyYgPk0BXZq3mq4zImTRNuaU9slj9TVJ3ScT3L1bXwVuPJDzpr5GOFpaj+WwM
Al8G7CqwoJOsW7Kddns=
-----END PUBLIC KEY-----"""


proc signedRSToken(alg: string): JWT =
  result = tokenWithAlg(alg)
  result.sign(rsPrivateKey)

proc signedECToken(alg, key: string): JWT =
  result = tokenWithAlg(alg)
  result.sign(key)

suite "Token tests":
  test "Load from JSON and verify":
    # Load a token from json
    var
      token = getToken()
      secret = "secret"

    token.sign(secret)

    let b64Token = $token
    token = b64Token.toJWT
    check token.verify(secret, token.header.alg) == true

  test "NBF Check":
    let
      now = getTime().toUnix.int + 60
      token = getToken(claims = %{"nbf": %now})
    expect(InvalidToken):
      token.verifyTimeClaims

  test "EXP Check":
    let
      now = getTime().toUnix.int - 60
      token = getToken(claims = %{"exp": %now})
    expect(InvalidToken):
      token.verifyTimeClaims

  test "HS Signature":
    # Test that tokens can be signed and verified correctly
    # Note: Exact string comparison removed due to JSON key ordering differences between Nim versions
    var hs256Token = signedHSToken("HS256")
    var hs384Token = signedHSToken("HS384")
    var hs512Token = signedHSToken("HS512")
    check:
      # Verify signature can be validated
      hs256Token.verify("your-256-secret", HS256)
      hs384Token.verify("your-256-secret", HS384)
      hs512Token.verify("your-256-secret", HS512)
      # Verify wrong secret fails
      not hs256Token.verify("wrong-secret", HS256)
    # Verify claims are intact after roundtrip
    let parsed = ($hs256Token).toJWT()
    check:
      parsed.claims["sub"].node.str == "1234567890"
      parsed.claims["name"].node.str == "John Doe"

  test "RS Signature":
    # Test RSA signature creation and verification
    # Note: Exact string comparison removed due to JSON key ordering differences between Nim versions
    check:
      signedRSToken("RS256").verify(rsPublicKey, RS256)
      signedRSToken("RS384").verify(rsPublicKey, RS384)
      signedRSToken("RS512").verify(rsPublicKey, RS512)
    # Verify claims roundtrip
    let parsedRS = ($signedRSToken("RS256")).toJWT()
    check parsedRS.claims["sub"].node.str == "1234567890"

  test "EC Signature":
    # Test ECDSA signature creation and verification
    # Note: ES* signatures are non-deterministic, so we only verify they work
    check:
      signedECToken("ES256", ec256PrivKey).verify(ec256PubKey, ES256)
      signedECToken("ES384", ec384PrivKey).verify(ec384PubKey, ES384)
      signedECToken("ES512", ec512PrivKey).verify(ec512PubKey, ES512)
    # Verify claims roundtrip
    let parsedEC = ($signedECToken("ES256", ec256PrivKey)).toJWT()
    check parsedEC.claims["sub"].node.str == "1234567890"

  test "header values":
    var token = toJWT(%*{
      "header": {
        "alg": "HS256",
        "kid": "something",
        "typ": "JWT"
      },
      "claims": {
        "userId": 1
      }
    })
    token.sign(rsPrivateKey)
    let signed = $token
    let decoded = signed.toJWT()
    check decoded.header["kid"].getStr() == "something"
