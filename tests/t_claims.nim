import json, unittest

import ../jwt

suite "Claim ops":
  test "Create claims from JSON":
    let asJson = %{
      "iss": %"jane",
      "sub": %"john",
      "nbf": %1234,
      "iat": %1234,
      "exp": %1234,
      "jti": %"token-id",
      "foo": %{"bar": %1}
    }
    let claims = asJson.toClaims
    let toJson = %claims

    assert asJson.len == toJson.len
    for k, v in asJson:
      assert v == toJson[k]

  test "JTI rejects non-string":
    expect(ValueError):
      discard newJTI(%123)

  test "ISS rejects non-string":
    expect(ValueError):
      discard newISS(%123)

  test "SUB rejects non-string":
    expect(ValueError):
      discard newSUB(%123)

  test "AUD accepts string":
    let aud = newAUD("test")
    check aud.node.kind == JArray
    check aud.node.len == 1

  test "AUD accepts array":
    let aud = newAUD(@["a", "b"])
    check aud.node.kind == JArray
    check aud.node.len == 2

  test "AUD rejects int":
    expect(ValueError):
      discard newAUD(%123)

  test "Time claims from int":
    let nbf = newNBF(1000'i64)
    check nbf.node.num == 1000

  test "Time claims from string":
    let exp = newEXP("2000")
    check exp.node.num == 2000

  test "getClaimTime":
    let iat = newIAT(1516239022'i64)
    let t = iat.getClaimTime
    check t.toUnix == 1516239022

  test "Convenience claim constructors":
    let s = newStringClaim("hello")
    check s.node.str == "hello"
    check s.kind == GENERAL

    let i = newIntClaim(42)
    check i.node.num == 42

    let b = newBoolClaim(true)
    check b.node.bval == true

  test "Claims toBase64 roundtrip":
    let claims = newClaims(("sub", newStringClaim("user")), ("iss", newStringClaim("test")))
    let b64 = claims.toBase64
    check b64.len > 0

  test "Empty claims":
    let claims = newClaims()
    check claims.len == 0
