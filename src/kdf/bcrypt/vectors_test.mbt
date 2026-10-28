///|
/// The vectors below were produced by the reference `bcrypt` library:
/// password, sixteen salt bytes, cost, and the string it formats to.
/// `scripts/gen_bcrypt_vectors.py` regenerates them.
let vectors : Array[(String, String, Int32, String)] = [
  // password, all-C salt
  (
    "70617373776f7264", "43434343434343434343434343434343", 5, "$2b$05$OyLBOyLBOyLBOyLBOyLBOukfy/WlNdjHyhR9VwUDAjC0biiUiTPse",
  ),
  // empty password
  (
    "", "43434343434343434343434343434343", 5, "$2b$05$OyLBOyLBOyLBOyLBOyLBOu0CWKXc26WbUzOgg0l6auj2FnT6Mpb/G",
  ),
  // one byte
  (
    "61", "000102030405060708090a0b0c0d0e0f", 4, "$2b$04$..CA.uOD/eaGAOmJB.yMBunBitU1jIt2E6xX6kPhDtSnJIjNzugbS",
  ),
  // seventy-two bytes
  (
    "787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
    "101112131415161718191a1b1c1d1e1f", 4, "$2b$04$C/CQCvOTDfaWEPmZF/ycFuJXIM1U87.gxqOKfRYzlMGP7VIuQXzoC",
  ),
  // high-bit bytes
  (
    "80ff007fc3a9", "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0", 6, "$2b$06$mIAemIAemIAemIAemIAem.WdSqjV2.HL1ISOHn1egeyt9acOLajc2",
  ),
  // mixed
  (
    "636f727265637420686f727365206261747465727920737461706c65", "5bbf0ceef39c2b7a1122334455667788",
    5, "$2b$05$U56K5tMaI1mPGhLCTUX1g.kBBjIUknH4jn0mK8EKO48Hi.ftTzGrW",
  ),
]

///|
/// Exactly seventy-two bytes, the longest password the format accepts.
let longest_password : String = "$2b$04$OyLBOyLBOyLBOyLBOyLBOuBtEbza7YykIetz66Y.4wiS78gma7jYq"
