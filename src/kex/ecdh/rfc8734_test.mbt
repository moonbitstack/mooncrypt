// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0
//
// RFC 8734 Appendix A: one ECDHE exchange per brainpool curve, from the
// private key to the public point to the shared secret.

///|
test "RFC 8734: the brainpool exchanges reproduce the published shares" {
  let cases = [
    (
      @curve.BrainpoolP256r1,
      "81db1ee100150ff2ea338d708271be38300cb54241d79950f77b063039804f1d",
      "0444106e913f92bc02a1705d9953a8414db95e1aaa49e81d9e85f929a8e3100be58ab4846f11caccb73ce49cbdd120f5a900a69fd32c272223f789ef10eb089bdc",
      "55e40bc41e37e3e2ad25c3c6654511ffa8474a91a0032087593852d3e7d76bd3",
      "048d2d688c6cf93e1160ad04cc4429117dc2c41825e1e9fca0addd34e6f1b39f7b990c57520812be512641e47034832106bc7d3e8dd0e4c7f1136d7006547cec6a",
      "89afc39d41d3b327814b80940b042590f96556ec91e6ae7939bce31f3a18bf2b",
    ),
    (
      @curve.BrainpoolP384r1,
      "1e20f5e048a5886f1f157c74e91bde2b98c8b52d58e5003d57053fc4b0bd65d6f15eb5d1ee1610df870795143627d042",
      "0468b665dd91c195800650cdd363c625f4e742e8134667b767b1b476793588f885ab698c852d4a6e77a252d6380fcaf06855bc91a39c9ec01dee36017b7d673a931236d2f1f5c83942d049e3fa20607493e0d038ff2fd30c2ab67d15c85f7faa59",
      "032640bc6003c59260f7250c3db58ce647f98e1260acce4acda3dd869f74e01f8ba5e0324309db6a9831497abac96670",
      "044d44326f269a597a5b58bba565da5556ed7fd9a8a9eb76c25f46db69d19dc8ce6ad18e404b15738b2086df37e71d1eb462d692136de56cbe93bf5fa3188ef58bc8a3a0ec6c1e151a21038a42e9185329b5b275903d192f8d4e1f32fe9cc78c48",
      "0bd9d3a7ea0b3d519d09d8e48d0785fb744a6b355e6304bc51c229fbbce239bbadf6403715c35d4fb2a5444f575d4f42",
    ),
    (
      @curve.BrainpoolP512r1,
      "16302ff0dbbb5a8d733dab7141c1b45acbc8715939677f6a56850a38bd87bd59b09e80279609ff333eb9d4c061231fb26f92eeb04982a5f1d1764cad57665422",
      "040a420517e406aac0acdce90fcd71487718d3b953efd7fbec5f7f27e28c6149999397e91e029e06457db2d3e640668b392c2a7e737a7f0bf04436d11640fd09fd72e6882e8db28aad36237cd25d580db23783961c8dc52dfa2ec138ad472a0fcef3887cf62b623b2a87de5c588301ea3e5fc269b373b60724f5e82a6ad147fde7",
      "230e18e1bcc88a362fa54e4ea3902009292f7f8033624fd471b5d8ace49d12cfabbc19963dab8e2f1eba00bffb29e4d72d13f2224562f405cb80503666b25429",
      "049d45f66de5d67e2e6db6e93a59ce0bb48106097ff78a081de781cdb31fce8ccbaaea8dd4320c4119f1e9cd437a2eab3731fa9668ab268d871deda55a5473199f2fdc313095bcdd5fb3a91636f07a959c8e86b5636a1e930e8396049cb481961d365cc11453a06c719835475b12cb52fc3c383bce35e27ef194512b71876285fa",
      "a7927098655f1f9976fa50a9d566865dc530331846381c87256baf3226244b76d36403c024d7bbf0aa0803eaff405d3d24f11a9b5c0bef679fe1454b21c4cd1f",
    ),
  ]
  let un = fn(s : String) -> Bytes { @base16.decode_lossy(s) }
  for (curve, da, qa, db, qb, z) in cases {
    let pub_a = @ecdh.public(un(da)[:], curve~) catch {
      _ => abort("rfc 8734: a valid scalar must make a point")
    }
    let pub_b = @ecdh.public(un(db)[:], curve~) catch {
      _ => abort("rfc 8734: a valid scalar must make a point")
    }
    assert_eq(@base16.encode(pub_a), qa)
    assert_eq(@base16.encode(pub_b), qb)
    let sa = @ecdh.shared(un(da)[:], un(qb)[:], curve~) catch {
      _ => abort("rfc 8734: a valid peer point must agree")
    }
    let sb = @ecdh.shared(un(db)[:], un(qa)[:], curve~) catch {
      _ => abort("rfc 8734: a valid peer point must agree")
    }
    assert_eq(@base16.encode(sa), z)
    assert_eq(@base16.encode(sb), z)
  }
}
