// Copyright 2026 Leo Cheng
// SPDX-License-Identifier: Apache-2.0

///|
fn hex(b : Bytes) -> String {
  @base16.encode(b[:])
}

///|
fn raw(s : String) -> Bytes {
  @base16.decode_lossy(s)
}

///|
fn curve_of(name : String) -> @ecdsa.Curve {
  match name {
    "P256" => P256
    "P384" => P384
    "P521" => P521
    _ => Secp256k1
  }
}

///|
/// Signing is deterministic, so a vector pins the signature exactly rather than
/// only checking that it verifies. Two of the P-256 rows are the ones RFC 6979
/// §A.2.5 prints; the rest were produced by an independent implementation of the
/// same derivation and checked against a third-party verifier.
test "ECDSA signs and verifies the RFC 6979 vectors" {
  let cases = [
    (
      "P256", "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
      "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "", "0338197042a13192bec427db63c8d2dece6a08dbcc3d5181a9983e62032b023098feda6c583d409233023308d3848aa21b64381d85ee6e1c090a5d11fb7be0c7",
    ),
    (
      "P256", "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
      "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "73616d706c65", "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    ),
    (
      "P256", "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
      "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "74657374", "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
    ),
    (
      "P256", "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
      "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "4d6f6f6e426974", "b6a8496590f36ccde0a468bf3a24f4d13b2f04782f46382617ae5209e7fc61210872f7bf76476272e237b55c3bec3b49d32a0486d20625a3dec12b0fa7b7d490",
    ),
    (
      "P256", "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
      "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
      "05223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4011e3b587592afcce90623405d7a97b4d1ee0b2845627f9cb9d6f3102d4a6784a1bedbf815324f6c89a6c3e0fd1a3754718eabc8e5021f3c597693b0cdea0724415e7b98b5d2ef0c294663809dbad7f4112e4b6885a2bfdcf91633506d8aa7c4e1fe1b3855728facc9e603203d5a7794b1ceeb0825425f7c99b6d3f00d2a4764819ebbd8f5122f4c6986a3c0ddfa1734516e8ba8c5e2ff1c39567390adcae704213e5b7895b2cfec092643607d9ab7d4f10e2b4865829fbcd9f613304d6a87a4c1defb1835526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4",
      "191469e1ae899a567d89621ba87c8409e9c3bc95edf7c4c077850ee1c8b12ac7ec48416801cff49364520374f58a96cbeb767bc6568db6caad46cc2871df0841",
    ),
    (
      "P384", "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
      "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
      "", "35533bf285d9f75c246b89680ba0cb6681aa491fedd71d90ca46670477cac6967399571259ccf0858d6fd051820f7109b5bc3402dd257b8fffd2599cf966d4a9bc4d947a030a52b193a9347f3ba6bae8fc2fa1e168e5e7d698d91a927df6baa2",
    ),
    (
      "P384", "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
      "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
      "73616d706c65", "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe4699ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8",
    ),
    (
      "P384", "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
      "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
      "74657374", "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023dbddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5",
    ),
    (
      "P384", "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
      "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
      "4d6f6f6e426974", "2e6849684872a0ae1b977cdc4a4c3f511ca054715c9dacb278d83b4b3d0b70f8e8774ae4a1e3598af74beb306a4ebf173047ea03393460d735f536f91124a4796b05a84626f3ef36b9e3f7c688c9120aa9dd6cbb13f14dbc3ab058b8655a7d3e",
    ),
    (
      "P384", "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
      "04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc138015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720",
      "05223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4011e3b587592afcce90623405d7a97b4d1ee0b2845627f9cb9d6f3102d4a6784a1bedbf815324f6c89a6c3e0fd1a3754718eabc8e5021f3c597693b0cdea0724415e7b98b5d2ef0c294663809dbad7f4112e4b6885a2bfdcf91633506d8aa7c4e1fe1b3855728facc9e603203d5a7794b1ceeb0825425f7c99b6d3f00d2a4764819ebbd8f5122f4c6986a3c0ddfa1734516e8ba8c5e2ff1c39567390adcae704213e5b7895b2cfec092643607d9ab7d4f10e2b4865829fbcd9f613304d6a87a4c1defb1835526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4",
      "34a51632b3fbd8f6d6e409793a46246b4ea17d09101d2366401743ae06ae08dfe69083fddec9d9f97217cc2cc40f3c2e0c3263b062d168fa4336fd20638cd823420ceaa0edcbabbfbb3e8b2c13a59f5ebb4084666f6768a588ccb90ff0c4415e",
    ),
    (
      "P521", "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
      "0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a400493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5",
      "", "015ab5e4ebcef539aadb6a5be45a24ae9bf49864f5f919fc1b37e4fc552fe63223d302510973fc9380b4639f6fa77ed276165e8a3165f038c80a28b8a2efa9271528014e99657c02f437a7fe252f4f076f6cda7245baa7e18039f3643710b9728414c8652612afdb48949d33d6647854327edcfbe12bb5f841afc9fd9a472a5e345003c8",
    ),
    (
      "P521", "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
      "0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a400493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5",
      "73616d706c65", "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e377fa00617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af282623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a67a",
    ),
    (
      "P521", "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
      "0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a400493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5",
      "74657374", "013e99020abf5cee7525d16b69b229652ab6bdf2affcaef38773b4b7d08725f10cdb93482fdcc54edcee91eca4166b2a7c6265ef0ce2bd7051b7cef945babd47ee6d01fbd0013c674aa79cb39849527916ce301c66ea7ce8b80682786ad60f98f7e78a19ca69eff5c57400e3b3a0ad66ce0978214d13baf4e9ac60752f7b155e2de4dce3",
    ),
    (
      "P521", "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
      "0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a400493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5",
      "4d6f6f6e426974", "01a92007c10433f5d1468c034215e0b9ceae779d120b6fd7172603316b552002ce0a11495a7f376c504e156ad6ba1f4d7aa53453246040f764ebe97439b1c3b8d61f01a58e2fd64aeee0407a928d7cbe4e3f722bc6ca6d2accccdff3ddc4c085c8ca291e8b1b9cd707a031b276e5f19a75f0317e0281bace6ef1bf352dac20a4475a288b",
    ),
    (
      "P521", "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
      "0401894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f5023a400493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfdfcf5",
      "05223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4011e3b587592afcce90623405d7a97b4d1ee0b2845627f9cb9d6f3102d4a6784a1bedbf815324f6c89a6c3e0fd1a3754718eabc8e5021f3c597693b0cdea0724415e7b98b5d2ef0c294663809dbad7f4112e4b6885a2bfdcf91633506d8aa7c4e1fe1b3855728facc9e603203d5a7794b1ceeb0825425f7c99b6d3f00d2a4764819ebbd8f5122f4c6986a3c0ddfa1734516e8ba8c5e2ff1c39567390adcae704213e5b7895b2cfec092643607d9ab7d4f10e2b4865829fbcd9f613304d6a87a4c1defb1835526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4",
      "0137e867d889383cb58b60c0795fe0951f85398c15705fd73e76309113add8c7ef51e3d27003dafbe00bb9e56b735ef5d6d9f2df6c144f54cfe1fc0da356e2cb42450025fdc28d149b0c6ae197169a444a980d4b36b207a1078f4852753400c8dc69e1befba289397294d4f944a304499e1892dbc6044dd0d7ba155a3fdb7f8426e560a5",
    ),
    (
      "Secp256k1", "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
      "04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
      "", "9bc82f802274bfc15306ab449ee9adeafd325f02b2d1e6d6cc614d10f1790b0494a8036576c06f8f4e345ae7478636c337c1e0651121d433aaa1ed3a979ef8cb",
    ),
    (
      "Secp256k1", "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
      "04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
      "73616d706c65", "663656c743dd96ddcffe7ef30188086a24e876e821fa1126ac3038b564baa65b324d523cb5718d05c24c06f06608f3850f0117cdc2bf61f36a91110f5bbcfe2b",
    ),
    (
      "Secp256k1", "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
      "04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
      "74657374", "5fabbfbf8efcfc01acd9436af44bd18b91e70791348469a7dd718c7f1f288039122dd586e41ddc6e089be5af11e456ba084d2f28140fd424c1c32fd3baf1304a",
    ),
    (
      "Secp256k1", "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
      "04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
      "4d6f6f6e426974", "6be79e8fe1e45e9b24e00534e83cb7a2fcbbec8e4d703552571e06c4e38b6138b4de1fffdab53566bc92f2f0b4efeaf0f68d8cda3171cf734b6434d62a807777",
    ),
    (
      "Secp256k1", "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
      "04779dd197a5df977ed2cf6cb31d82d43328b790dc6b3b7d4437a427bd5847dfcde94b724a555b6d017bb7607c3e3281daf5b1699d6ef4124975c9237b917d426f",
      "05223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4011e3b587592afcce90623405d7a97b4d1ee0b2845627f9cb9d6f3102d4a6784a1bedbf815324f6c89a6c3e0fd1a3754718eabc8e5021f3c597693b0cdea0724415e7b98b5d2ef0c294663809dbad7f4112e4b6885a2bfdcf91633506d8aa7c4e1fe1b3855728facc9e603203d5a7794b1ceeb0825425f7c99b6d3f00d2a4764819ebbd8f5122f4c6986a3c0ddfa1734516e8ba8c5e2ff1c39567390adcae704213e5b7895b2cfec092643607d9ab7d4f10e2b4865829fbcd9f613304d6a87a4c1defb1835526f8ca9c6e3001d3a577491aecbe805223f5c7996b3d0ed0a2744617e9bb8d5f20f2c496683a0bddaf714314e6b88a5c2dffc193653708daac7e4",
      "7c19c3f4e66bded7e23e57e30b3cd5e3f5ddf79a20427379c522c6d0a3fb0f885ae78d9481f63cc8222b6736e363110d4d267fef8cd8bbdf3174decefe1df418",
    ),
  ]
  for case in cases {
    let (name, scalar, point, msg, want) = case
    let curve = curve_of(name)
    let sk = @ecdsa.PrivateKey::new(raw(scalar)[:], curve~)
    assert_eq(hex(sk.public().bytes()), point)
    assert_eq(hex(sk.sign(raw(msg)[:])), want)
    let pk = @ecdsa.PublicKey::new(raw(point)[:], curve~)
    assert_true(pk.verify(raw(msg)[:], raw(want)[:]))
  }
}

///|
/// Signing the same message twice must give the same bytes: a nonce drawn from
/// an entropy source would not, and a repeated nonce across two messages leaks
/// the key.
test "signing is deterministic" {
  let sk = @ecdsa.PrivateKey::new(
    raw("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")[:],
  )
  assert_eq(sk.sign(b"sample"[:]), sk.sign(b"sample"[:]))
  assert_not_eq(sk.sign(b"sample"[:]), sk.sign(b"samplf"[:]))
}

///|
/// A compressed point must decompress to the same key as the uncompressed form,
/// and the two coordinates must come back as a JWK would want them.
test "point encodings agree" {
  let keys = [
    ("P256", "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
    (
      "P384", "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5",
    ),
    (
      "P521", "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b83538",
    ),
    (
      "Secp256k1", "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f",
    ),
  ]
  for case in keys {
    let (name, scalar) = case
    let curve = curve_of(name)
    let size = curve.size()
    let sk = @ecdsa.PrivateKey::new(raw(scalar)[:], curve~)
    let pk = sk.public()
    let (x, y) = pk.xy()
    assert_eq(x.length(), size)
    assert_eq(y.length(), size)
    assert_eq(@ecdsa.PublicKey::of_xy(x[:], y[:], curve~).bytes(), pk.bytes())
    let odd = (y[size - 1].to_int() & 1) == 1
    let tag = if odd { b'\x03' } else { b'\x02' }
    let compressed : Array[Byte] = [tag]
    for b in x {
      compressed.push(b)
    }
    let back = @ecdsa.PublicKey::new(Bytes::from_array(compressed)[:], curve~)
    assert_eq(back.bytes(), pk.bytes())
    assert_eq(back.curve(), curve)
    assert_eq(sk.curve(), curve)
    assert_eq(hex(sk.bytes()), scalar)
  }
}

///|
/// Everything a verifier must refuse: a signature of the wrong width, a scalar
/// outside `[1, n)`, a bent byte, and another key's signature.
test "a bad signature is refused" {
  let sk = @ecdsa.PrivateKey::new(
    raw("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")[:],
  )
  let pk = sk.public()
  let sig = sk.sign(b"hello"[:])
  assert_true(pk.verify(b"hello"[:], sig[:]))
  assert_false(pk.verify(b"hellp"[:], sig[:]))
  assert_false(pk.verify(b"hello"[:], sig[0:63]))
  let zero = Bytes::make(64, b'\x00')
  assert_false(pk.verify(b"hello"[:], zero[:]))
  for i in [0, 31, 32, 63] {
    let bent = sig.to_array()
    bent[i] = (bent[i].to_int() ^ 1).to_byte()
    assert_false(pk.verify(b"hello"[:], Bytes::from_array(bent)[:]))
  }
  let other = @ecdsa.PrivateKey::new(
    raw("00000000000000000000000000000000000000000000000000000000000000ff")[:],
  )
  assert_false(other.public().verify(b"hello"[:], sig[:]))
}

///|
/// A point off the curve, a scalar of zero and a key of the wrong width are all
/// refused at construction, before anything can be signed with them.
test "a malformed key is refused" {
  let zero = Bytes::make(32, b'\x00')
  try @ecdsa.PrivateKey::new(zero[:]) |> ignore catch {
    e => assert_eq(e, @spec.Tag)
  } noraise {
    _ => fail("a zero scalar was accepted")
  }
  try @ecdsa.PrivateKey::new(zero[0:8]) |> ignore catch {
    e => assert_eq(e, @spec.Size(want=32, got=8))
  } noraise {
    _ => fail("an eight-byte scalar was accepted")
  }
  let bogus : Array[Byte] = [b'\x04']
  for _ in 0..<64 {
    bogus.push(b'\x07')
  }
  try @ecdsa.PublicKey::new(Bytes::from_array(bogus)[:]) |> ignore catch {
    e => assert_eq(e, @spec.Tag)
  } noraise {
    _ => fail("a point off the curve was accepted")
  }
}

///|
/// Pairing a digest wider than the group order with a curve must truncate the
/// digest rather than reduce it, so the signature still verifies.
test "a wider digest than the curve is truncated" {
  let sk = @ecdsa.PrivateKey::with_hash(
    raw("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721")[:],
    fn() { @sha2.Hasher::new(kind=Sha512) },
  )
  let pk = @ecdsa.PublicKey::with_hash(sk.public().bytes()[:], fn() {
    @sha2.Hasher::new(kind=Sha512)
  })
  let sig = sk.sign(b"wide"[:])
  assert_true(pk.verify(b"wide"[:], sig[:]))
  // The standard pairing must not accept it: a different digest is a different
  // signature scheme, even under the same key.
  let paired = @ecdsa.PublicKey::new(sk.public().bytes()[:])
  assert_false(paired.verify(b"wide"[:], sig[:]))
}
