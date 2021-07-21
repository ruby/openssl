# frozen_string_literal: true
require_relative 'utils'

if defined?(OpenSSL) && defined?(OpenSSL::PKey::EC)

class OpenSSL::TestEC < OpenSSL::PKeyTestCase
  def test_ec_key
    builtin_curves = OpenSSL::PKey::EC.builtin_curves
    assert_not_empty builtin_curves

    builtin_curves.each do |curve_name, comment|
      # Oakley curves and X25519 are not suitable for signing and causes
      # FIPS-selftest failure on some environment, so skip for now.
      next if ["Oakley", "X25519"].any? { |n| curve_name.start_with?(n) }

      key = OpenSSL::PKey::EC.new(curve_name)
      key.generate_key!

      assert_predicate key, :private?
      assert_predicate key, :public?
      assert_nothing_raised { key.check_key }
    end

    key1 = OpenSSL::PKey::EC.new("prime256v1").generate_key!

    key2 = OpenSSL::PKey::EC.new
    key2.group = key1.group
    key2.private_key = key1.private_key
    key2.public_key = key1.public_key
    assert_equal key1.to_der, key2.to_der

    key3 = OpenSSL::PKey::EC.new(key1)
    assert_equal key1.to_der, key3.to_der

    key4 = OpenSSL::PKey::EC.new(key1.to_der)
    assert_equal key1.to_der, key4.to_der

    key5 = key1.dup
    assert_equal key1.to_der, key5.to_der
    key_tmp = OpenSSL::PKey::EC.new("prime256v1").generate_key!
    key5.private_key = key_tmp.private_key
    key5.public_key = key_tmp.public_key
    assert_not_equal key1.to_der, key5.to_der
  end

  def test_generate
    assert_raise(OpenSSL::PKey::ECError) { OpenSSL::PKey::EC.generate("non-existent") }
    g = OpenSSL::PKey::EC::Group.new("prime256v1")
    ec = OpenSSL::PKey::EC.generate(g)
    assert_equal(true, ec.private?)
    ec = OpenSSL::PKey::EC.generate("prime256v1")
    assert_equal(true, ec.private?)
  end

  def test_marshal
    key = Fixtures.pkey("p256")
    deserialized = Marshal.load(Marshal.dump(key))

    assert_equal key.to_der, deserialized.to_der
  end

  def test_check_key
    key = OpenSSL::PKey::EC.new("prime256v1").generate_key!
    assert_equal(true, key.check_key)
    assert_equal(true, key.private?)
    assert_equal(true, key.public?)
    key2 = OpenSSL::PKey::EC.new(key.group)
    assert_equal(false, key2.private?)
    assert_equal(false, key2.public?)
    key2.public_key = key.public_key
    assert_equal(false, key2.private?)
    assert_equal(true, key2.public?)
    key2.private_key = key.private_key
    assert_equal(true, key2.private?)
    assert_equal(true, key2.public?)
    assert_equal(true, key2.check_key)
    key2.private_key += 1
    assert_raise(OpenSSL::PKey::ECError) { key2.check_key }
  end

  def test_sign_verify
    p256 = Fixtures.pkey("p256")
    data = "Sign me!"
    signature = p256.sign("SHA1", data)
    assert_equal true, p256.verify("SHA1", signature, data)

    signature0 = (<<~'end;').unpack("m")[0]
      MEQCIEOTY/hD7eI8a0qlzxkIt8LLZ8uwiaSfVbjX2dPAvN11AiAQdCYx56Fq
      QdBp1B4sxJoA8jvODMMklMyBKVmudboA6A==
    end;
    assert_equal true, p256.verify("SHA256", signature0, data)
    signature1 = signature0.succ
    assert_equal false, p256.verify("SHA256", signature1, data)
  end

  def test_derive_key
    # NIST CAVP, KAS_ECC_CDH_PrimitiveTest.txt, P-256 COUNT = 0
    qCAVSx = "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287"
    qCAVSy = "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac"
    dIUT = "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534"
    zIUT = "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"
    a = OpenSSL::PKey::EC.new("prime256v1")
    a.private_key = OpenSSL::BN.new(dIUT, 16)
    b = OpenSSL::PKey::EC.new("prime256v1")
    uncompressed = OpenSSL::BN.new("04" + qCAVSx + qCAVSy, 16)
    b.public_key = OpenSSL::PKey::EC::Point.new(b.group, uncompressed)
    assert_equal [zIUT].pack("H*"), a.derive(b)

    assert_equal a.derive(b), a.dh_compute_key(b.public_key)
  end

  def test_sign_verify_raw
    key = Fixtures.pkey("p256")
    data1 = "foo"
    data2 = "bar"

    malformed_sig = "*" * 30

    # Sign by #dsa_sign_asn1
    sig = key.dsa_sign_asn1(data1)
    assert_equal true, key.dsa_verify_asn1(data1, sig)
    assert_equal false, key.dsa_verify_asn1(data2, sig)
    assert_raise(OpenSSL::PKey::ECError) { key.dsa_verify_asn1(data1, malformed_sig) }
    assert_equal true, key.verify_raw(nil, sig, data1)
    assert_equal false, key.verify_raw(nil, sig, data2)
    assert_raise(OpenSSL::PKey::PKeyError) { key.verify_raw(nil, malformed_sig, data1) }

    # Sign by #sign_raw
    sig = key.sign_raw(nil, data1)
    assert_equal true, key.dsa_verify_asn1(data1, sig)
    assert_equal false, key.dsa_verify_asn1(data2, sig)
    assert_raise(OpenSSL::PKey::ECError) { key.dsa_verify_asn1(data1, malformed_sig) }
    assert_equal true, key.verify_raw(nil, sig, data1)
    assert_equal false, key.verify_raw(nil, sig, data2)
    assert_raise(OpenSSL::PKey::PKeyError) { key.verify_raw(nil, malformed_sig, data1) }
  end

  def test_dsa_sign_asn1_FIPS186_3
    key = OpenSSL::PKey::EC.new("prime256v1").generate_key!
    size = key.group.order.num_bits / 8 + 1
    dgst = (1..size).to_a.pack('C*')
    sig = key.dsa_sign_asn1(dgst)
    # dgst is auto-truncated according to FIPS186-3 after openssl-0.9.8m
    assert(key.dsa_verify_asn1(dgst + "garbage", sig))
  end

  def test_dh_compute_key
    key_a = OpenSSL::PKey::EC.new("prime256v1").generate_key!
    key_b = OpenSSL::PKey::EC.new(key_a.group).generate_key!

    pub_a = key_a.public_key
    pub_b = key_b.public_key
    a = key_a.dh_compute_key(pub_b)
    b = key_b.dh_compute_key(pub_a)
    assert_equal a, b
  end

  def test_ECPrivateKey
    p256 = Fixtures.pkey("p256")
    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(1),
      OpenSSL::ASN1::OctetString(p256.private_key.to_s(2)),
      OpenSSL::ASN1::ObjectId("prime256v1", 0, :EXPLICIT),
      OpenSSL::ASN1::BitString(p256.public_key.to_octet_string(:uncompressed),
                               1, :EXPLICIT)
    ])
    key = OpenSSL::PKey::EC.new(asn1.to_der)
    assert_predicate key, :private?
    assert_same_ec p256, key

    pem = <<~EOF
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIID49FDqcf1O1eO8saTgG70UbXQw9Fqwseliit2aWhH1oAoGCCqGSM49
    AwEHoUQDQgAEFglk2c+oVUIKQ64eZG9bhLNPWB7lSZ/ArK41eGy5wAzU/0G51Xtt
    CeBUl+MahZtn9fO1JKdF4qJmS39dXnpENg==
    -----END EC PRIVATE KEY-----
    EOF
    key = OpenSSL::PKey::EC.new(pem)
    assert_same_ec p256, key

    assert_equal asn1.to_der, p256.to_der
    assert_equal pem, p256.export
  end

  def test_ECPrivateKey_encrypted
    p256 = Fixtures.pkey("p256")
    # key = abcdef
    pem = <<~EOF
    -----BEGIN EC PRIVATE KEY-----
    Proc-Type: 4,ENCRYPTED
    DEK-Info: AES-128-CBC,85743EB6FAC9EA76BF99D9328AFD1A66

    nhsP1NHxb53aeZdzUe9umKKyr+OIwQq67eP0ONM6E1vFTIcjkDcFLR6PhPFufF4m
    y7E2HF+9uT1KPQhlE+D63i1m1Mvez6PWfNM34iOQp2vEhaoHHKlR3c43lLyzaZDI
    0/dGSU5SzFG+iT9iFXCwCvv+bxyegkBOyALFje1NAsM=
    -----END EC PRIVATE KEY-----
    EOF
    key = OpenSSL::PKey::EC.new(pem, "abcdef")
    assert_same_ec p256, key
    key = OpenSSL::PKey::EC.new(pem) { "abcdef" }
    assert_same_ec p256, key

    cipher = OpenSSL::Cipher.new("aes-128-cbc")
    exported = p256.to_pem(cipher, "abcdef\0\1")
    assert_same_ec p256, OpenSSL::PKey::EC.new(exported, "abcdef\0\1")
    assert_raise(OpenSSL::PKey::ECError) {
      OpenSSL::PKey::EC.new(exported, "abcdef")
    }
  end

  def test_PUBKEY
    p256 = Fixtures.pkey("p256")
    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
        OpenSSL::ASN1::ObjectId("prime256v1")
      ]),
      OpenSSL::ASN1::BitString(
        p256.public_key.to_octet_string(:uncompressed)
      )
    ])
    key = OpenSSL::PKey::EC.new(asn1.to_der)
    assert_not_predicate key, :private?
    assert_same_ec dup_public(p256), key

    pem = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFglk2c+oVUIKQ64eZG9bhLNPWB7l
    SZ/ArK41eGy5wAzU/0G51XttCeBUl+MahZtn9fO1JKdF4qJmS39dXnpENg==
    -----END PUBLIC KEY-----
    EOF
    key = OpenSSL::PKey::EC.new(pem)
    assert_same_ec dup_public(p256), key

    assert_equal asn1.to_der, dup_public(p256).to_der
    assert_equal pem, dup_public(p256).export
  end

# test Group: asn1_flag, point_conversion
  
  def assert_same_ec(expected, key)
    check_component(expected, key, [:group, :public_key, :private_key])
  end
end

end
