# frozen_string_literal: true
require_relative "utils"

class OpenSSL::TestPKey < OpenSSL::PKeyTestCase
  def test_generic_oid_inspect
    # RSA private key
    rsa = Fixtures.pkey("rsa-1")
    assert_instance_of OpenSSL::PKey::RSA, rsa
    assert_equal "rsaEncryption", rsa.oid
    assert_match %r{oid=rsaEncryption}, rsa.inspect

    # X25519 private key
    x25519_pem = <<~EOF
    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VuBCIEIHcHbQpzGKV9PBbBclGyZkXfTC+H68CZKrF3+6UduSwq
    -----END PRIVATE KEY-----
    EOF
    begin
      x25519 = OpenSSL::PKey.read(x25519_pem)
    rescue OpenSSL::PKey::PKeyError
      # OpenSSL < 1.1.0
      pend "X25519 is not implemented"
    end
    assert_instance_of OpenSSL::PKey::PKey, x25519
    assert_equal "X25519", x25519.oid
    assert_match %r{oid=X25519}, x25519.inspect
  end

  def test_s_generate_parameters
    # 512 is non-default; 1024 is used if 'dsa_paramgen_bits' is not specified
    # with OpenSSL 1.1.0.
    pkey = OpenSSL::PKey.generate_parameters("DSA", {
      "dsa_paramgen_bits" => 512,
      "dsa_paramgen_q_bits" => 256,
    })
    assert_instance_of OpenSSL::PKey::DSA, pkey
    assert_equal 512, pkey.p.num_bits
    assert_equal 256, pkey.q.num_bits
    assert_equal nil, pkey.priv_key

    # Invalid options are checked
    assert_raise(OpenSSL::PKey::PKeyError) {
      OpenSSL::PKey.generate_parameters("DSA", "invalid" => "option")
    }

    # Parameter generation callback is called
    cb_called = []
    assert_raise(RuntimeError) {
      OpenSSL::PKey.generate_parameters("DSA") { |*args|
        cb_called << args
        raise "exit!" if cb_called.size == 3
      }
    }
    assert_not_empty cb_called
  end

  def test_s_generate_key
    assert_raise(OpenSSL::PKey::PKeyError) {
      # DSA key pair cannot be generated without parameters
      OpenSSL::PKey.generate_key("DSA")
    }
    pkey_params = OpenSSL::PKey.generate_parameters("DSA", {
      "dsa_paramgen_bits" => 512,
      "dsa_paramgen_q_bits" => 256,
    })
    pkey = OpenSSL::PKey.generate_key(pkey_params)
    assert_instance_of OpenSSL::PKey::DSA, pkey
    assert_equal 512, pkey.p.num_bits
    assert_not_equal nil, pkey.priv_key
  end

  def test_hmac_sign_verify
    pkey = OpenSSL::PKey.generate_key("HMAC", { "key" => "abcd" })

    hmac = OpenSSL::HMAC.new("abcd", "SHA256").update("data").digest
    assert_equal hmac, pkey.sign("SHA256", "data")

    # EVP_PKEY_HMAC does not support verify
    assert_raise(OpenSSL::PKey::PKeyError) {
      pkey.verify("SHA256", "data", hmac)
    }
  end

  def test_ed25519
    # Test vector from RFC 8032 Section 7.1 TEST 2
    priv_pem = <<~EOF
    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VwBCIEIEzNCJso/5banbbDRuwRTg9bijGfNaumJNqM9u1PuKb7
    -----END PRIVATE KEY-----
    EOF
    pub_pem = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MCowBQYDK2VwAyEAPUAXw+hDiVqStwqnTRt+vJyYLM8uxJaMwM1V8Sr0Zgw=
    -----END PUBLIC KEY-----
    EOF
    begin
      priv = OpenSSL::PKey.read(priv_pem)
      pub = OpenSSL::PKey.read(pub_pem)
    rescue OpenSSL::PKey::PKeyError
      # OpenSSL < 1.1.1
      pend "Ed25519 is not implemented"
    end
    assert_instance_of OpenSSL::PKey::PKey, priv
    assert_instance_of OpenSSL::PKey::PKey, pub
    assert_equal priv_pem, priv.private_to_pem
    assert_equal true, priv.private?
    assert_equal true, priv.public?
    priv_deserialized = Marshal.load(Marshal.dump(priv))
    assert_equal priv.private_to_der, priv_deserialized.private_to_der
    assert_equal "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      priv.private_to_raw.unpack1("H*")
    assert_equal OpenSSL::PKey.private_new("ED25519", priv.private_to_raw).private_to_pem,
      priv.private_to_pem

    assert_equal pub_pem, priv.public_to_pem
    assert_equal pub_pem, pub.public_to_pem
    assert_equal false, pub.private?
    assert_equal true, pub.public?
    pub_deserialized = Marshal.load(Marshal.dump(pub))
    assert_equal pub.public_to_der, pub_deserialized.public_to_der
    assert_equal "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
      priv.public_to_raw.unpack1("H*")
    assert_equal OpenSSL::PKey.public_new("ED25519", priv.public_to_raw).public_to_pem,
      pub.public_to_pem


    sig = [<<~EOF.gsub(/[^0-9a-f]/, "")].pack("H*")
    92a009a9f0d4cab8720e820b5f642540
    a2b27b5416503f8fb3762223ebdb69da
    085ac1e43e15996e458f3613d0f11d8c
    387b2eaeb4302aeeb00d291612bb0c00
    EOF
    data = ["72"].pack("H*")
    assert_equal sig, priv.sign(nil, data)
    assert_equal true, priv.verify(nil, sig, data)
    assert_equal true, pub.verify(nil, sig, data)
    assert_equal false, pub.verify(nil, sig, data.succ)

    # PureEdDSA wants nil as the message digest
    assert_raise(OpenSSL::PKey::PKeyError) { priv.sign("SHA512", data) }
    assert_raise(OpenSSL::PKey::PKeyError) { pub.verify("SHA512", sig, data) }

    # Ed25519 pkey type does not support key derivation
    assert_raise(OpenSSL::PKey::PKeyError) { priv.derive(pub) }
  end

  def test_x25519
    # Test vector from RFC 7748 Section 6.1
    alice_pem = <<~EOF
    -----BEGIN PRIVATE KEY-----
    MC4CAQAwBQYDK2VuBCIEIHcHbQpzGKV9PBbBclGyZkXfTC+H68CZKrF3+6UduSwq
    -----END PRIVATE KEY-----
    EOF
    bob_pem = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MCowBQYDK2VuAyEA3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08=
    -----END PUBLIC KEY-----
    EOF
    shared_secret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    begin
      alice = OpenSSL::PKey.read(alice_pem)
      bob = OpenSSL::PKey.read(bob_pem)
    rescue OpenSSL::PKey::PKeyError
      # OpenSSL < 1.1.0
      pend "X25519 is not implemented"
    end
    assert_instance_of OpenSSL::PKey::PKey, alice
    assert_equal alice_pem, alice.private_to_pem
    assert_equal bob_pem, bob.public_to_pem
    assert_equal [shared_secret].pack("H*"), alice.derive(bob)
    alice_deserialized = Marshal.load(Marshal.dump(alice))
    assert_equal alice.private_to_der, alice_deserialized.private_to_der
    bob_deserialized = Marshal.load(Marshal.dump(bob))
    assert_equal bob.public_to_der, bob_deserialized.public_to_der
    assert_equal "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
      alice.private_to_raw.unpack1("H*")
    assert_equal OpenSSL::PKey.private_new("X25519", alice.private_to_raw).private_to_pem,
      alice.private_to_pem
    assert_equal "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
      bob.public_to_raw.unpack1("H*")
    assert_equal OpenSSL::PKey.public_new("X25519", bob.public_to_raw).public_to_pem,
      bob.public_to_pem
  end

  def raw_initialize
    pend "Ed25519 is not implemented" unless OpenSSL::OPENSSL_VERSION_NUMBER >= 0x10101000 && # >= v1.1.1

    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.private_new("foo123", "xxx") }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.private_new("ED25519", "xxx") }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.public_new("foo123", "xxx") }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.public_new("ED25519", "xxx") }
  end
end
