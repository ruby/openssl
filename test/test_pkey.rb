# frozen_string_literal: false
require_relative 'utils'

class OpenSSL::TestPKey < OpenSSL::PKeyTestCase
  def test_s_generate_parameters
    # 512 is non-default; 1024 is used if 'dsa_paramgen_bits' is not specified
    # with OpenSSL 1.1.0.
    pkey = OpenSSL::PKey.generate_parameters("DSA", "dsa_paramgen_bits" => 512)
    assert_instance_of OpenSSL::PKey::DSA, pkey
    assert_equal 512, pkey.p.num_bits
    assert_equal 160, pkey.q.num_bits
    assert_equal nil, pkey.priv_key

    assert_raise(OpenSSL::PKey::PKeyError) {
      OpenSSL::PKey.generate_parameters("DSA", "invalid" => "option")
    }
  end

  def test_s_generate_key
    assert_raise(OpenSSL::PKey::PKeyError) {
      # DSA key pair cannot be generated without parameters
      OpenSSL::PKey.generate_key("DSA")
    }
    pkey_params = OpenSSL::PKey.generate_parameters("DSA", "dsa_paramgen_bits" => 512)
    pkey = OpenSSL::PKey.generate_key(pkey_params)
    assert_instance_of OpenSSL::PKey::DSA, pkey
    assert_not_equal nil, pkey.priv_key
  end

  def test_x25519
    # RFC 7748 Section 6.1
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

    # Generating an X25519 key
    assert_raise(OpenSSL::PKey::PKeyError) {
      OpenSSL::PKey.generate_parameters("X25519")
    }
    key = OpenSSL::PKey.generate_key("X25519")
    assert_nothing_raised { key.derive(bob) }
    assert_raise(OpenSSL::PKey::PKeyError) { key.sign("sha256", "data") }
  end
end
