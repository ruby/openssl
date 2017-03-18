# frozen_string_literal: false
require_relative 'utils'

class OpenSSL::TestPKey < OpenSSL::PKeyTestCase
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
      pend "X25519 is not implemented"
    end
    assert_equal alice_pem, alice.private_to_pem
    assert_equal bob_pem, bob.public_to_pem
    assert_equal [shared_secret].pack("H*"), alice.derive(bob)
  end
end
