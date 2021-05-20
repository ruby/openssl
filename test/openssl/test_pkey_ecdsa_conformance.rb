# frozen_string_literal: true

require_relative 'utils'

if defined?(OpenSSL) && defined?(OpenSSL::PKey::EC)

class OpenSSL::TestECConformance < OpenSSL::PKeyTestCase
  include OpenSSL::TestUtils::Fixtures

  def setup
    super

    @curves = [ { data: read_yaml('ecdsa', 'prime192v1.yml') } ]
    @curves.each do |curve|
      curve[:group] = OpenSSL::PKey::EC::Group.new curve[:data]['curve']
      curve[:private_bn] = OpenSSL::BN.new(curve[:data]['key']['private'], 16)
      curve[:public_bn] = OpenSSL::BN.new("04#{curve[:data]['key']['public']['x']}#{curve[:data]['key']['public']['y']}", 16)
      curve[:key] = OpenSSL::PKey::EC.new(curve[:group])
      curve[:key].private_key = curve[:private_bn]
      curve[:public_key] = OpenSSL::PKey::EC.new(curve[:group])
      curve[:public_key].public_key = OpenSSL::PKey::EC::Point.new(curve[:group], curve[:public_bn])
    end
  end

  def test_examples
    @curves.each do |curve|
      key = curve[:key]
      assert_not_nil(key.private_key)

      verify_key = curve[:public_key]
      assert_not_nil(verify_key.public_key)
      assert_true(verify_key.public_key.on_curve?)

      curve[:data]['examples'].each do |example|
        hash = OpenSSL::Digest.new(example['hash'])
        digest = hash.digest(example['message'])

        nonce = OpenSSL::BN.new example['nonce'], 16
        r_value = OpenSSL::BN.new example['signature']['r'], 16
        s_value = OpenSSL::BN.new example['signature']['s'], 16
        assert_false(r_value.negative?)
        assert_false(s_value.negative?)
        assert_false(nonce.negative?)

        sig_compute_nonce = key.dsa_sign_asn1(digest)
        assert_true(verify_key.dsa_verify_asn1(digest, sig_compute_nonce))

        sig_fixed_nonce = key.dsa_sign_asn1(digest, nonce)
        #        assert_true(verify_key.dsa_verify_asn1(digest, sig_fixed_nonce))

        parsed_asn = OpenSSL::ASN1.decode(sig_fixed_nonce)

        assert_false(parsed_asn.value[0].value.negative?)
        assert_false(parsed_asn.value[1].value.negative?)

        assert_equal(r_value, parsed_asn.value[0].value)
        assert_equal(s_value, parsed_asn.value[1].value)
      end
    end
  end
end

end