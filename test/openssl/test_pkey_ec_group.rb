# frozen_string_literal: true
require_relative 'utils'

if defined?(OpenSSL) && defined?(OpenSSL::PKey::EC)

class OpenSSL::TestECGroup < OpenSSL::PKeyTestCase
  SECP256K1_NAME = 'secp256k1'
  SECP256K1_FIELD = OpenSSL::BN.new "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16
  SECP256K1_A = 0.to_bn
  SECP256K1_B = 7.to_bn
  SECP256K1_G_COMPRESSED = OpenSSL::BN.new "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16
  SECP256K1_G_UNCOMPRESSED = OpenSSL::BN.new "0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" \
                                             "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16
  SECP256K1_ORDER = OpenSSL::BN.new "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
  SECP256K1_COFACTOR = 1
  SECP256K1_DEGREE = 256

  def test_ec_group
    group1 = OpenSSL::PKey::EC::Group.new("prime256v1")
    key1 = OpenSSL::PKey::EC.new(group1)
    assert_equal group1, key1.group

    group2 = OpenSSL::PKey::EC::Group.new(group1)
    assert_equal group1.to_der, group2.to_der
    assert_equal group1, group2
    group2.asn1_flag ^=OpenSSL::PKey::EC::NAMED_CURVE
    assert_not_equal group1.to_der, group2.to_der
    assert_equal group1, group2

    group3 = group1.dup
    assert_equal group1.to_der, group3.to_der

    assert group1.asn1_flag & OpenSSL::PKey::EC::NAMED_CURVE # our default
    der = group1.to_der
    group4 = OpenSSL::PKey::EC::Group.new(der)
    group1.point_conversion_form = group4.point_conversion_form = :uncompressed
    assert_equal :uncompressed, group1.point_conversion_form
    assert_equal :uncompressed, group4.point_conversion_form
    assert_equal group1, group4
    assert_equal group1.curve_name, group4.curve_name
    assert_equal group1.generator.to_octet_string(:uncompressed),
                 group4.generator.to_octet_string(:uncompressed)
    assert_equal group1.order, group4.order
    assert_equal group1.cofactor, group4.cofactor
    assert_equal group1.seed, group4.seed
    assert_equal group1.degree, group4.degree
  end

  def test_get_group_parameters
    group = OpenSSL::PKey::EC::Group.new SECP256K1_NAME

    assert_equal(SECP256K1_NAME, group.curve_name)
    assert_equal(SECP256K1_ORDER, group.order)
    assert_equal(SECP256K1_COFACTOR, group.cofactor)
    assert_equal(SECP256K1_DEGREE, group.degree)
    assert_equal(SECP256K1_FIELD, group.field)
    assert_equal(:GFp, group.field_type)
    assert_equal([:GFp, SECP256K1_FIELD, SECP256K1_A, SECP256K1_B], group.curve_params)
  end
end
end