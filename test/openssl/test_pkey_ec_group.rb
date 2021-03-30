# frozen_string_literal: true
require_relative 'utils'

if defined?(OpenSSL) && defined?(OpenSSL::PKey::EC)

class OpenSSL::TestECGroup < OpenSSL::PKeyTestCase
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
end
end