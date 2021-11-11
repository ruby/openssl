# frozen_string_literal: true
require_relative 'utils'

if defined?(OpenSSL) && defined?(OpenSSL::PKey::EC)

class OpenSSL::TestECPoint < OpenSSL::PKeyTestCase
  def test_ec_point
    group = OpenSSL::PKey::EC::Group.new("prime256v1")
    key = OpenSSL::PKey::EC.new(group).generate_key!
    point = key.public_key

    point2 = OpenSSL::PKey::EC::Point.new(group, point.to_bn)
    assert_equal point, point2
    assert_equal point.to_bn, point2.to_bn
    assert_equal point.to_octet_string(:uncompressed),
                 point2.to_octet_string(:uncompressed)

    point3 = OpenSSL::PKey::EC::Point.new(group,
                                          point.to_octet_string(:uncompressed))
    assert_equal point, point3
    assert_equal point.to_bn, point3.to_bn
    assert_equal point.to_octet_string(:uncompressed),
                 point3.to_octet_string(:uncompressed)

    point2.invert!
    point3.invert!
    assert_not_equal point.to_octet_string(:uncompressed),
                     point2.to_octet_string(:uncompressed)
    assert_equal point2.to_octet_string(:uncompressed),
                 point3.to_octet_string(:uncompressed)

    begin
      group = OpenSSL::PKey::EC::Group.new(:GFp, 17, 2, 2)
      group.point_conversion_form = :uncompressed
      generator = OpenSSL::PKey::EC::Point.new(group, B(%w{ 04 05 01 }))
      group.set_generator(generator, 19, 1)
      point = OpenSSL::PKey::EC::Point.new(group, B(%w{ 04 06 03 }))
    rescue OpenSSL::PKey::EC::Group::Error
      pend "Patched OpenSSL rejected curve" if /unsupported field/ =~ $!.message
      raise
    end

    assert_equal 0x040603.to_bn, point.to_bn
    assert_equal 0x040603.to_bn, point.to_bn(:uncompressed)
    assert_equal 0x0306.to_bn, point.to_bn(:compressed)
    assert_equal 0x070603.to_bn, point.to_bn(:hybrid)

    group2 = group.dup; group2.point_conversion_form = :compressed
    point2 = OpenSSL::PKey::EC::Point.new(group2, B(%w{ 04 06 03 }))
    assert_equal 0x0306.to_bn, point2.to_bn

    assert_equal B(%w{ 04 06 03 }), point.to_octet_string(:uncompressed)
    assert_equal B(%w{ 03 06 }), point.to_octet_string(:compressed)
    assert_equal B(%w{ 07 06 03 }), point.to_octet_string(:hybrid)

    assert_equal true, point.on_curve?
    point.invert! # 8.5
    assert_equal B(%w{ 04 06 0E }), point.to_octet_string(:uncompressed)
    assert_equal true, point.on_curve?

    assert_equal false, point.infinity?
    point.set_to_infinity!
    assert_equal true, point.infinity?
    assert_equal 0.to_bn, point.to_bn
    assert_equal B(%w{ 00 }), point.to_octet_string(:uncompressed)
    assert_equal true, point.on_curve?
  end

  def test_ec_point_add
    begin
      group = OpenSSL::PKey::EC::Group.new(:GFp, 17, 2, 2)
      group.point_conversion_form = :uncompressed
      gen = OpenSSL::PKey::EC::Point.new(group, B(%w{ 04 05 01 }))
      group.set_generator(gen, 19, 1)

      point_a = OpenSSL::PKey::EC::Point.new(group, B(%w{ 04 06 03 }))
      point_b = OpenSSL::PKey::EC::Point.new(group, B(%w{ 04 10 0D }))
    rescue OpenSSL::PKey::EC::Group::Error
      pend "Patched OpenSSL rejected curve" if /unsupported field/ =~ $!.message
      raise
    end

    result = point_a.add(point_b)
    assert_equal B(%w{ 04 0D 07 }), result.to_octet_string(:uncompressed)

    assert_raise(TypeError) { point_a.add(nil) }
    assert_raise(ArgumentError) { point_a.add }
  end

  def test_ec_point_mul
    begin
      # y^2 = x^3 + 2x + 2 over F_17
      # generator is (5, 1)
      group = OpenSSL::PKey::EC::Group.new(:GFp, 17, 2, 2)
      group.point_conversion_form = :uncompressed
      gen = OpenSSL::PKey::EC::Point.new(group, B(%w{ 04 05 01 }))
      group.set_generator(gen, 19, 1)

      # 3 * (6, 3) = (16, 13)
      point_a = OpenSSL::PKey::EC::Point.new(group, B(%w{ 04 06 03 }))
      result_a1 = point_a.mul(3)
      assert_equal B(%w{ 04 10 0D }), result_a1.to_octet_string(:uncompressed)
      # 3 * (6, 3) + 3 * (5, 1) = (7, 6)
      result_a2 = point_a.mul(3, 3)
      assert_equal B(%w{ 04 07 06 }), result_a2.to_octet_string(:uncompressed)
      EnvUtil.suppress_warning do # Point#mul(ary, ary [, bn]) is deprecated
        begin
          result_b1 = point_a.mul([3], [])
        rescue NotImplementedError
          # LibreSSL and OpenSSL 3.0 do no longer support this form of calling
          next
        end

        # 3 * point_a = 3 * (6, 3) = (16, 13)
        result_b1 = point_a.mul([3], [])
        assert_equal B(%w{ 04 10 0D }), result_b1.to_octet_string(:uncompressed)
        # 3 * point_a + 2 * point_a = 3 * (6, 3) + 2 * (6, 3) = (7, 11)
        result_b1 = point_a.mul([3, 2], [point_a])
        assert_equal B(%w{ 04 07 0B }), result_b1.to_octet_string(:uncompressed)
        # 3 * point_a + 5 * point_a.group.generator = 3 * (6, 3) + 5 * (5, 1) = (13, 10)
        result_b1 = point_a.mul([3], [], 5)
        assert_equal B(%w{ 04 0D 0A }), result_b1.to_octet_string(:uncompressed)

        assert_raise(ArgumentError) { point_a.mul([1], [point_a]) }
        assert_raise(TypeError) { point_a.mul([1], nil) }
        assert_raise(TypeError) { point_a.mul([nil], []) }
      end
    rescue OpenSSL::PKey::EC::Group::Error
      # CentOS patches OpenSSL to reject curves defined over Fp where p < 256 bits
      raise if $!.message !~ /unsupported field/
    end

    p256_key = Fixtures.pkey("p256")
    p256_g = p256_key.group
    assert_equal(p256_key.public_key, p256_g.generator.mul(p256_key.private_key))

    # invalid argument
    point = p256_key.public_key
    assert_raise(TypeError) { point.mul(nil) }
  end

private

  def B(ary)
    [Array(ary).join].pack("H*")
  end

end
end
