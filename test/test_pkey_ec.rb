# frozen_string_literal: false
require_relative 'utils'

if defined?(OpenSSL::TestUtils) && defined?(OpenSSL::PKey::EC)

class OpenSSL::TestEC < OpenSSL::TestCase
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

  def test_dsa_sign_verify
    data1 = "foo"
    data2 = "bar"
    key = OpenSSL::PKey::EC.new("prime256v1").generate_key!
    sig = key.dsa_sign_asn1(data1)
    assert_equal true, key.dsa_verify_asn1(data1, sig)
    assert_equal false, key.dsa_verify_asn1(data2, sig)
  end

  def test_dsa_sign_asn1_FIPS186_3
    key = OpenSSL::PKey::EC.new("prime256v1").generate_key!
    size = key.group.order.num_bits / 8 + 1
    dgst = (1..size).to_a.pack('C*')
    begin
      sig = key.dsa_sign_asn1(dgst)
      # dgst is auto-truncated according to FIPS186-3 after openssl-0.9.8m
      assert(key.dsa_verify_asn1(dgst + "garbage", sig))
    rescue OpenSSL::PKey::ECError => e
      # just an exception for longer dgst before openssl-0.9.8m
      assert_equal('ECDSA_sign: data too large for key size', e.message)
      # no need to do following tests
      return
    end
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

  def test_read_private_key_der
    ec = OpenSSL::TestUtils::TEST_KEY_EC_P256V1
    der = ec.to_der
    ec2 = OpenSSL::PKey.read(der)
    assert(ec2.private_key?)
    assert_equal(der, ec2.to_der)
  end

  def test_read_private_key_pem
    ec = OpenSSL::TestUtils::TEST_KEY_EC_P256V1
    pem = ec.to_pem
    ec2 = OpenSSL::PKey.read(pem)
    assert(ec2.private_key?)
    assert_equal(pem, ec2.to_pem)
  end

  def test_read_public_key_der
    ec = OpenSSL::TestUtils::TEST_KEY_EC_P256V1
    ec2 = OpenSSL::PKey::EC.new(ec.group)
    ec2.public_key = ec.public_key
    der = ec2.to_der
    ec3 = OpenSSL::PKey.read(der)
    assert(!ec3.private_key?)
    assert_equal(der, ec3.to_der)
  end

  def test_read_public_key_pem
    ec = OpenSSL::TestUtils::TEST_KEY_EC_P256V1
    ec2 = OpenSSL::PKey::EC.new(ec.group)
    ec2.public_key = ec.public_key
    pem = ec2.to_pem
    ec3 = OpenSSL::PKey.read(pem)
    assert(!ec3.private_key?)
    assert_equal(pem, ec3.to_pem)
  end

  def test_read_private_key_pem_pw
    ec = OpenSSL::TestUtils::TEST_KEY_EC_P256V1
    pem = ec.to_pem(OpenSSL::Cipher.new('AES-128-CBC'), 'secret')
    #callback form for password
    ec2 = OpenSSL::PKey.read(pem) do
      'secret'
    end
    assert(ec2.private_key?)
    # pass password directly
    ec2 = OpenSSL::PKey.read(pem, 'secret')
    assert(ec2.private_key?)
    #omit pem equality check, will be different due to cipher iv
  end

  def test_export_password_length
    key = OpenSSL::TestUtils::TEST_KEY_EC_P256V1
    assert_raise(OpenSSL::OpenSSLError) do
      key.export(OpenSSL::Cipher.new('AES-128-CBC'), 'sec')
    end
    pem = key.export(OpenSSL::Cipher.new('AES-128-CBC'), 'secr')
    assert(pem)
  end

  def test_export_password_funny
    key = OpenSSL::TestUtils::TEST_KEY_EC_P256V1
    pem = key.export(OpenSSL::Cipher.new('AES-128-CBC'), "pass\0wd")
    assert_raise(OpenSSL::PKey::PKeyError) do
      OpenSSL::PKey.read(pem, "pass")
    end
    key2 = OpenSSL::PKey.read(pem, "pass\0wd")
    assert(key2.private_key?)
    key3 = OpenSSL::PKey::EC.new(pem, "pass\0wd")
    assert(key3.private_key?)
  end

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
    assert_equal group1.generator.to_bn, group4.generator.to_bn
    assert_equal group1.order, group4.order
    assert_equal group1.cofactor, group4.cofactor
    assert_equal group1.seed, group4.seed
    assert_equal group1.degree, group4.degree
  end

  def test_ec_point
    group = OpenSSL::PKey::EC::Group.new("prime256v1")
    key = OpenSSL::PKey::EC.new(group).generate_key!
    point = key.public_key

    point2 = OpenSSL::PKey::EC::Point.new(group, point.to_bn)
    assert_equal point, point2
    assert_equal point.to_bn, point2.to_bn
    point2.invert!
    assert_not_equal point.to_bn, point2.to_bn

    begin
      group = OpenSSL::PKey::EC::Group.new(:GFp, 17, 2, 2)
      group.point_conversion_form = :uncompressed
      generator = OpenSSL::PKey::EC::Point.new(group, 0x040501.to_bn)
      group.set_generator(generator, 19, 1)
      point = OpenSSL::PKey::EC::Point.new(group, 0x040603.to_bn)
    rescue OpenSSL::PKey::EC::Group::Error
      pend "Patched OpenSSL rejected curve" if /unsupported field/ =~ $!.message
      raise
    end

    assert_equal 0x040603.to_bn, point.to_bn
    assert_equal true, point.on_curve?
    point.invert! # 8.5
    assert_equal 0x04060E.to_bn, point.to_bn
    assert_equal true, point.on_curve?

    assert_equal false, point.infinity?
    point.set_to_infinity!
    assert_equal true, point.infinity?
    assert_equal 0.to_bn, point.to_bn
    assert_equal true, point.on_curve?
  end

  def test_ec_point_mul
    begin
      # y^2 = x^3 + 2x + 2 over F_17
      # generator is (5, 1)
      group = OpenSSL::PKey::EC::Group.new(:GFp, 17, 2, 2)
      gen = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new("040501", 16))
      group.set_generator(gen, 0, 0)

      # 3 * (6, 3) = (16, 13)
      point_a = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new("040603", 16))
      result_a1 = point_a.mul(3.to_bn)
      assert_equal("04100D", result_a1.to_bn.to_s(16))
      # 3 * (6, 3) + 3 * (5, 1) = (7, 6)
      result_a2 = point_a.mul(3.to_bn, 3.to_bn)
      assert_equal("040706", result_a2.to_bn.to_s(16))
      # 3 * point_a = 3 * (6, 3) = (16, 13)
      result_b1 = point_a.mul([3.to_bn], [])
      assert_equal("04100D", result_b1.to_bn.to_s(16))
      # 3 * point_a + 2 * point_a = 3 * (6, 3) + 2 * (6, 3) = (7, 11)
      result_b1 = point_a.mul([3.to_bn, 2.to_bn], [point_a])
      assert_equal("04070B", result_b1.to_bn.to_s(16))
      # 3 * point_a + 5 * point_a.group.generator = 3 * (6, 3) + 5 * (5, 1) = (13, 10)
      result_b1 = point_a.mul([3.to_bn], [], 5)
      assert_equal("040D0A", result_b1.to_bn.to_s(16))
    rescue OpenSSL::PKey::EC::Group::Error
      # CentOS patches OpenSSL to reject curves defined over Fp where p < 256 bits
      raise if $!.message !~ /unsupported field/
    end

    p256_key = OpenSSL::TestUtils::TEST_KEY_EC_P256V1
    p256_g = p256_key.group
    assert_equal(p256_key.public_key, p256_g.generator.mul(p256_key.private_key))

    # invalid argument
    point = p256_key.public_key
    assert_raise(TypeError) { point.mul(nil) }
    assert_raise(ArgumentError) { point.mul([1.to_bn], [point]) }
    assert_raise(TypeError) { point.mul([1.to_bn], nil) }
    assert_raise(TypeError) { point.mul([nil], []) }
  end

# test Group: asn1_flag, point_conversion

end

end
