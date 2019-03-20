# -*- coding: utf-8 -*-
require 'minitest/autorun'
require 'openssl/pkey/ec/ies'

Minitest.autorun

class TestIES < Minitest::Test
  def setup
    test_key = File.read(File.expand_path(File.join(__FILE__, '..', 'test_key.pem')))
    @ec = OpenSSL::PKey::EC::IES.new(test_key, "placeholder")
  end

  def test_ec_has_private_and_public_keys
    assert @ec.private_key?
    assert @ec.public_key?
  end

  def test_encrypt_then_decrypt_get_the_source_text
    source = 'いろはにほへと ちるぬるを わかよたれそ つねならむ うゐのおくやま けふこえて あさきゆめみし ゑひもせすん'
    cryptogram = @ec.public_encrypt(source)
    result = @ec.private_decrypt(cryptogram)
    assert_equal source, result.force_encoding('UTF-8')
  end
end
