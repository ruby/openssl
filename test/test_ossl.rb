# frozen_string_literal: true
require_relative "utils"

if defined?(OpenSSL)

class OpenSSL::OSSL < OpenSSL::SSLTestCase
  def test_memcmp?
    assert_raises(ArgumentError) { OpenSSL.memcmp?("aaa", "a") }
    assert_raises(ArgumentError) { OpenSSL.memcmp?("aaa", "aa") }

    assert OpenSSL.memcmp?("aaa", "aaa")
    assert OpenSSL.memcmp?(
      OpenSSL::Digest::SHA256.digest("aaa"), OpenSSL::Digest::SHA256.digest("aaa")
    )

    assert_raises(ArgumentError) { OpenSSL.memcmp?("aaa", "aaaa") }
    refute OpenSSL.memcmp?("aaa", "baa")
    refute OpenSSL.memcmp?("aaa", "aba")
    refute OpenSSL.memcmp?("aaa", "aab")
    assert_raises(ArgumentError) { OpenSSL.memcmp?("aaa", "aaab") }
    assert_raises(ArgumentError) { OpenSSL.memcmp?("aaa", "b") }
    assert_raises(ArgumentError) { OpenSSL.memcmp?("aaa", "bb") }
    refute OpenSSL.memcmp?("aaa", "bbb")
    assert_raises(ArgumentError) { OpenSSL.memcmp?("aaa", "bbbb") }
  end
end

end
