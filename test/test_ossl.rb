# frozen_string_literal: true
require_relative "utils"

require 'benchmark'

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

  def test_memcmp_timing
    # Ensure using memcmp? takes almost exactly the same amount of time to compare two different strings.
    # Regular string comparison will short-circuit on the first non-matching character, failing this test.
    # NOTE: this test may be susceptible to noise if the system running the tests is otherwise under load.
    a = "x" * 512_000
    b = "#{a}y"
    c = "y#{a}"
    a = "#{a}x"

    n = 10_000
    a_b_time = Benchmark.measure { n.times { OpenSSL.memcmp?(a, b) } }.real
    a_c_time = Benchmark.measure { n.times { OpenSSL.memcmp?(a, c) } }.real
    assert_in_delta(a_b_time, a_c_time, 1, "memcmp? timing test failed")
  end
end

end
