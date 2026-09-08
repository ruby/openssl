# frozen_string_literal: true
require_relative "utils"

class OpenSSL::TestRequire < OpenSSL::TestCase
  IPADDR_LOADED = '$LOADED_FEATURES.any? { |f| File.basename(f) == "ipaddr.rb" }'

  def subprocess(script)
    lib = File.expand_path("../../lib", __dir__)
    IO.popen([RbConfig.ruby, "-I", lib, "-e", script], &:read)
  end

  def test_requiring_openssl_does_not_load_ipaddr
    assert_equal "false", subprocess("require 'openssl'; print #{IPADDR_LOADED}")
  end

  def test_ipaddr_is_still_reachable_after_requiring_openssl
    assert_equal "127.0.0.1", subprocess("require 'openssl'; print IPAddr.new('127.0.0.1').to_s")
  end

  def test_referencing_ipaddr_loads_it
    script = "require 'openssl'; IPAddr.new('127.0.0.1'); print #{IPADDR_LOADED}"
    assert_equal "true", subprocess(script)
  end
end
