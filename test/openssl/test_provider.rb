# frozen_string_literal: true
require_relative 'utils'
if defined?(OpenSSL) && defined?(OpenSSL::Provider)

class OpenSSL::TestProvider < OpenSSL::TestCase
  def test_openssl_provider_name_inspect
    with_openssl <<-'end;'
      provider = OpenSSL::Provider.load("default")
      assert_equal("default", provider.name)
      assert_not_nil(provider.inspect)
    end;
  end

  def test_openssl_provider_names
    # We expect the following providers are loaded in the cases:
    # * Non-FIPS: default
    # * FIPS: fips, base
    # Use the null provider to test the added provider.
    # See provider(7) - OPENSSL PROVIDERS to see the list of providers, and
    # OSSL_PROVIDER-null(7) to check the details of the null provider.
    with_openssl <<-'end;'
      num = OpenSSL::Provider.provider_names.size

      added_provider = OpenSSL::Provider.load("null")
      assert_equal(num + 1, OpenSSL::Provider.provider_names.size)
      assert_includes(OpenSSL::Provider.provider_names, "null")

      assert_equal(true, added_provider.unload)
      assert_equal(num, OpenSSL::Provider.provider_names.size)
      assert_not_includes(OpenSSL::Provider.provider_names, "null")
    end;
  end

  def test_unloaded_openssl_provider
    with_openssl <<-'end;'
      default_provider = OpenSSL::Provider.load("default")
      assert_equal(true, default_provider.unload)
      assert_raise(OpenSSL::Provider::ProviderError) { default_provider.name }
      assert_raise(OpenSSL::Provider::ProviderError) { default_provider.unload }
    end;
  end

  def test_openssl_legacy_provider
    # The legacy provider is not supported on FIPS.
    omit_on_fips

    with_openssl(<<-'end;')
      begin
        OpenSSL::Provider.load("legacy")
      rescue OpenSSL::Provider::ProviderError
        omit "Only for OpenSSL with legacy provider"
      end

      algo = "RC4"
      data = "a" * 1000
      key = OpenSSL::Random.random_bytes(16)

      # default provider does not support RC4
      cipher = OpenSSL::Cipher.new(algo)
      cipher.encrypt
      cipher.key = key
      encrypted = cipher.update(data) + cipher.final

      other_cipher = OpenSSL::Cipher.new(algo)
      other_cipher.decrypt
      other_cipher.key = key
      decrypted = other_cipher.update(encrypted) + other_cipher.final

      assert_equal(data, decrypted)
    end;
  end

  def test_add_conf_parameter
    with_openssl <<-'end;'
      prov = OpenSSL::Provider.load("null")
      assert_raise(TypeError) { prov.add_conf_parameter("foo", nil) }

      # This assumes that ML-DSA is provided by the "default" provider, which
      # may not always be the case.
      # TODO: OpenSSL::PKey should allow specifying the provider to use
      return if OpenSSL.fips_mode
      pkey = OpenSSL::PKey.generate_key("ML-DSA-44")
      out_a = pkey.private_to_der
      prov = OpenSSL::Provider.load("default")
      prov.add_conf_parameter("ml-dsa.output_formats", "seed-only")
      out_b = pkey.private_to_der
      omit "ML-DSA not provided by the \"default\" provider?" if out_a == out_b
      assert_not_equal(out_a, out_b)
    end;
  end if openssl?(3, 5, 0)

  private

  # this is required because OpenSSL::Provider methods change global state
  def with_openssl(code, **opts)
    assert_separately(["-ropenssl"], <<~"end;", **opts)
      #{code}
    end;
  end
end

end
