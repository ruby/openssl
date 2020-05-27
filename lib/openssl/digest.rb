# frozen_string_literal: true
#--
# = Ruby-space predefined Digest subclasses
#
# = Info
# 'OpenSSL for Ruby 2' project
# Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
# All rights reserved.
#
# = Licence
# This program is licensed under the same licence as Ruby.
# (See the file 'LICENCE'.)
#++

module OpenSSL
  class Digest

    # Return the hash value computed with _name_ Digest. _name_ is either the
    # long name or short name of a supported digest algorithm.
    #
    # === Examples
    #
    #   OpenSSL::Digest.digest("SHA256", "abc")
    #
    # which is equivalent to:
    #
    #   OpenSSL::Digest.digest('SHA256', "abc")

    def self.digest(name, data)
      super(data, name)
    end

    %w(MD4 MD5 RIPEMD160 SHA1 SHA224 SHA256 SHA384 SHA512).each do |name|
      klass = Class.new(self) {
        define_method(:initialize, ->(data = nil) {super(name, data)})
      }

      singleton = (class << klass; self; end)

      singleton.class_eval{
        define_method(:digest) {|data| new.digest(data)}
        define_method(:hexdigest) {|data| new.hexdigest(data)}
      }

      const_set(name.tr('-', '_'), klass)
    end

    # Deprecated.
    #
    # This class is only provided for backwards compatibility.
    # Use OpenSSL::Digest instead.
    class Digest < Digest; end # :nodoc:
    deprecate_constant :Digest

  end # Digest

  # Returns a Digest subclass by _name_
  #
  #   require 'openssl'
  #
  #   OpenSSL::Digest("MD5")
  #   # => OpenSSL::Digest::MD5
  #
  #   Digest("Foo")
  #   # => NameError: wrong constant name Foo

  def Digest(name)
    OpenSSL::Digest.const_get(name)
  end

  module_function :Digest

end # OpenSSL

# The 'digest' standard library providesa ::Digest, a framework for message
# digest algorithms and bundles basic implementations of commonly used
# algorithms.
#
# Ruby/OpenSSL provides a more efficient implementation of those algorithms
# in OpenSSL::Digest, which also inherts from Digest::Class and has the
# same interface as ::Digest.
#
# This redefines the constants in ::Digest with the OpenSSL implementations.
# The original constants are renamed to add "_DEFAULT" to their original name.
module Digest
  rename_builtin = proc { |name|
    begin
      default = const_get(name)
    rescue LoadError
    else
      const_set(:"#{name}_DEFAULT", default)
      remove_const(name)
    end
  }

  # OpenSSL::Digest.new("RIPEMD160")
  RMD160 = OpenSSL::Digest::RIPEMD160 if rename_builtin.(:RMD160)

  # OpenSSL::Digest.new("MD5")
  MD5 = OpenSSL::Digest::MD5 if rename_builtin.(:MD5)

  # OpenSSL::Digest.new("SHA1")
  SHA1 = OpenSSL::Digest::SHA1 if rename_builtin.(:SHA1)

  # OpenSSL::Digest.new("SHA256")
  SHA256 = OpenSSL::Digest::SHA256 if rename_builtin.(:SHA256)

  # OpenSSL::Digest.new("SHA384")
  SHA384 = OpenSSL::Digest::SHA384 if rename_builtin.(:SHA384)

  # OpenSSL::Digest.new("SHA512")
  SHA512 = OpenSSL::Digest::SHA512 if rename_builtin.(:SHA512)
end
