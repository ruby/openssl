# frozen_string_literal: false
#--
# = Ruby-space predefined Cipher subclasses
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
  class Cipher
    %w(AES CAST5 BF DES IDEA RC2 RC4 RC5).each{|name|
      klass = Class.new(Cipher){
        define_method(:initialize){|*args|
          cipher_name = args.inject(name){|n, arg| "#{n}-#{arg}" }
          super(cipher_name.downcase)
        }
      }
      const_set(name, klass)
    }

    %w(128 192 256).each{|keylen|
      klass = Class.new(Cipher){
        define_method(:initialize){|mode = "CBC"|
          super("aes-#{keylen}-#{mode}".downcase)
        }
      }
      const_set("AES#{keylen}", klass)
    }

    # Generate, set, and return a random key.
    # You must call cipher.encrypt or cipher.decrypt before calling this method.
    def random_key
      str = OpenSSL::Random.random_bytes(self.key_len)
      self.key = str
      return str
    end

    # Generate, set, and return a random iv.
    # You must call cipher.encrypt or cipher.decrypt before calling this method.
    def random_iv
      str = OpenSSL::Random.random_bytes(self.iv_len)
      self.iv = str
      return str
    end

    # Deprecated.
    #
    # This class is only provided for backwards compatibility.
    # Use OpenSSL::Cipher.
    class Cipher < Cipher; end
    deprecate_constant :Cipher
  end # Cipher
end # OpenSSL
