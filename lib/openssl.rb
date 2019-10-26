# frozen_string_literal: false
=begin
= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2002  Michal Rokos <m.rokos@sh.cvut.cz>
  All rights reserved.

= Licence
  This program is licensed under the same licence as Ruby.
  (See the file 'LICENCE'.)
=end

require 'openssl.so'

require 'openssl/bn'
require 'openssl/pkey'
require 'openssl/cipher'
require 'openssl/config'
require 'openssl/digest'
require 'openssl/x509'
require 'openssl/ssl'
require 'openssl/pkcs5'

module OpenSSL
  # call-seq:
  #   OpenSSL.secure_compare(string, string) -> boolean
  #
  # Constant time memory comparison. Inputs are hashed using SHA-256 to mask
  # the length of the secret. Returns +true+ if the strings are identical,
  # +false+ otherwise.
  def self.secure_compare(a, b)
    hashed_a = OpenSSL::Digest::SHA256.digest(a)
    hashed_b = OpenSSL::Digest::SHA256.digest(b)
    OpenSSL.fixed_length_secure_compare(hashed_a, hashed_b) && a == b
  end
end
