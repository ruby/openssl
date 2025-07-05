# frozen_string_literal: true

module OpenSSL
  module KDF
    if respond_to?(:derive)
      # Argon2id, a variant of Argon2, is a password hashing function
      # described in {RFC 9106}[https://www.rfc-editor.org/rfc/rfc9106].
      #
      # Available when compiled with \OpenSSL 3.2 or later.
      #
      # === Parameters
      # pass::    Passowrd to be hashed. Message string +P+ in RFC 9106.
      # salt::    Salt. Nonce +S+ in RFC 9106.
      # lanes::   Degree of parallelism. +p+ in RFC 9106.
      # length::  Desired output length in bytes. Tag length +T+ in RFC 9106.
      # memcost:: Memory size in the number of kibibytes. +m+ in RFC 9106.
      # iter::    Number of passes. +t+ in RFC 9106.
      # secret::  Secret value. +K+ in RFC 9106.
      # ad::      Associated data. +X+ in RFC 9106.
      def self.argon2id(pass, salt:, lanes:, length:, memcost:, iter:,
                        secret: "", ad: "")
        params = {
          pass: pass, salt: salt, lanes: lanes, memcost: memcost, iter: iter,
          secret: secret, ad: ad,
        }
        derive("ARGON2ID", length, params)
      end
    end
  end
end
