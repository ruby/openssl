# frozen_string_literal: true

module OpenSSL
  module KDF
    if respond_to?(:derive)
      # Argon2id, a variant of Argon2, is a password hashing function
      # described in {RFC 9106}[https://www.rfc-editor.org/rfc/rfc9106].
      #
      # This methods requires \OpenSSL 3.2 or later.
      #
      # === Parameters
      # pass::    Passowrd to be hashed. Message string +P+ in RFC 9106.
      # salt::    Salt. Nonce +S+ in RFC 9106.
      # lanes::   Degree of parallelism. +p+ in RFC 9106.
      # length::  Desired output length in bytes. Tag length +T+ in RFC 9106.
      # memcost:: Memory size in the number of kibibytes. +m+ in RFC 9106.
      # iter::    Number of passes. +t+ in RFC 9106.
      # secret::  Secret value. Optional. +K+ in RFC 9106.
      # ad::      Associated data. Optional. +X+ in RFC 9106.
      #
      # === Example
      #   password = "\x01" * 32
      #   salt = "\x02" * 16
      #   secret = "\x03" * 8
      #   ad = "\x04" * 12
      #   ret = OpenSSL::KDF.argon2id(
      #     password, salt: salt, lanes: 4, length: 32,
      #     memcost: 32, iter: 3, secret: secret, ad: ad,
      #   )
      #   p ret.unpack1("H*")
      #   #=> "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
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
