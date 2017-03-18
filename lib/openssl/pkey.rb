# frozen_string_literal: false
module OpenSSL
  module PKey
    class DH
      # :call-seq:
      #    dh.compute_key(pub_bn) -> string
      #
      # Returns a String containing a shared secret computed from the other
      # party's public value.
      #
      # This method is provided for backwards compatibility, and calls #derive
      # internally.
      #
      # === Parameters
      # * _pub_bn_ is a OpenSSL::BN, *not* the DH instance returned by
      #   DH#public_key as that contains the DH parameters only.
      def compute_key(pub_bn)
        peer = dup
        peer.set_key(pub_bn, nil)
        derive(peer)
      end
    end

    if defined?(EC)
    class EC
      # :call-seq:
      #    ec.dh_compute_key(pubkey) -> string
      #
      # Derives a shared secret by ECDH. _pubkey_ must be an instance of
      # OpenSSL::PKey::EC::Point and must belong to the same group.
      #
      # This method is provided for backwards compatibility, and calls #derive
      # internally.
      def dh_compute_key(pubkey)
        peer = OpenSSL::PKey::EC.new(group)
        peer.public_key = pubkey
        derive(peer)
      end
    end
    end
  end
end
