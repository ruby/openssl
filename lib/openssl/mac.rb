# frozen_string_literal: true

module OpenSSL
  if defined?(MAC)
    class MAC
      def ==(other)
        return false unless self.class === other
        return false unless self.mac.bytesize == other.mac.bytesize

        OpenSSL.fixed_length_secure_compare(self.mac, other.mac)
      end

      def hexmac
        mac.unpack1('H*')
      end
      alias inspect hexmac
      alias to_s hexmac

      def base64mac
        [mac].pack('m0')
      end
    end
  end
end
