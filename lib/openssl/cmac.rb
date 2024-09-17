# frozen_string_literal: true

module OpenSSL
  class CMAC
    def ==(other)
      return false unless CMAC === other
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

    class << self
      def mac(key, message, cipher = nil)
        cmac = new(key, cipher)
        cmac << message
        cmac.mac
      end

      def hexmac(key, message, cipher = nil)
        cmac = new(key, cipher)
        cmac << message
        cmac.hexmac
      end

      def base64mac(key, message, cipher = nil)
        cmac = new(key, cipher)
        cmac << message
        cmac.base64mac
      end
    end
  end
end
