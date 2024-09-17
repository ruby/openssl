# frozen_string_literal: true

module OpenSSL
  class CMAC
    # :call-seq:
    #   == other -> true or false
    #
    # Returns +true+ if the other OpenSSL::CMAC has the same MAC as +self+; +false+ otherwise.
    #
    # This method compares two MACs of equal length in constant time.
    #
    # === Example
    #
    #   key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*")
    #   message = "message"
    #
    #   cmac1 = OpenSSL::CMAC.new(key)
    #   cmac2 = cmac1.dup
    #   cmac2 == cmac1
    #   #=> true
    #
    #   cmac1.update(message)
    #   cmac2 == cmac1
    #   #=> false
    #
    #   cmac2.update(message)
    #   cmac2 == cmac1
    #   #=> true
    def ==(other)
      return false unless CMAC === other
      return false unless self.mac.bytesize == other.mac.bytesize

      OpenSSL.fixed_length_secure_compare(self.mac, other.mac)
    end

    # :call-seq:
    #   hexmac -> string
    #
    # Returns the MAC as a hex string.
    def hexmac
      mac.unpack1('H*')
    end
    alias inspect hexmac
    alias to_s hexmac

    # :call-seq:
    #   base64mac -> string
    #
    # Returns the MAC as a base 64 string.
    def base64mac
      [mac].pack('m0')
    end

    class << self
      # :call-seq:
      #   CMAC.mac(key, message, cipher = "AES-128-CBC") -> string
      #
      # Returns the MAC.
      def mac(key, message, cipher = nil)
        cmac = new(key, cipher)
        cmac << message
        cmac.mac
      end

      # :call-seq:
      #   CMAC.hexmac(key, message, cipher = "AES-128-CBC") -> string
      #
      # Returns the MAC as a hex string.
      def hexmac(key, message, cipher = nil)
        cmac = new(key, cipher)
        cmac << message
        cmac.hexmac
      end

      # :call-seq:
      #   CMAC.base64mac(key, message, cipher = "AES-128-CBC") -> string
      #
      # Returns the MAC as a base 64 string.
      def base64mac(key, message, cipher = nil)
        cmac = new(key, cipher)
        cmac << message
        cmac.base64mac
      end
    end
  end
end
