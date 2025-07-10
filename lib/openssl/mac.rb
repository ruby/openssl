# frozen_string_literal: true

module OpenSSL
  if defined?(MAC)
    class MAC
      def hexmac
        mac.unpack1('H*')
      end
      alias to_s hexmac

      def base64mac
        [mac].pack('m0')
      end

      class CMAC < MAC
        class << self
          def mac(cipher, key, message)
            cmac = new(cipher, key)
            cmac << message
            cmac.send(__callee__)
          end
          alias hexmac mac
          alias base64mac mac
        end
      end
    end
  end
end
