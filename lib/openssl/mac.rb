# frozen_string_literal: true

module OpenSSL
  if defined?(MAC)
    class MAC
      def hexdigest
        digest.unpack1('H*')
      end
      alias to_s hexdigest

      def base64digest
        [digest].pack('m0')
      end

      class CMAC < MAC
        class << self
          def digest(cipher, key, message)
            cmac = new(cipher, key)
            cmac << message
            cmac.send(__callee__)
          end
          alias hexdigest digest
          alias base64digest digest
        end
      end
    end
  end
end
