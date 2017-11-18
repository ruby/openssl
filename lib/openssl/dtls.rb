# frozen_string_literal: false
=begin
= Info
  'OpenSSL for Ruby 2' project
  Copyright (C) 2001 GOTOU YUUZOU <gotoyuzo@notwork.org>
  All rights reserved.

= Licence
  This program is licensed under the same licence as Ruby.
  (See the file 'LICENCE'.)
=end

require "openssl/buffering"
require "io/nonblock"

module OpenSSL
  module SSL
    class DTLSContext < SSLContext
      DEFAULT_PARAMS = { # :nodoc:
        :min_version => OpenSSL::SSL::TLS12_VERSION,
        :verify_mode => OpenSSL::SSL::VERIFY_PEER,
        :verify_hostname => true,
        :options => -> {
          opts = OpenSSL::SSL::OP_ALL
          opts &= ~OpenSSL::SSL::OP_DONT_INSERT_EMPTY_FRAGMENTS
          opts |= OpenSSL::SSL::OP_NO_COMPRESSION
          opts
        }.call
      }

      # call-seq:
      #    SSLContext.new           -> ctx
      #    SSLContext.new(:TLSv1)   -> ctx
      #    SSLContext.new("SSLv23") -> ctx
      #
      # Creates a new SSL context.
      #
      # If an argument is given, #ssl_version= is called with the value. Note
      # that this form is deprecated. New applications should use #min_version=
      # and #max_version= as necessary.
      def initialize(version = nil)
        super(version)
        # other stuff?
      end
    end

    class DTLSSocket < SSLSocket
      # parent does:
      # attr_reader :hostname

      # The underlying IO object.
      #attr_reader :io
      #alias :to_io :io

      # call-seq:
      #   ssl.session -> aSession
      #
      # Returns the SSLSession object currently used, or nil if the session is
      # not established.
      def session
        SSL::Session.new(self)
      rescue SSL::Session::SessionError
        nil
      end

      private
    end

    ##
    # DTLSServer represents a TCP/IP server socket with Datagram TLS (DTLS)
    #
    class DTLSServer < SSLServer
      # Creates a new instance of SSLServer.
      # * _srv_ is an instance of TCPServer.
      # * _ctx_ is an instance of OpenSSL::SSL::SSLContext.
      def initialize(svr, ctx)
        super(svr, ctx)
        @start_immediately = true  # not sure.
      end

      # See TCPServer#listen for details.
      def listen(backlog=5)
        # UDP sockets have no backlog configuration.
        # do nothing
        true
      end

      # See BasicSocket#shutdown for details.
      def shutdown(how=Socket::SHUT_RDWR)
        # UDP sockets do not have shutdown semantics, but TLS does
        @svr.shutdown(how)
      end

      # Works similar to TCPServer#accept.
      def accept
        # Socket#accept returns [socket, addrinfo].
        # TCPServer#accept returns a socket.
        # The following comma strips addrinfo.
        sock, = @svr.accept
        begin
          ssl = OpenSSL::SSL::DTLSSocket.new(sock, @ctx)
          ssl.sync_close = true
          ssl.accept if @start_immediately
          ssl
        rescue Exception => ex
          if ssl
            ssl.close
          else
            sock.close
          end
          raise ex
        end
      end

      # See IO#close for details.
      def close
        @svr.close
      end
    end
  end
end
