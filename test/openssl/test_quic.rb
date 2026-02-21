# frozen_string_literal: true
require_relative "utils"

if defined?(OpenSSL::SSL)

class OpenSSL::TestQUIC < Test::Unit::TestCase
  QUIC_SUPPORTED = OpenSSL::SSL::SSLContext.respond_to?(:quic)

  def test_quic_context_client
    pend "QUIC not supported" unless QUIC_SUPPORTED

    ctx = OpenSSL::SSL::SSLContext.quic(:client)
    assert_equal :client, ctx.quic
    assert_predicate ctx, :quic?
  end

  def test_quic_context_client_thread
    pend "QUIC not supported" unless QUIC_SUPPORTED
    # :client_thread may not be available on all builds
    begin
      ctx = OpenSSL::SSL::SSLContext.quic(:client_thread)
      assert_equal :client_thread, ctx.quic
      assert_predicate ctx, :quic?
    rescue OpenSSL::SSL::SSLError
      pend "QUIC client_thread method not available"
    end
  end

  def test_quic_context_unknown_mode_raises
    pend "QUIC not supported" unless QUIC_SUPPORTED

    assert_raise(ArgumentError) do
      OpenSSL::SSL::SSLContext.quic(:bogus)
    end
  end

  def test_tls_context_backward_compat
    ctx = OpenSSL::SSL::SSLContext.new
    assert_nil ctx.quic
    refute_predicate ctx, :quic?
  end

  def test_quic_context_frozen_after_setup
    pend "QUIC not supported" unless QUIC_SUPPORTED

    ctx = OpenSSL::SSL::SSLContext.quic(:client)
    assert_equal true, ctx.setup
    assert_predicate ctx, :frozen?
    assert_nil ctx.setup
  end

  def test_quic_context_verify_defaults
    pend "QUIC not supported" unless QUIC_SUPPORTED

    ctx = OpenSSL::SSL::SSLContext.quic(:client)
    assert_equal OpenSSL::SSL::VERIFY_NONE, ctx.verify_mode
  end

  def test_quic_socket_with_udp
    pend "QUIC not supported" unless QUIC_SUPPORTED

    ctx = OpenSSL::SSL::SSLContext.quic(:client)
    udp = UDPSocket.new
    begin
      udp.connect("127.0.0.1", 12345)
      ssl = OpenSSL::SSL::SSLSocket.new(udp, ctx)
      assert_instance_of OpenSSL::SSL::SSLSocket, ssl
    ensure
      udp.close rescue nil
    end
  end

  def test_quic_stream_constants
    pend "QUIC not supported" unless QUIC_SUPPORTED

    assert_kind_of Integer, OpenSSL::SSL::STREAM_FLAG_UNI
    assert_kind_of Integer, OpenSSL::SSL::STREAM_FLAG_NO_BLOCK
  end

  # --- Listener / server-side tests (OpenSSL 3.5+) ---

  LISTENER_SUPPORTED = QUIC_SUPPORTED &&
    OpenSSL::SSL::SSLSocket.respond_to?(:new_listener)

  def test_new_listener_method_defined
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED

    assert_respond_to OpenSSL::SSL::SSLSocket, :new_listener
  end

  def test_new_listener_creates_socket
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED

    ctx = OpenSSL::SSL::SSLContext.quic(:server)
    udp = UDPSocket.new
    begin
      udp.bind("127.0.0.1", 0)
      listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
      assert_instance_of OpenSSL::SSL::SSLSocket, listener
    ensure
      udp.close rescue nil
    end
  end

  def test_accept_connection_method_defined
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED
    pend "accept_connection not available" unless
      OpenSSL::SSL::SSLSocket.method_defined?(:accept_connection)

    ctx = OpenSSL::SSL::SSLContext.quic(:server)
    udp = UDPSocket.new
    begin
      udp.bind("127.0.0.1", 0)
      listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
      assert_respond_to listener, :accept_connection
    ensure
      udp.close rescue nil
    end
  end

  def test_listen_method_defined
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED
    pend "listen not available" unless
      OpenSSL::SSL::SSLSocket.method_defined?(:listen)

    ctx = OpenSSL::SSL::SSLContext.quic(:server)
    udp = UDPSocket.new
    begin
      udp.bind("127.0.0.1", 0)
      listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
      assert_respond_to listener, :listen
    ensure
      udp.close rescue nil
    end
  end

  def test_accept_connection_queue_len_method_defined
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED
    pend "accept_connection_queue_len not available" unless
      OpenSSL::SSL::SSLSocket.method_defined?(:accept_connection_queue_len)

    ctx = OpenSSL::SSL::SSLContext.quic(:server)
    udp = UDPSocket.new
    begin
      udp.bind("127.0.0.1", 0)
      listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
      assert_respond_to listener, :accept_connection_queue_len
    ensure
      udp.close rescue nil
    end
  end

  def test_accept_connection_no_block_constant
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED
    pend "ACCEPT_CONNECTION_NO_BLOCK not defined" unless
      OpenSSL::SSL.const_defined?(:ACCEPT_CONNECTION_NO_BLOCK)

    assert_kind_of Integer, OpenSSL::SSL::ACCEPT_CONNECTION_NO_BLOCK
  end
end

end
