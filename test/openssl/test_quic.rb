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
      assert ssl, "SSLSocket should be available"
    ensure
      udp.close rescue nil
    end
  end

  def test_quic_stream_constants
    pend "QUIC not supported" unless QUIC_SUPPORTED

    assert OpenSSL::SSL::STREAM_FLAG_UNI, "STREAM_FLAG_UNI should be available"
    assert OpenSSL::SSL::STREAM_FLAG_NO_BLOCK, "STREAM_FLAG_NO_BLOCK should be available"
  end

  # --- Listener / server-side tests (OpenSSL 3.5+) ---

  LISTENER_SUPPORTED = QUIC_SUPPORTED &&
    OpenSSL::SSL::SSLSocket.respond_to?(:new_listener)

  def test_new_listener_creates_socket
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED

    ctx = OpenSSL::SSL::SSLContext.quic(:server)
    udp = UDPSocket.new
    begin
      udp.bind("127.0.0.1", 0)
      listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
      assert listener, "SSLSocket listener should be available"
    ensure
      udp.close rescue nil
    end
  end

  def test_accept_connection_nonblock_no_exception
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED

    ctx = OpenSSL::SSL::SSLContext.quic(:server)
    udp = UDPSocket.new
    begin
      udp.bind("127.0.0.1", 0)
      listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
      listener.listen
      result = listener.accept_connection_nonblock(exception: false)
      assert_equal :wait_readable, result
    ensure
      udp.close rescue nil
    end
  end

  def test_accept_connection_nonblock_raises
    pend "QUIC listener not supported" unless LISTENER_SUPPORTED

    ctx = OpenSSL::SSL::SSLContext.quic(:server)
    udp = UDPSocket.new
    begin
      udp.bind("127.0.0.1", 0)
      listener = OpenSSL::SSL::SSLSocket.new_listener(udp, context: ctx)
      listener.listen
      assert_raise(OpenSSL::SSL::SSLErrorWaitReadable) do
        listener.accept_connection_nonblock
      end
    ensure
      udp.close rescue nil
    end
  end
end

end
