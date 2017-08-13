# frozen_string_literal: false
begin
  require "openssl"

  # Disable FIPS mode for tests for installations
  # where FIPS mode would be enabled by default.
  # Has no effect on all other installations.
  OpenSSL.fips_mode=false
rescue LoadError
end

# Compile OpenSSL with crypto-mdebug and run this test suite with OSSL_MDEBUG=1
# environment variable to enable memory leak check.
if ENV["OSSL_MDEBUG"] == "1"
  if OpenSSL.respond_to?(:print_mem_leaks)
    OpenSSL.mem_check_start

    END {
      GC.start
      case OpenSSL.print_mem_leaks
      when nil
        warn "mdebug: check what is printed"
      when true
        raise "mdebug: memory leaks detected"
      end
    }
  else
    warn "OSSL_MDEBUG=1 is specified but OpenSSL is not built with crypto-mdebug"
  end
end

require "test/unit"
require "tempfile"
require "socket"
require "envutil"

if defined?(OpenSSL) && OpenSSL::OPENSSL_VERSION_NUMBER >= 0x10000000

module OpenSSL::TestUtils
  module Fixtures
    module_function

    def pkey(name)
      OpenSSL::PKey.read(read_file("pkey", name))
    end

    def pkey_dh(name)
      # DH parameters can be read by OpenSSL::PKey.read atm
      OpenSSL::PKey::DH.new(read_file("pkey", name))
    end

    def read_file(category, name)
      @file_cache ||= {}
      @file_cache[[category, name]] ||=
        File.read(File.join(__dir__, "fixtures", category, name + ".pem"))
    end
  end

  DSA_SIGNATURE_DIGEST = OpenSSL::OPENSSL_VERSION_NUMBER > 0x10000000 ?
                         OpenSSL::Digest::SHA1 :
                         OpenSSL::Digest::DSS1

  module_function

  def issue_cert(dn, key, serial, extensions, issuer, issuer_key,
                 not_before: nil, not_after: nil, digest: nil)
    cert = OpenSSL::X509::Certificate.new
    issuer = cert unless issuer
    issuer_key = key unless issuer_key
    cert.version = 2
    cert.serial = serial
    cert.subject = dn
    cert.issuer = issuer.subject
    cert.public_key = key.public_key
    now = Time.now
    cert.not_before = not_before || now - 3600
    cert.not_after = not_after || now + 3600
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.subject_certificate = cert
    ef.issuer_certificate = issuer
    extensions.each{|oid, value, critical|
      cert.add_extension(ef.create_extension(oid, value, critical))
    }
    digest ||= OpenSSL::PKey::DSA === issuer_key ? DSA_SIGNATURE_DIGEST.new : "sha256"
    cert.sign(issuer_key, digest)
    cert
  end

  def issue_crl(revoke_info, serial, lastup, nextup, extensions,
                issuer, issuer_key, digest)
    crl = OpenSSL::X509::CRL.new
    crl.issuer = issuer.subject
    crl.version = 1
    crl.last_update = lastup
    crl.next_update = nextup
    revoke_info.each{|rserial, time, reason_code|
      revoked = OpenSSL::X509::Revoked.new
      revoked.serial = rserial
      revoked.time = time
      enum = OpenSSL::ASN1::Enumerated(reason_code)
      ext = OpenSSL::X509::Extension.new("CRLReason", enum)
      revoked.add_extension(ext)
      crl.add_revoked(revoked)
    }
    ef = OpenSSL::X509::ExtensionFactory.new
    ef.issuer_certificate = issuer
    ef.crl = crl
    crlnum = OpenSSL::ASN1::Integer(serial)
    crl.add_extension(OpenSSL::X509::Extension.new("crlNumber", crlnum))
    extensions.each{|oid, value, critical|
      crl.add_extension(ef.create_extension(oid, value, critical))
    }
    crl.sign(issuer_key, digest)
    crl
  end

  def get_subject_key_id(cert)
    asn1_cert = OpenSSL::ASN1.decode(cert)
    tbscert   = asn1_cert.value[0]
    pkinfo    = tbscert.value[6]
    publickey = pkinfo.value[1]
    pkvalue   = publickey.value
    OpenSSL::Digest::SHA1.hexdigest(pkvalue).scan(/../).join(":").upcase
  end
end

class OpenSSL::TestCase < Test::Unit::TestCase
  include OpenSSL::TestUtils
  extend OpenSSL::TestUtils

  def setup
    if ENV["OSSL_GC_STRESS"] == "1"
      GC.stress = true
    end
  end

  def teardown
    if ENV["OSSL_GC_STRESS"] == "1"
      GC.stress = false
    end
    # OpenSSL error stack must be empty
    assert_equal([], OpenSSL.errors)
  end
end

class OpenSSL::SSLTestCase < OpenSSL::TestCase
  RUBY = EnvUtil.rubybin
  ITERATIONS = ($0 == __FILE__) ? 100 : 10

  def setup
    super
    @ca_key  = Fixtures.pkey("rsa2048")
    @svr_key = Fixtures.pkey("rsa1024")
    @cli_key = Fixtures.pkey("dsa1024")
    @ca  = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")
    @svr = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=localhost")
    @cli = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=localhost")
    ca_exts = [
      ["basicConstraints","CA:TRUE",true],
      ["keyUsage","cRLSign,keyCertSign",true],
    ]
    ee_exts = [
      ["keyUsage","keyEncipherment,digitalSignature",true],
    ]
    @ca_cert  = issue_cert(@ca, @ca_key, 1, ca_exts, nil, nil)
    @svr_cert = issue_cert(@svr, @svr_key, 2, ee_exts, @ca_cert, @ca_key)
    @cli_cert = issue_cert(@cli, @cli_key, 3, ee_exts, @ca_cert, @ca_key)
    @server = nil
  end

  def tls12_supported?
    OpenSSL::SSL::SSLContext::METHODS.include?(:TLSv1_2)
  end

  def readwrite_loop(ctx, ssl)
    while line = ssl.gets
      ssl.write(line)
    end
  rescue OpenSSL::SSL::SSLError
  rescue IOError
  ensure
    ssl.close rescue nil
  end

  def server_loop(ctx, ssls, stop_pipe_r, ignore_listener_error, server_proc, threads)
    loop do
      ssl = nil
      begin
        readable, = IO.select([ssls, stop_pipe_r])
        if readable.include? stop_pipe_r
          return
        end
        ssl = ssls.accept
      rescue OpenSSL::SSL::SSLError, Errno::ECONNRESET
        if ignore_listener_error
          retry
        else
          raise
        end
      end

      th = Thread.start do
        server_proc.call(ctx, ssl)
      end
      threads << th
    end
  rescue Errno::EBADF, IOError, Errno::EINVAL, Errno::ECONNABORTED, Errno::ENOTSOCK, Errno::ECONNRESET
    if !ignore_listener_error
      raise
    end
  end

  def start_server(verify_mode: OpenSSL::SSL::VERIFY_NONE, start_immediately: true,
                   ctx_proc: nil, server_proc: method(:readwrite_loop),
                   ignore_listener_error: false, &block)
    IO.pipe {|stop_pipe_r, stop_pipe_w|
      store = OpenSSL::X509::Store.new
      store.add_cert(@ca_cert)
      store.purpose = OpenSSL::X509::PURPOSE_SSL_CLIENT
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert_store = store
      ctx.cert = @svr_cert
      ctx.key = @svr_key
      ctx.tmp_dh_callback = proc { Fixtures.pkey_dh("dh1024") }
      begin
        ctx.ecdh_curves = "P-256"
      rescue NotImplementedError
      end
      ctx.verify_mode = verify_mode
      ctx_proc.call(ctx) if ctx_proc

      Socket.do_not_reverse_lookup = true
      tcps = nil
      tcps = TCPServer.new("127.0.0.1", 0)
      port = tcps.connect_address.ip_port

      ssls = OpenSSL::SSL::SSLServer.new(tcps, ctx)
      ssls.start_immediately = start_immediately

      threads = []
      begin
        server = Thread.new do
          begin
            server_loop(ctx, ssls, stop_pipe_r, ignore_listener_error, server_proc, threads)
          ensure
            tcps.close
          end
        end
        threads.unshift server

        $stderr.printf("SSL server started: pid=%d port=%d\n", $$, port) if $DEBUG

        client = Thread.new do
          begin
            block.call(port)
          ensure
            stop_pipe_w.close
          end
        end
        threads.unshift client
      ensure
        assert_join_threads(threads)
      end
    }
  end
end

class OpenSSL::PKeyTestCase < OpenSSL::TestCase
  def check_component(base, test, keys)
    keys.each { |comp|
      assert_equal base.send(comp), test.send(comp)
    }
  end

  def dup_public(key)
    case key
    when OpenSSL::PKey::RSA
      rsa = OpenSSL::PKey::RSA.new
      rsa.set_key(key.n, key.e, nil)
      rsa
    when OpenSSL::PKey::DSA
      dsa = OpenSSL::PKey::DSA.new
      dsa.set_pqg(key.p, key.q, key.g)
      dsa.set_key(key.pub_key, nil)
      dsa
    when OpenSSL::PKey::DH
      dh = OpenSSL::PKey::DH.new
      dh.set_pqg(key.p, nil, key.g)
      dh
    else
      if defined?(OpenSSL::PKey::EC) && OpenSSL::PKey::EC === key
        ec = OpenSSL::PKey::EC.new(key.group)
        ec.public_key = key.public_key
        ec
      else
        raise "unknown key type"
      end
    end
  end
end

end
