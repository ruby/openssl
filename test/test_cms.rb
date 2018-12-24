# frozen_string_literal: false
require_relative 'utils'

if defined?(OpenSSL::CMS)

class OpenSSL::TestCMS < OpenSSL::TestCase
  def setup
    super
    @rsa1024 = Fixtures.pkey("rsa1024")
    @rsa2048 = Fixtures.pkey("rsa2048")
    ca = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=CA")
    ee1 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=EE1")
    ee2 = OpenSSL::X509::Name.parse("/DC=org/DC=ruby-lang/CN=EE2")

    ca_exts = [
      ["basicConstraints","CA:TRUE",true],
      ["keyUsage","keyCertSign, cRLSign",true],
      ["subjectKeyIdentifier","hash",false],
      ["authorityKeyIdentifier","keyid:always",false],
    ]
    @ca_cert = issue_cert(ca, @rsa2048, 1, ca_exts, nil, nil)
    ee_exts = [
      ["keyUsage","Non Repudiation, Digital Signature, Key Encipherment",true],
      ["authorityKeyIdentifier","keyid:always",false],
      ["extendedKeyUsage","clientAuth, emailProtection, codeSigning",false],
    ]
    @ee1_cert = issue_cert(ee1, @rsa1024, 2, ee_exts, @ca_cert, @rsa2048)
    @ee2_cert = issue_cert(ee2, @rsa1024, 3, ee_exts, @ca_cert, @rsa2048)
  end

  def test_signed
    store = OpenSSL::X509::Store.new
    store.add_cert(@ca_cert)
    ca_certs = [@ca_cert]

    data = "aaaaa\r\nbbbbb\r\nccccc\r\n"
    tmp = OpenSSL::CMS.sign(@ee1_cert, @rsa1024, data, ca_certs)
    cms = OpenSSL::CMS::ContentInfo.new(tmp.to_der)
    certs = cms.certificates
    signers = cms.signers
    assert(cms.verify([], store))
    assert_equal(data, cms.data)
    assert_equal(2, certs.size)
    assert_equal(@ee1_cert.subject.to_s, certs[0].subject.to_s)
    assert_equal(@ca_cert.subject.to_s, certs[1].subject.to_s)
    assert_equal(1, signers.size)
    assert_equal(@ee1_cert.serial, signers[0].serial)
    assert_equal(@ee1_cert.issuer.to_s, signers[0].issuer.to_s)

    # Normally OpenSSL tries to translate the supplied content into canonical
    # MIME format (e.g. a newline character is converted into CR+LF).
    # If the content is a binary, CMS::BINARY flag should be used.

    data = "aaaaa\nbbbbb\nccccc\n"
    flag = OpenSSL::CMS::BINARY
    tmp = OpenSSL::CMS.sign(@ee1_cert, @rsa1024, data, ca_certs, flag)
    cms = OpenSSL::CMS::ContentInfo.new(tmp.to_der)
    certs = cms.certificates
    signers = cms.signers
    assert(cms.verify([], store))
    assert_equal(data, cms.data)
    assert_equal(2, certs.size)
    assert_equal(@ee1_cert.subject.to_s, certs[0].subject.to_s)
    assert_equal(@ca_cert.subject.to_s, certs[1].subject.to_s)
    assert_equal(1, signers.size)
    assert_equal(@ee1_cert.serial, signers[0].serial)
    assert_equal(@ee1_cert.issuer.to_s, signers[0].issuer.to_s)

    if false
      # multiple signers not yet supported.
      # A signed-data which have multiple signatures can be created
      # through the following steps.
      #   1. create two signed-data
      #   2. copy signerInfo and certificate from one to another

      tmp1 = OpenSSL::CMS.sign(@ee1_cert, @rsa1024, data, [], flag)
      tmp2 = OpenSSL::CMS.sign(@ee2_cert, @rsa1024, data, [], flag)
      tmp1.add_signer(tmp2.signers[0])
      tmp1.add_certificate(@ee2_cert)

      cms = OpenSSL::CMS.ContentInfo.new(tmp1.to_der)
      certs = cms.certificates
      signers = cms.signers
      assert(cms.verify([], store))
      assert_equal(data, cms.data)
      assert_equal(2, certs.size)
      assert_equal(2, signers.size)
      assert_equal(@ee1_cert.serial, signers[0].serial)
      assert_equal(@ee1_cert.issuer.to_s, signers[0].issuer.to_s)
      assert_equal(@ee2_cert.serial, signers[1].serial)
      assert_equal(@ee2_cert.issuer.to_s, signers[1].issuer.to_s)
    end
  end

end
end # if(OpenSSL)
