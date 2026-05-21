require_relative "utils"

if defined?(OpenSSL) && defined?(OpenSSL::Timestamp)

class OpenSSL::TestTimestamp < OpenSSL::TestCase
  # 2048-bit RSA keys for intermediate_key and ee_key are required for signing
  # and encryption in FIPS.
  # SP 800-131A Rev. 2
  # * 3. Digital Signatures
  # * 6. Key Agreement and Key Transport Using RSA
  # https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
  # https://github.com/openssl/openssl/blob/71943544885ff364a10bcc5ffc62d0e651c9a021/providers/common/securitycheck.c#L72-L73
  def intermediate_key
    @intermediate_key ||= OpenSSL::PKey::RSA.new <<-_end_of_pem_
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC9FTDnvTJvvS0w
mn/EANQKQsup5LRYEqj+aMnslI6eVBe0USC3dvjY6Bj4xkMVhVEb25L4KVSjqdnM
60IvL73P9aatFbpPJM837eHXVE25qsKzc7yxdk4covODsbd/J/jztaWEFcdoIjNd
IkuyVFo7uWlRzgboI5xHCBFBO7srimTKpICZeKslfm023J24H40GaF8+d3o0pOg/
h5u3lYsDON9h01eWB1j2ELRelv6zeELk27AWD+jdyDOTX49aqh0PEbPEj/TeDExY
5EdiZEwGrE075rnaR1vGz4YsGZvDMX0pxlM7efextd1jy9VWAbRq8UPV2NzthopC
ZGh3EZnHAgMBAAECggEACMqd8gBxgmbaMuApdaG7j4M940yEzXLcqauR9pk3rQk9
lZQ6FbMHQf/p/VMr66m9tN0M5H34zKfz6QZn7DgSNsOguCaCTvYSrnKLOs8AKCmr
kNrI7hARSgfnk6V6jIPSxvNuBTSwB1mjvWj/+lmCsokzP5Wj65I693CFa4eNSH+7
1Ue8LegiWz1KEwzUwE/MoDqQ+RQxQl/cIov/8oI3lYCu0S/gO5ybylLXRNy8liVM
mZusiMe8Q8SiGD+oIUBnMgcg5MYZeYcNZuFb90xl/c4Bof0Wlyznsyyw7swlZhSm
OTIl1OleSQ1eAcvGAJc6gTpt/Q6rPvgUdzUAlYAmPQKBgQDiWD2fZVL5s7ZRKpi+
lNSzj/UaFUZlmnjcmr4p/y+25nP/m4Q11lHyDr/zSdX4CjGMLkg5uPrnHvJ00taW
Yo2Akaqx8iT9ncF5gj18jfnHwGChEbMVhXSbvegcASPA4C7cA8gBwdX+ZQeahD6k
D5dz5vC1rbVPzz3oycWn5QVO0wKBgQDV2yjhxA/wlyes5h4OATwuNwTKctCT50yr
ZrfmbUpyXAIM4uKYLfI/zS0x9nePuTTIz8jldb68ehRNzqfw+1DCbWKBSoOlBS/u
eGGw4ni37Nm6lmCRZHMus1UZFS41/kSuA+xWV8fbzcfzNzkVvo+91n5xm48MN7K3
SlFk8M74vQKBgQCoj5pkqCqg9qrhy10xINk+WAjqQcnJRL6ZW0wfLoG0Le9Y/dH5
3f/syfs9DVGhhMXdZWI4Sn/fuvZI9fMEz6QdiV2bY38UuHUrLkjoBztq/ON5UBsT
/e0XRtgict7TdqCvDMnYNShOaaK9+ZpEx6+8itHcGt8Z7nZmdE0UecP4LQKBgQCk
peQ21bWT/TxNsKnpDGhiCHgGyhjuFoF/4Uiq/u/3VgE6HKBqm81L89LdCa4JmIUc
KmW4zEt6Xt8s/HNuZH9MAd16P31VWsYJauODxQk+Sftj3Y0hw12u0eEtu5Hlfgsw
ktKts02rXCaaiaTIqfuPJAobu7GJrYRJ+8zo00H2XQKBgFMm+oGbmrx6byzfFZJX
ZGukUi5vKR95KDjhLyM9Z2XHJUGj/z8a8fEMh51btI8AGKc84DS71FBsTheyrA7g
y0jEXaW4MB2AwdOW7QKaD3DjuZdWLCPDboWkoRBQY7PmRsdxF0Ve+0+xMtfJDPP8
1d4GA0IexsTOAkPAly2/vr4g
-----END PRIVATE KEY-----
_end_of_pem_
  end

  def ee_key
    @ee_key ||= OpenSSL::PKey::RSA.new <<-_end_of_pem_
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkQi2bnexNZipP
RM0e4VLBxd9aKzN5KZKP/k4lqDmkwhJ0GDpD440RNvwqBvP31iA44O0QBeyNMexC
djtDek61dI1jmwj3CuM4xO84AO+nrvV6sylvlxX/rEjHgQjFLlFP9uySL6faHbCn
fmy1HvL6wdS9iqbbGkjAtAHDZmb1V6GKzsIUEyC2webwrgzkUC5CePim3oY83e1t
DM5I1rblJk4IUpXoWsQWS2YGS6cpsoifTwsktq6olk/YW6YV+eSHuYARCByhBBlO
E2tBAiWjaRrbmVSeAZKxQpyiW2ZgVVJBE2ar9QOjEKcYECJxBu+L87uTTfITunW8
bSPg4Um1AgMBAAECggEAAZPWukre+eaESE41DIBF4Je7S5nLA1vgQEL4Xylpb4Kj
O+6Ybw4TzPMfoth92VOuHyQeqR7vC0AY48TptsrJT+02bZsPwy4DydTIwChW8ay4
rZzKeUh7LQE4X1CG7aKo10Eo1N9hfkyQslsaRV1uhsGVZUI11GunmgPG8vVCm3j5
bD4hQoXcuUY/d8VjnIeyZ0R79Y0Z+M5Zv/HP0YVkKMpLGaIJm8p0O5whkx8ztqOD
+9XVITYuiiQb17I7ab/14ZFrVeNTz9ubo5KYWwznLeUaux5Gi4wLMSK4Pr8Bpdwz
bGz2oL226iv/Nlz0rFsc/ftro4nvMDnlptRpM7paAQKBgQDft0HwEb9g13sIy4uI
+Ie1eniodvU/vghMJRorakLzQFtT8U7Jh7bA89zNvtUDvwl/QHNpVqnZTBPEv1j1
Xz+n7HxDGp2eLkylvLIaqIs2Z5ZD8hRRR/d0ltx1SirFNILTEGnFF3IQ4pszUlUE
RcYUICnQJMaahlkFYH/PtHBcNQKBgQC79mLNrRtbWkkWbf+0rlJh7+g5O5m/vZW1
f3E6SLtELhXxQMV4K+bzkjfF5Lee2DksxtAtIoZOB+OY7LoqVdqE3zRpFyxioiJN
bIQUTHZaXnGJn32qfuFjLOab42+Dc8t3iFw/g51dCaA/UdLwFLnCpxX4i5ShmCpA
9p/KuLPngQKBgD1Bt6tdoLKKriS9X0q1CqvVih5O3F6E0U7QRfcnVIe40okMpQ8n
uxHgdFBd9YPeFmKiqjdoxH88hpkz787YMtzvMyNIsWnzsYccQQRtrBjMime2bHvJ
IefpuxneohF3jG7wqpWOEuyur+KAo8jUtiUinXBh8YO0T8HaJ4UfGjkVAoGAM87l
zOs57yQjoRsQsCycaIJH7/6NklwfN7e47ee+Njy9r5G63DS9o8VZuiIgupe+qqji
GI67liZ2hWA6sBCZ+qXLPGw2v7kQ22ZdwXqR5LbDdLuRV71BQqTNq4o04na4Tmo3
gwo0BcDxeoKDMcmEqjKDy84tWZ0niGByCt5+OAECgYAKlMHNGVSyiSezrlXEVpxv
BSM/f96hJFads4jeb4wUnKWZxJvywabJxG6ln3RgrderapY7oYTxsGTYERqUvZNm
MkqVYbLY9Shj+faE1Xw4xP78aRGhrTsqPyORtGBeIJl6zsb1s8+7u47BkSDBumph
tCLmQPQFmTQQUDP6g2FtHw==
-----END PRIVATE KEY-----
_end_of_pem_
  end

  def ca_cert
    @ca_cert ||= OpenSSL::Certs.ca_cert
  end

  def ca_store
    @ca_store ||= OpenSSL::X509::Store.new.tap { |s| s.add_cert(ca_cert) }
  end

  def ts_cert_direct
    @ts_cert_direct ||= OpenSSL::Certs.ts_cert_direct(ee_key, ca_cert)
  end

  def intermediate_cert
    @intermediate_cert ||= OpenSSL::Certs.intermediate_cert(intermediate_key, ca_cert)
  end

  def intermediate_store
    @intermediate_store ||= OpenSSL::X509::Store.new.tap { |s| s.add_cert(intermediate_cert) }
  end

  def ts_cert_ee
    @ts_cert_ee ||= OpenSSL::Certs.ts_cert_ee(ee_key, intermediate_cert, intermediate_key)
  end

  def test_request_mandatory_fields
    req = OpenSSL::Timestamp::Request.new
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      req.to_der
    end
    req.algorithm = "sha1"
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      req.to_der
    end
    req.message_imprint = OpenSSL::Digest.digest('SHA1', "data")
    assert_nothing_raised { req.to_der }
  end

  def test_request_assignment
    req = OpenSSL::Timestamp::Request.new

    req.version = 2
    assert_equal(2, req.version)
    assert_raise(TypeError) { req.version = nil }
    assert_raise(TypeError) { req.version = "foo" }

    req.algorithm = "sha1"
    assert_equal("SHA1", req.algorithm)
    assert_equal("SHA1", OpenSSL::ASN1.ObjectId("SHA1").sn)
    assert_raise(TypeError) { req.algorithm = nil }
    assert_raise(OpenSSL::ASN1::ASN1Error) { req.algorithm = "xxx" }

    req.message_imprint = "test"
    assert_equal("test", req.message_imprint)
    assert_raise(TypeError) { req.message_imprint = nil }

    req.policy_id = "1.2.3.4.5"
    assert_equal("1.2.3.4.5", req.policy_id)
    assert_raise(TypeError) { req.policy_id = 123 }
    assert_raise(TypeError) { req.policy_id = nil }

    req.nonce = 42
    assert_equal(42, req.nonce)
    assert_raise(TypeError) { req.nonce = "foo" }
    assert_raise(TypeError) { req.nonce = nil }

    req.cert_requested = false
    assert_equal(false, req.cert_requested?)
    req.cert_requested = nil
    assert_equal(false, req.cert_requested?)
    req.cert_requested = 123
    assert_equal(true, req.cert_requested?)
    req.cert_requested = "asdf"
    assert_equal(true, req.cert_requested?)
  end

  def test_request_serialization
    req = OpenSSL::Timestamp::Request.new

    req.version = 2
    req.algorithm = "SHA1"
    req.message_imprint = "test"
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42
    req.cert_requested = true

    req = OpenSSL::Timestamp::Request.new(req.to_der)

    assert_equal(2, req.version)
    assert_equal("SHA1", req.algorithm)
    assert_equal("test", req.message_imprint)
    assert_equal("1.2.3.4.5", req.policy_id)
    assert_equal(42, req.nonce)
    assert_equal(true, req.cert_requested?)

  end

  def test_request_re_assignment
    #tests whether the potential 'freeing' of previous values in C works properly
    req = OpenSSL::Timestamp::Request.new
    req.version = 2
    req.version = 3
    req.algorithm = "SHA1"
    req.algorithm = "SHA256"
    req.message_imprint = "test"
    req.message_imprint = "test2"
    req.policy_id = "1.2.3.4.5"
    req.policy_id = "1.2.3.4.6"
    req.nonce = 42
    req.nonce = 24
    req.cert_requested = false
    req.cert_requested = true
    req.to_der
  end

  def test_request_encode_decode
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42

    qer = OpenSSL::Timestamp::Request.new(req.to_der)
    assert_equal(1, qer.version)
    assert_equal("SHA1", qer.algorithm)
    assert_equal(digest, qer.message_imprint)
    assert_equal("1.2.3.4.5", qer.policy_id)
    assert_equal(42, qer.nonce)

    #put OpenSSL::ASN1.decode inbetween
    qer2 = OpenSSL::Timestamp::Request.new(OpenSSL::ASN1.decode(req.to_der))
    assert_equal(1, qer2.version)
    assert_equal("SHA1", qer2.algorithm)
    assert_equal(digest, qer2.message_imprint)
    assert_equal("1.2.3.4.5", qer2.policy_id)
    assert_equal(42, qer2.nonce)
  end

  def test_request_invalid_asn1
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      OpenSSL::Timestamp::Request.new("*" * 44)
    end
  end

  def test_response_constants
    assert_equal(0, OpenSSL::Timestamp::Response::GRANTED)
    assert_equal(1, OpenSSL::Timestamp::Response::GRANTED_WITH_MODS)
    assert_equal(2, OpenSSL::Timestamp::Response::REJECTION)
    assert_equal(3, OpenSSL::Timestamp::Response::WAITING)
    assert_equal(4, OpenSSL::Timestamp::Response::REVOCATION_WARNING)
    assert_equal(5, OpenSSL::Timestamp::Response::REVOCATION_NOTIFICATION)
  end

  def test_response_creation
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"

    fac = OpenSSL::Timestamp::Factory.new
    time = Time.now
    fac.gen_time = time
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]

    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    resp = OpenSSL::Timestamp::Response.new(resp)
    assert_equal(OpenSSL::Timestamp::Response::GRANTED, resp.status)
    assert_nil(resp.failure_info)
    assert_equal([], resp.status_text)
    assert_equal(1, resp.token_info.version)
    assert_equal("1.2.3.4.5", resp.token_info.policy_id)
    assert_equal("SHA1", resp.token_info.algorithm)
    assert_equal(digest, resp.token_info.message_imprint)
    assert_equal(1, resp.token_info.serial_number)
    assert_equal(time.to_i, resp.token_info.gen_time.to_i)
    assert_equal(false, resp.token_info.ordering)
    assert_nil(resp.token_info.nonce)
    assert_cert(ts_cert_ee, resp.tsa_certificate)
    #compare PKCS7
    token = OpenSSL::ASN1.decode(resp.to_der).value[1]
    assert_equal(token.to_der, resp.token.to_der)
  end

  def test_response_failure_info
    resp = OpenSSL::Timestamp::Response.new("0\"0 \x02\x01\x020\x17\f\x15Invalid TimeStampReq.\x03\x02\x06\x80")
    assert_equal(:BAD_ALG, resp.failure_info)
  end

  def test_response_mandatory_fields
    fac = OpenSSL::Timestamp::Factory.new
    req = OpenSSL::Timestamp::Request.new
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      fac.create_timestamp(ee_key, ts_cert_ee, req)
    end
    req.algorithm = "sha1"
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      fac.create_timestamp(ee_key, ts_cert_ee, req)
    end
    req.message_imprint = OpenSSL::Digest.digest('SHA1', "data")
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      fac.create_timestamp(ee_key, ts_cert_ee, req)
    end
    fac.gen_time = Time.now
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      fac.create_timestamp(ee_key, ts_cert_ee, req)
    end
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      fac.create_timestamp(ee_key, ts_cert_ee, req)
    end
    fac.default_policy_id = "1.2.3.4.5"
    assert_equal OpenSSL::Timestamp::Response::GRANTED, fac.create_timestamp(ee_key, ts_cert_ee, req).status
    fac.default_policy_id = nil
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      fac.create_timestamp(ee_key, ts_cert_ee, req)
    end
    req.policy_id = "1.2.3.4.5"
    assert_equal OpenSSL::Timestamp::Response::GRANTED, fac.create_timestamp(ee_key, ts_cert_ee, req).status
  end

  def test_response_allowed_digests
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    req.message_imprint = OpenSSL::Digest.digest('SHA1', "test")

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.default_policy_id = "1.2.3.4.6"

    # None allowed by default
    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal OpenSSL::Timestamp::Response::REJECTION, resp.status

    # Explicitly allow SHA1 (string)
    fac.allowed_digests = ["sha1"]
    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal OpenSSL::Timestamp::Response::GRANTED, resp.status

    # Explicitly allow SHA1 (object)
    fac.allowed_digests = [OpenSSL::Digest.new('SHA1')]
    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal OpenSSL::Timestamp::Response::GRANTED, resp.status

    # Others not allowed
    req.algorithm = "SHA256"
    req.message_imprint = OpenSSL::Digest.digest('SHA256', "test")
    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal OpenSSL::Timestamp::Response::REJECTION, resp.status

    # Non-Array
    fac.allowed_digests = 123
    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal OpenSSL::Timestamp::Response::REJECTION, resp.status

    # Non-String, non-Digest Array element
    fac.allowed_digests = ["sha1", OpenSSL::Digest.new('SHA1'), 123]
    assert_raise(TypeError) do
      fac.create_timestamp(ee_key, ts_cert_ee, req)
    end
  end

  def test_response_default_policy
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    fac.default_policy_id = "1.2.3.4.6"

    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal(OpenSSL::Timestamp::Response::GRANTED, resp.status)
    assert_equal("1.2.3.4.6", resp.token_info.policy_id)

    assert_match(/1\.2\.3\.4\.6/, resp.to_text)
  end

  def test_response_bad_purpose
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]


    assert_raise(OpenSSL::Timestamp::TimestampError) do
      fac.create_timestamp(ee_key, intermediate_cert, req)
    end
  end

  def test_response_invalid_asn1
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      OpenSSL::Timestamp::Response.new("*" * 44)
    end
  end

  def test_no_cert_requested
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.cert_requested = false

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    fac.default_policy_id = "1.2.3.4.5"

    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal(OpenSSL::Timestamp::Response::GRANTED, resp.status)
    assert_nil(resp.tsa_certificate)
  end

  def test_response_no_policy_defined
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]

    assert_raise(OpenSSL::Timestamp::TimestampError) do
      fac.create_timestamp(ee_key, ts_cert_ee, req)
    end
  end

  def test_verify_ee_no_req
    ts, _ = timestamp_ee
    assert_raise(TypeError) do
      ts.verify(nil, ca_cert)
    end
  end

  def test_verify_ee_no_store
    ts, req = timestamp_ee
    assert_raise(TypeError) do
      ts.verify(req, nil)
    end
  end

  def test_verify_ee_wrong_root_no_intermediate
    ts, req = timestamp_ee
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      ts.verify(req, intermediate_store)
    end
  end

  def test_verify_ee_wrong_root_wrong_intermediate
    ts, req = timestamp_ee
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      ts.verify(req, intermediate_store, [ca_cert])
    end
  end

  def test_verify_ee_nonce_mismatch
    ts, req = timestamp_ee
    req.nonce = 1
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      ts.verify(req, ca_store, [intermediate_cert])
    end
  end

  def test_verify_ee_intermediate_missing
    ts, req = timestamp_ee
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      ts.verify(req, ca_store)
    end
  end

  def test_verify_ee_intermediate
    ts, req = timestamp_ee
    ts.verify(req, ca_store, [intermediate_cert])
  end

  def test_verify_ee_intermediate_type_error
    ts, req = timestamp_ee
    assert_raise(TypeError) { ts.verify(req, [ca_cert], 123) }
  end

  def test_verify_ee_def_policy
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.nonce = 42

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    fac.default_policy_id = "1.2.3.4.5"

    ts = fac.create_timestamp(ee_key, ts_cert_ee, req)
    ts.verify(req, ca_store, [intermediate_cert])
  end

  def test_verify_direct
    ts, req = timestamp_direct
    ts.verify(req, ca_store)
  end

  def test_verify_direct_redundant_untrusted
    ts, req = timestamp_direct
    ts.verify(req, ca_store, [ts.tsa_certificate, ts.tsa_certificate])
  end

  def test_verify_direct_unrelated_untrusted
    ts, req = timestamp_direct
    ts.verify(req, ca_store, [intermediate_cert])
  end

  def test_verify_direct_wrong_root
    ts, req = timestamp_direct
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      ts.verify(req, intermediate_store)
    end
  end

  def test_verify_direct_no_cert_no_intermediate
    ts, req = timestamp_direct_no_cert
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      ts.verify(req, ca_store)
    end
  end

  def test_verify_ee_no_cert
    ts, req = timestamp_ee_no_cert
    assert_same(ts, ts.verify(req, ca_store, [ts_cert_ee, intermediate_cert]))
  end

  def test_verify_ee_no_cert_no_intermediate
    ts, req = timestamp_ee_no_cert
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      ts.verify(req, ca_store, [ts_cert_ee])
    end
  end

  def test_verify_ee_additional_certs_array
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42
    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    fac.additional_certs = [intermediate_cert]
    ts = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal(2, ts.token.certificates.size)
    fac.additional_certs = nil
    ts.verify(req, ca_store)
    ts = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal(1, ts.token.certificates.size)
  end

  def test_verify_ee_additional_certs_with_root
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42
    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    fac.additional_certs = [intermediate_cert, ca_cert]
    ts = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_equal(3, ts.token.certificates.size)
    ts.verify(req, ca_store)
  end

  def test_verify_ee_cert_inclusion_not_requested
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.nonce = 42
    req.cert_requested = false
    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    #needed because the Request contained no policy identifier
    fac.default_policy_id = '1.2.3.4.5'
    fac.additional_certs = [ ts_cert_ee, intermediate_cert ]
    ts = fac.create_timestamp(ee_key, ts_cert_ee, req)
    assert_nil(ts.token.certificates) #since cert_requested? == false
    ts.verify(req, ca_store, [ts_cert_ee, intermediate_cert])
  end

  def test_reusable
    #test if req and faq are reusable, i.e. the internal
    #CTX_free methods don't mess up e.g. the certificates
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    fac.additional_certs = [ intermediate_cert ]
    ts1 = fac.create_timestamp(ee_key, ts_cert_ee, req)
    ts1.verify(req, ca_store)
    ts2 = fac.create_timestamp(ee_key, ts_cert_ee, req)
    ts2.verify(req, ca_store)
    refute_nil(ts1.tsa_certificate)
    refute_nil(ts2.tsa_certificate)
  end

  def test_token_info_creation
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = OpenSSL::BN.new(123)

    fac = OpenSSL::Timestamp::Factory.new
    time = Time.now
    fac.gen_time = time
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]

    resp = fac.create_timestamp(ee_key, ts_cert_ee, req)
    info = resp.token_info
    info = OpenSSL::Timestamp::TokenInfo.new(info.to_der)

    assert_equal(1, info.version)
    assert_equal("1.2.3.4.5", info.policy_id)
    assert_equal("SHA1", info.algorithm)
    assert_equal(digest, info.message_imprint)
    assert_equal(1, info.serial_number)
    assert_equal(time.to_i, info.gen_time.to_i)
    assert_equal(false, info.ordering)
    assert_equal(123, info.nonce)
  end

  def test_token_info_invalid_asn1
    assert_raise(OpenSSL::Timestamp::TimestampError) do
      OpenSSL::Timestamp::TokenInfo.new("*" * 44)
    end
  end

  private

  def assert_cert expected, actual
    assert_equal expected.to_der, actual.to_der
  end

  def timestamp_ee
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    return fac.create_timestamp(ee_key, ts_cert_ee, req), req
  end

  def timestamp_ee_no_cert
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42
    req.cert_requested = false

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    return fac.create_timestamp(ee_key, ts_cert_ee, req), req
  end

  def timestamp_direct
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    return fac.create_timestamp(ee_key, ts_cert_direct, req), req
  end

  def timestamp_direct_no_cert
    req = OpenSSL::Timestamp::Request.new
    req.algorithm = "SHA1"
    digest = OpenSSL::Digest.digest('SHA1', "test")
    req.message_imprint = digest
    req.policy_id = "1.2.3.4.5"
    req.nonce = 42
    req.cert_requested = false

    fac = OpenSSL::Timestamp::Factory.new
    fac.gen_time = Time.now
    fac.serial_number = 1
    fac.allowed_digests = ["sha1"]
    return fac.create_timestamp(ee_key, ts_cert_direct, req), req
  end
end

end
