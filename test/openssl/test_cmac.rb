# frozen_string_literal: true
require_relative "utils"

if defined?(OpenSSL)

class OpenSSL::TestCMAC < OpenSSL::TestCase
  def test_cmac
    cmac = OpenSSL::CMAC.new(["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*"))
    cmac.update(["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
    assert_equal ["070a16b46b4d4144f79bdd9dd04a287c"].pack("H*"), cmac.mac
    assert_equal "070a16b46b4d4144f79bdd9dd04a287c", cmac.hexmac
    assert_equal "BwoWtGtNQUT3m92d0EoofA==", cmac.base64mac

    cmac = OpenSSL::CMAC.new(["8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"].pack("H*"), "AES-192-CBC")
    cmac.update(["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
    assert_equal ["9e99a7bf31e710900662f65e617c5184"].pack("H*"), cmac.mac
    assert_equal "9e99a7bf31e710900662f65e617c5184", cmac.hexmac
    assert_equal "npmnvzHnEJAGYvZeYXxRhA==", cmac.base64mac

    cmac = OpenSSL::CMAC.new(["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"].pack("H*"), OpenSSL::Cipher.new("AES-256-CBC"))
    cmac.update(["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
    assert_equal ["28a7023f452e8f82bd4bf28d8c37c35c"].pack("H*"), cmac.mac
    assert_equal "28a7023f452e8f82bd4bf28d8c37c35c", cmac.hexmac
    assert_equal "KKcCP0Uuj4K9S/KNjDfDXA==", cmac.base64mac
  end

  def test_dup
    cmac1 = OpenSSL::CMAC.new(["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*"))
    cmac2 = cmac1.dup
    assert_equal cmac2, cmac1

    cmac1.update("message")
    assert_not_equal cmac2, cmac1

    cmac2.update("message")
    assert_equal cmac2, cmac1
  end

  def test_class_methods
    assert_equal ["070a16b46b4d4144f79bdd9dd04a287c"].pack("H*"), OpenSSL::CMAC.mac(["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
    assert_equal "070a16b46b4d4144f79bdd9dd04a287c", OpenSSL::CMAC.hexmac(["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
    assert_equal "BwoWtGtNQUT3m92d0EoofA==", OpenSSL::CMAC.base64mac(["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))

    assert_equal ["9e99a7bf31e710900662f65e617c5184"].pack("H*"), OpenSSL::CMAC.mac(["8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"), "AES-192-CBC")
    assert_equal "9e99a7bf31e710900662f65e617c5184", OpenSSL::CMAC.hexmac(["8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"), "AES-192-CBC")
    assert_equal "npmnvzHnEJAGYvZeYXxRhA==", OpenSSL::CMAC.base64mac(["8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"), "AES-192-CBC")

    assert_equal ["28a7023f452e8f82bd4bf28d8c37c35c"].pack("H*"), OpenSSL::CMAC.mac(["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"), OpenSSL::Cipher.new("AES-256-CBC"))
    assert_equal "28a7023f452e8f82bd4bf28d8c37c35c", OpenSSL::CMAC.hexmac(["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"), OpenSSL::Cipher.new("AES-256-CBC"))
    assert_equal "KKcCP0Uuj4K9S/KNjDfDXA==", OpenSSL::CMAC.base64mac(["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"), OpenSSL::Cipher.new("AES-256-CBC"))
  end
end

end
