# frozen_string_literal: true
require_relative "utils"

if defined?(OpenSSL::MAC::CMAC)

class OpenSSL::TestCMAC < OpenSSL::TestCase
  def test_cmac
    cmac = OpenSSL::MAC::CMAC.new("AES-128-CBC", ["2b7e151628aed2a6abf7158809cf4f3c"].pack("H*"))
    cmac.update(["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
    assert_equal ["070a16b46b4d4144f79bdd9dd04a287c"].pack("H*"), cmac.mac
    assert_equal "070a16b46b4d4144f79bdd9dd04a287c", cmac.hexmac
    assert_equal "BwoWtGtNQUT3m92d0EoofA==", cmac.base64mac
  end

  def test_dup
    cmac1 = OpenSSL::MAC::CMAC.new("AES-192-CBC", ["8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"].pack("H*"))
    cmac2 = cmac1.dup
    assert_equal cmac2.mac, cmac1.mac

    cmac1.update("message")
    assert_not_equal cmac2.mac, cmac1.mac

    cmac2.update("message")
    assert_equal cmac2.mac, cmac1.mac
  end

  def test_class_methods
    assert_equal ["28a7023f452e8f82bd4bf28d8c37c35c"].pack("H*"), OpenSSL::MAC::CMAC.mac("AES-256-CBC", ["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
    assert_equal "28a7023f452e8f82bd4bf28d8c37c35c", OpenSSL::MAC::CMAC.hexmac("AES-256-CBC", ["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
    assert_equal "KKcCP0Uuj4K9S/KNjDfDXA==", OpenSSL::MAC::CMAC.base64mac("AES-256-CBC", ["603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"].pack("H*"), ["6bc1bee22e409f96e93d7e117393172a"].pack("H*"))
  end
end

end
