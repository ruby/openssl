# frozen_string_literal: false
require "mkmf"

dir_config("openssl")
pkg_config("openssl") or
  have_library("crypto", "CRYPTO_malloc") or
  have_library("libeay32", "CRYPTO_malloc")

create_makefile("mdebug")
