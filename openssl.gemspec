# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'openssl'

Gem::Specification.new do |spec|
  spec.name          = "openssl"
  spec.version       = OpenSSL::VERSION
  spec.authors       = ["Martin Bosslet", "SHIBATA Hiroshi", "Zachary Scott"]
  spec.email         = ["ruby-core@ruby-lang.org"]
  spec.summary       = %q{OpenSSL provides SSL, TLS and general purpose cryptography.}
  spec.description   = %q{It wraps the OpenSSL library.}
  spec.homepage      = "http://www.ruby-lang.org/"
  spec.license       = "ruby"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.3"
  spec.add_development_dependency "rake-compiler", "~> 0.9"
  spec.add_development_dependency "test-unit", "~> 3.0"
end
