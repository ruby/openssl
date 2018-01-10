Gem::Specification.new do |spec|
  spec.name          = "openssl"
  spec.version       = "2.2.0-mcr1"
  spec.authors       = ["Michael Richardson", "Martin Bosslet", "SHIBATA Hiroshi", "Zachary Scott", "Kazuki Yamaguchi"]
  spec.email         = ["mcr@sandelman.ca","ruby-core@ruby-lang.org"]
  spec.summary       = %q{OpenSSL provides SSL, TLS and general purpose cryptography.}
  spec.description   = %q{It wraps the OpenSSL library. Note this version depends upon an as-yet-unreleased version of OpenSSL. Built it from https://github.com/mcr/openssl/tree/dtls-listen-refactor.}
  spec.homepage      = "https://github.com/mcr/ruby-openssl"
  spec.license       = "Ruby"

  spec.files         = Dir["lib/**/*.rb", "ext/**/*.{c,h,rb}", "*.md", "BSDL", "LICENSE.txt"]
  spec.require_paths = ["lib"]
  spec.extensions    = ["ext/openssl/extconf.rb"]

  spec.extra_rdoc_files = Dir["*.md"]
  spec.rdoc_options = ["--main", "README.md"]

  spec.required_ruby_version = ">= 2.3.0"

  spec.add_development_dependency "rake"
  spec.add_development_dependency "rake-compiler"
  spec.add_development_dependency "test-unit", "~> 3.0"
  spec.add_development_dependency "rdoc"

  spec.metadata["msys2_mingw_dependencies"] = "openssl"
end
