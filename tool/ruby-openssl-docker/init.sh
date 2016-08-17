#!/bin/bash

if [[ "$RUBY_VERSION" = "" ]]
then
  RUBY_VERSION=ruby-2.3
fi

if [[ "$OPENSSL_VERSION" = "" ]]
then
  OPENSSL_VERSION=openssl-1.0.2
fi

echo "Using Ruby ${RUBY_VERSION} with OpenSSL ${OPENSSL_VERSION}."
export PATH="/opt/ruby/${RUBY_VERSION}/bin:$PATH"
export LD_LIBRARY_PATH="/opt/openssl/${OPENSSL_VERSION}/lib"
export PKG_CONFIG_PATH="/opt/openssl/${OPENSSL_VERSION}/lib/pkgconfig"

ruby -e '
  newsource = Gem::Source.new("http://rubygems.org")
  Gem.sources.replace([newsource])
  Gem.configuration.write

  spec = eval(File.read("openssl.gemspec"))
  spec.development_dependencies.each do |dep|
    Gem.install(dep.name, dep.requirement, force: true)
  end
'

exec $*
