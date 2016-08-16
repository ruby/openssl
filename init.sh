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

gem build openssl.gemspec
gem install --development --clear-sources -s http://rubygems.org openssl-*.gem -- --with-openssl-dir=/opt/openssl/$OPENSSL_VERSION

exec $*
