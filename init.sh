#!/bin/bash

if [[ "$OPENSSL_VERSION" != "" ]]
then
  echo "Using Ruby ${RUBY_VERSION} with OpenSSL ${OPENSSL_VERSION}."
  export PATH="/opt/ruby/ruby-${RUBY_VERSION}/bin:$PATH"
elif [[ "$LIBRESSL_VERSION" != "" ]]
then
  echo "Using Ruby ${RUBY_VERSION} with LibreSSL ${LIBRESSL_VERSION}."
  export PATH="/opt/ruby/ruby-${RUBY_VERSION}/bin:$PATH"
fi

gem build openssl.gemspec
if [[ "$OPENSSL_VERSION" != "" ]]
then
  gem install --development --clear-sources -s http://rubygems.org openssl-*.gem -- --with-openssl-dir=/opt/openssl/openssl-$OPENSSL_VERSION
elif [[ "$LIBRESSL_VERSION" != "" ]]
then
  gem install --development --clear-sources -s http://rubygems.org openssl-*.gem -- --with-openssl-dir=/opt/libressl/libressl-$LIBRESSL_VERSION
fi

exec $*
