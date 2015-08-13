#!/bin/bash

echo "Using Ruby ${RUBY_VERSION} with OpenSSL ${OPENSSL_VERSION}."
export PATH="/opt/ruby/ruby-${RUBY_VERSION}-with-openssl-${OPENSSL_VERSION}/bin:$PATH"
gem install bundler
bundle install

exec $*
