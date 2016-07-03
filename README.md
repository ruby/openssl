# OpenSSL

[![Build Status](https://travis-ci.org/ruby/openssl.svg?branch=master)](https://travis-ci.org/ruby/openssl)

OpenSSL provides SSL, TLS and general purpose cryptography. It wraps the
OpenSSL library.

## Installation

The openssl gem is available at [rubygems.org](https://rubygems.org/gems/openssl).
You can install with:

```
gem install openssl
```

You may need to specify the path where OpenSSL is installed.

```
gem install openssl -- --with-openssl-dir=/opt/openssl
```

## Usage

After you install it, you can require "openssl" in your application.

```ruby
require "openssl"
```

If you are using Ruby 2.3, you may need to tell RubyGems to prefer the gem
version of openssl.

```ruby
gem "openssl"
require "openssl"
```

See the documentation on OpenSSL for more usage,
and the official [OpenSSL library](http://www.openssl.org/).

## Getting Started

1. `$ gem install rake-compiler test-unit`
2. `$ rake compile`
3. `$ rake test`

## Contributing

Please read CONTRIBURING.md for instructions.

## Security

Security issues should be reported following the process described in the
[Security page on ruby-lang.org](https://www.ruby-lang.org/en/security/).
