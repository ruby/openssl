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

Alternatively, you can install the gem with `bundler`:

```ruby
# Gemfile
gem 'openssl'
# or specify git master
gem 'openssl', github: 'ruby/openssl'
```

After doing `bundle install`, you should have the gem installed in your bundle.

## Usage

Once installed, you can require "openssl" in your application.

```ruby
require "openssl"
```

NOTE: If you are using Ruby 2.3 (and not Bundler), you **must** activate the
gem version of openssl, otherwise the default gem packaged with the Ruby
installation will be used:

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

Please read our [CONTRIBURING.md] for instructions.

## Security

Security issues should be reported to ruby-core by following the process
described on ["Security at ruby-lang.org"](https://www.ruby-lang.org/en/security/).


[CONTRIBURING.md]: https://github.com/ruby/openssl/tree/master/CONTRIBURING.md
