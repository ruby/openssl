# Openssl

[![Build Status](https://travis-ci.org/ruby/openssl.svg?branch=master)](https://travis-ci.org/ruby/openssl)

OpenSSL provides SSL, TLS and general purpose cryptography.  It wraps the OpenSSL library.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'openssl'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install openssl

## Usage

See the documentation on OpenSSL for more usage,
and the official [openssl library](http://www.openssl.org/).

## Contributing

1. Fork it ( https://github.com/ruby/openssl/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Updating from source

```
~/code/openssl => cp ../ruby/ext/openssl/*.{c,h,rb} ext/openssl/.
~/code/openssl => cp -R ../ruby/ext/openssl/lib/ lib/
```
