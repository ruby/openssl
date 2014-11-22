# Openssl

* [![Build Status](https://travis-ci.org/zzak/openssl.svg?branch=master)](https://travis-ci.org/zzak/openssl)

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

TODO: Write usage instructions here

## Contributing

1. Fork it ( https://github.com/zzak/openssl/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

## Updating from source

```
~/code/openssl => cp -R ~/src/ruby/ext/openssl/*.{c,h} ext/openssl/.
~/code/openssl => cp -R ~/src/ruby/ext/openssl/deprecation.rb ext/openssl/deprecation.rb
~/code/openssl => cp -R ~/src/ruby/ext/openssl/extconf.rb ext/openssl/extconf.rb
~/code/openssl => cp -R ~/src/ruby/ext/openssl/lib/* lib/.
```
