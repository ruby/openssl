# ruby-openssl-docker

Th following rubies are currently included:

```
$ docker run -it ruby-openssl-docker ls /opt/ruby
-  ruby-2.2.2-with-openssl-1.0.0s
-  ruby-2.2.2-with-openssl-1.0.1p
-  ruby-2.2.2-with-openssl-1.0.2d
-  ruby-2.2.3-with-openssl-1.0.1p
-  ruby-2.2.3-with-openssl-1.0.0s
-  ruby-2.2.3-with-openssl-1.0.2d
```

For example:

```
OPENSSL_VERSION=1.0.1p
RUBY_VERSION=2.2.2

$ docker run -it openssl-docker \
    /opt/ruby/ruby-${RUBY_VERSION}-with-openssl-${OPENSSL_VERSION}/bin/ruby \
    -ropenssl -e 'puts RUBY_DESCRIPTION; puts OpenSSL::OPENSSL_VERSION'

ruby 2.2.2p95 (2015-04-13 revision 50295) [x86_64-linux]
OpenSSL 1.0.1p 9 Jul 2015
```
