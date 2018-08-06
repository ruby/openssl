FROM ubuntu:18.04

RUN apt-get update && apt-get install -y --no-install-recommends \
  autoconf \
  bison \
  build-essential \
  ca-certificates \
  curl \
  gzip \
  libreadline-dev \
  patch \
  pkg-config \
  sed \
  zlib1g-dev

# Supported OpenSSL versions: 1.0.1-
RUN mkdir -p /build/openssl
RUN curl -s https://www.openssl.org/source/openssl-1.0.0t.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.0.0t && \
    ./Configure \
      --openssldir=/opt/openssl/openssl-1.0.0 \
      shared linux-x86_64 && \
    make && make install_sw

RUN curl -s https://www.openssl.org/source/openssl-1.0.1u.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.0.1u && \
    ./Configure \
      --openssldir=/opt/openssl/openssl-1.0.1 \
      shared linux-x86_64 && \
    make && make install_sw

RUN curl -s https://www.openssl.org/source/openssl-1.0.2o.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.0.2o && \
    ./Configure \
      --openssldir=/opt/openssl/openssl-1.0.2 \
      shared linux-x86_64 && \
    make && make install_sw

RUN curl -s https://www.openssl.org/source/openssl-1.1.0h.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.1.0h && \
    ./Configure \
      --prefix=/opt/openssl/openssl-1.1.0 \
      enable-crypto-mdebug enable-crypto-mdebug-backtrace \
      linux-x86_64 && \
    make && make install_sw

RUN curl -s https://www.openssl.org/source/openssl-1.1.1-pre8.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.1.1-pre8 && \
    ./Configure \
      --prefix=/opt/openssl/openssl-1.1.1 \
      enable-crypto-mdebug enable-crypto-mdebug-backtrace \
      linux-x86_64 && \
    make && make install_sw

# Supported libressl versions: 2.3-
RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.3.10.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/libressl-2.3.10 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.3 && \
    make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.4.5.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/libressl-2.4.5 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.4 && \
    make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.5.5.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/libressl-2.5.5 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.5 && \
    make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.6.5.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/libressl-2.6.5 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.6 && \
    make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.7.4.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/libressl-2.7.4 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.7 && \
    make && make install

# Supported Ruby versions: 2.3-
RUN mkdir -p /build/ruby
RUN curl -s https://cache.ruby-lang.org/pub/ruby/2.3/ruby-2.3.7.tar.gz | tar -C /build/ruby -xzf - && \
    cd /build/ruby/ruby-2.3.7 && \
    autoconf && ./configure \
      --without-openssl \
      --prefix=/opt/ruby/ruby-2.3 \
      --disable-install-doc && \
    make && make install

RUN curl -s https://cache.ruby-lang.org/pub/ruby/2.4/ruby-2.4.4.tar.gz | tar -C /build/ruby -xzf - && \
    cd /build/ruby/ruby-2.4.4 && \
    autoconf && ./configure \
      --without-openssl \
      --prefix=/opt/ruby/ruby-2.4 \
      --disable-install-doc && \
    make && make install

RUN curl -s https://cache.ruby-lang.org/pub/ruby/2.5/ruby-2.5.1.tar.gz | tar -C /build/ruby -xzf - && \
    cd /build/ruby/ruby-2.5.1 && \
    autoconf && ./configure \
      --without-openssl \
      --prefix=/opt/ruby/ruby-2.5 \
      --disable-install-doc && \
    make && make install

ONBUILD ADD . /home/openssl/code
ONBUILD WORKDIR /home/openssl/code

COPY init.sh /home/openssl/init.sh
ENTRYPOINT ["/home/openssl/init.sh"]
