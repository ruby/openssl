FROM ubuntu:14.04

RUN apt-get update && apt-get install -y --no-install-recommends \
  autoconf \
  bison \
  build-essential \
  bzip2 \
  ca-certificates \
  cpio \
  curl \
  file \
  git \
  gzip \
  libreadline-dev \
  make \
  patch \
  pkg-config \
  sed \
  xz-utils \
  zlib1g-dev

# Supported OpenSSL versions: 1.0.0, 1.0.1, 1.0.2, 1.1.0
RUN mkdir -p /build/openssl
RUN curl -s https://www.openssl.org/source/openssl-1.0.0t.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.0.0t && \
    ./Configure \
      --openssldir=/opt/openssl/openssl-1.0.0 \
      shared debug-linux-x86_64 && \
    make && make install_sw

RUN curl -s https://www.openssl.org/source/openssl-1.0.1t.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.0.1t && \
    ./Configure \
      --openssldir=/opt/openssl/openssl-1.0.1 \
      shared debug-linux-x86_64 && \
    make && make install_sw

RUN curl -s https://www.openssl.org/source/openssl-1.0.2h.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.0.2h && \
    ./Configure \
      --openssldir=/opt/openssl/openssl-1.0.2 \
      shared debug-linux-x86_64 && \
    make && make install_sw

RUN curl -s https://www.openssl.org/source/openssl-1.1.0-pre6.tar.gz | tar -C /build/openssl -xzf - && \
    cd /build/openssl/openssl-1.1.0-pre6 && \
    ./Configure \
      --prefix=/opt/openssl/openssl-1.1.0 \
      enable-crypto-mdebug enable-crypto-mdebug-backtrace \
      debug-linux-x86_64 && \
    make && make install_sw

# Supported libressl versions: 2.1, 2.2, 2.3, 2.4
RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.1.10.tar.gz | tar -C /build/openssl -xzf -
RUN cd /build/openssl/libressl-2.1.10 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.1 && \
    make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.2.9.tar.gz | tar -C /build/openssl -xzf -
RUN cd /build/openssl/libressl-2.2.9 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.2 && \
    make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.3.7.tar.gz | tar -C /build/openssl -xzf -
RUN cd /build/openssl/libressl-2.3.7 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.3 && \
    make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.4.2.tar.gz | tar -C /build/openssl -xzf -
RUN cd /build/openssl/libressl-2.4.2 && \
    ./configure \
      --prefix=/opt/openssl/libressl-2.4 && \
    make && make install

# Supported Ruby versions: 2.3
RUN mkdir -p /build/ruby
RUN curl -s https://cache.ruby-lang.org/pub/ruby/2.3/ruby-2.3.1.tar.gz | tar -C /build/ruby -xzf - && \
    cd /build/ruby/ruby-2.3.1 && \
    autoconf && ./configure \
      --without-openssl \
      --prefix=/opt/ruby/ruby-2.3 \
      --disable-install-doc && \
    make && make install

ONBUILD ADD . /home/openssl/code
ONBUILD WORKDIR /home/openssl/code

COPY init.sh /home/openssl/init.sh
ENTRYPOINT ["/home/openssl/init.sh"]
