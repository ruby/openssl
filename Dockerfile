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
  sed \
  xz-utils \
  zlib1g-dev

# Supported OpenSSL versions: 1.0.0, 1.0.1, 1.0.2
RUN mkdir -p /build/openssl && \
    curl -s https://www.openssl.org/source/openssl-1.0.0t.tar.gz | tar -C /build/openssl -xzf - && \
    cd build/openssl/openssl-1.0.0t && \
    ./config \
      --openssldir=/opt/openssl/openssl-1.0.0t \
      shared && \
    make && make install

RUN curl -s https://www.openssl.org/source/openssl-1.0.1q.tar.gz | tar -C /build/openssl -xzf - && \
    cd build/openssl/openssl-1.0.1q && \
    ./config \
       --openssldir=/opt/openssl/openssl-1.0.1q \
       shared && \
    make && make install

RUN curl -s https://www.openssl.org/source/openssl-1.0.2e.tar.gz | tar -C /build/openssl -xzf - && \
    cd build/openssl/openssl-1.0.2e && \
    ./config \
       --openssldir=/opt/openssl/openssl-1.0.2e \
       shared && \
    make && make install

# Supported libressl versions: 2.1.9, 2.2.5, 2.3.1
RUN mkdir -p /build/libressl
RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.1.9.tar.gz | tar -C /build/libressl -xzf -
RUN cd /build/libressl/libressl-2.1.9 && \
  ./configure --prefix=/opt/libressl/libressl-2.1.9 && make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.2.5.tar.gz | tar -C /build/libressl -xzf -
RUN cd /build/libressl/libressl-2.2.5 && \
  ./configure --prefix=/opt/libressl/libressl-2.2.5 && make && make install

RUN curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.3.1.tar.gz | tar -C /build/libressl -xzf -
RUN cd /build/libressl/libressl-2.3.1 && \
  ./configure --prefix=/opt/libressl/libressl-2.3.1 && make && make install

# Supported Ruby versions: 2.3.0
RUN mkdir -p /build/ruby && \
    curl -s https://cache.ruby-lang.org/pub/ruby/2.2/ruby-2.3.0.tar.gz | tar -C /build/ruby -xzf - && \
    cd /build/ruby/ruby-2.3.0 && \
    autoconf && ./configure \
      --without-openssl \
      --prefix=/opt/ruby/ruby-2.3.0 \
      --disable-install-doc && \
    make && make install

ENV PATH /opt/ruby/ruby-2.3.0/bin:$PATH

ONBUILD WORKDIR /home/openssl/code

COPY init.sh /home/openssl/init.sh
ENTRYPOINT ["/home/openssl/init.sh"]
