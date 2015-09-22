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
    curl -s https://www.openssl.org/source/openssl-1.0.0s.tar.gz | tar -C /build/openssl -xzf - && \
    cd build/openssl/openssl-1.0.0s && \
    ./config \
       --openssldir=/opt/openssl/openssl-1.0.0s \
       --libdir=lib \
       shared \
       zlib-dynamic && \
    make && make install

RUN mkdir -p /build/openssl && \
    curl -s https://www.openssl.org/source/openssl-1.0.1p.tar.gz | tar -C /build/openssl -xzf - && \
    cd build/openssl/openssl-1.0.1p && \
    ./config \
       --openssldir=/opt/openssl/openssl-1.0.1p \
       --libdir=lib \
       shared \
       zlib-dynamic && \
    make && make install

RUN mkdir -p /build/openssl && \
    curl -s https://www.openssl.org/source/openssl-1.0.2d.tar.gz | tar -C /build/openssl -xzf - && \
    cd build/openssl/openssl-1.0.2d && \
    ./config \
       --openssldir=/opt/openssl/openssl-1.0.2d \
       --libdir=lib \
       shared \
       zlib-dynamic && \
    make && make install

# Supported Ruby versions: 2.2.2, 2.2.3
RUN mkdir -p /build/ruby && \
    curl -s https://cache.ruby-lang.org/pub/ruby/2.2/ruby-2.2.3.tar.gz | tar -C /build/ruby -xzf - && \
    cd /build/ruby/ruby-2.2.3 && \
    autoconf && ./configure \
      --with-openssl-dir=/opt/openssl/openssl-1.0.1p \
      --prefix=/opt/ruby/ruby-2.2.3-with-openssl-1.0.1p \
      --disable-install-doc && \
    make && make install

ENV PATH /opt/ruby/ruby-2.2.3-with-openssl-1.0.1p/bin:$PATH

RUN cd /build/ruby/ruby-2.2.3 && \
    make distclean && \
    autoconf && ./configure \
      --with-openssl-dir=/opt/openssl/openssl-1.0.0s \
      --prefix=/opt/ruby/ruby-2.2.3-with-openssl-1.0.0s \
      --disable-install-doc && \
    make && make install

RUN cd /build/ruby/ruby-2.2.3 && \
    make distclean && \
    autoconf && ./configure \
      --with-openssl-dir=/opt/openssl/openssl-1.0.2d \
      --prefix=/opt/ruby/ruby-2.2.3-with-openssl-1.0.2d \
      --disable-install-doc && \
    make && make install

RUN cd /build/ruby && \
    curl -s https://cache.ruby-lang.org/pub/ruby/2.2/ruby-2.2.2.tar.gz | tar -C /build/ruby -xzf - && \
    cd /build/ruby/ruby-2.2.2 && \
    autoconf && ./configure \
      --with-openssl-dir=/opt/openssl/openssl-1.0.1p \
      --prefix=/opt/ruby/ruby-2.2.2-with-openssl-1.0.1p \
      --disable-install-doc && \
    make && make install

RUN cd /build/ruby/ruby-2.2.2 && \
    make distclean && \
    autoconf && ./configure \
      --with-openssl-dir=/opt/openssl/openssl-1.0.0s \
      --prefix=/opt/ruby/ruby-2.2.2-with-openssl-1.0.0s \
      --disable-install-doc && \
    make && make install

RUN cd /build/ruby/ruby-2.2.2 && \
    make distclean && \
    autoconf && ./configure \
      --with-openssl-dir=/opt/openssl/openssl-1.0.2d \
      --prefix=/opt/ruby/ruby-2.2.2-with-openssl-1.0.2d \
      --disable-install-doc && \
    make && make install

ONBUILD WORKDIR /home/openssl/code

COPY init.sh /home/openssl/init.sh
ENTRYPOINT ["/home/openssl/init.sh"]
