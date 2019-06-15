FROM ubuntu:18.04

# Supported OpenSSL versions: 1.0.1-
ENV OPENSSL10_VERSIONS 1.0.0t 1.0.1u 1.0.2p
ENV OPENSSL11_VERSIONS 1.1.0i 1.1.1
# Supported libressl versions: 2.3-
ENV LIBRESSL_VERSIONS 2.3.10 2.4.5 2.5.5 2.6.5 2.7.4
# Supported Ruby versions: 2.3-
ENV RUBY_VERSIONS 2.3.7 2.4.4 2.5.1

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

RUN mkdir -p /build/openssl
RUN for version in ${OPENSSL10_VERSIONS}; do \
      version_dir=$(echo "${version}" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*$/\1/') && \
      curl -s https://www.openssl.org/source/openssl-${version}.tar.gz | tar -C /build/openssl -xzf - && \
      cd /build/openssl/openssl-${version} && \
      ./Configure \
        --openssldir=/opt/openssl/openssl-${version_dir} \
        shared linux-x86_64 && \
      make && make install_sw; \
    done

RUN for version in ${OPENSSL11_VERSIONS}; do \
      version_dir=$(echo "${version}" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+).*$/\1/') && \
      curl -s https://www.openssl.org/source/openssl-${version}.tar.gz | tar -C /build/openssl -xzf - && \
      cd /build/openssl/openssl-${version} && \
      ./Configure \
        --prefix=/opt/openssl/openssl-${version_dir} \
        enable-crypto-mdebug enable-crypto-mdebug-backtrace \
        linux-x86_64 && \
      make && make install_sw; \
    done

RUN for version in ${LIBRESSL_VERSIONS}; do \
      version_dir=$(echo "${version}" | sed -E 's/^([0-9]+\.[0-9]+).*$/\1/') && \
      curl -s http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${version}.tar.gz | tar -C /build/openssl -xzf - && \
      cd /build/openssl/libressl-${version} && \
      ./configure \
        --prefix=/opt/openssl/libressl-${version_dir} && \
      make && make install; \
    done

RUN mkdir -p /build/ruby
RUN for version in ${RUBY_VERSIONS}; do \
      version_dir=$(echo "${version}" | sed -E 's/^([0-9]+\.[0-9]+).*$/\1/') && \
      curl -s https://cache.ruby-lang.org/pub/ruby/${version_dir}/ruby-${version}.tar.gz | tar -C /build/ruby -xzf - && \
      cd /build/ruby/ruby-${version} && \
      autoconf && ./configure \
        --without-openssl \
        --prefix=/opt/ruby/ruby-${version_dir} \
        --disable-install-doc && \
      make && make install; \
    done

ONBUILD ADD . /home/openssl/code
ONBUILD WORKDIR /home/openssl/code

COPY init.sh /home/openssl/init.sh
ENTRYPOINT ["/home/openssl/init.sh"]
