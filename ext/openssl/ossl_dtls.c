/*
 * 'OpenSSL for Ruby' project
 * clone from ossl_ssl.c by Michael Richardson <mcr@sandelman.ca>
 * Copyright (C) 2017 Michael Richardson <mcr@sandelman.ca>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

VALUE cDTLSContext;
VALUE cDTLSSocket;
static VALUE eSSLError;
extern VALUE cSSLContext;
static int ossl_dtlsctx_ex_ptr_idx;  /* suspect this should be shared with ssl*/

extern const rb_data_type_t ossl_sslctx_type;

static VALUE
ossl_dtlsctx_s_alloc(VALUE klass)
{
    SSL_CTX *ctx;
    long mode = 0 |
	SSL_MODE_ENABLE_PARTIAL_WRITE |
	SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER |
	SSL_MODE_RELEASE_BUFFERS;
    VALUE obj;

    obj = TypedData_Wrap_Struct(klass, &ossl_sslctx_type, 0);
    ctx = SSL_CTX_new(DTLS_method());
    if (!ctx) {
        ossl_raise(eSSLError, "DTLS_CTX_new");
    }
    SSL_CTX_set_mode(ctx, mode);
    RTYPEDDATA_DATA(obj) = ctx;
    SSL_CTX_set_ex_data(ctx, ossl_dtlsctx_ex_ptr_idx, (void *)obj);

#if !defined(OPENSSL_NO_EC) && defined(HAVE_SSL_CTX_SET_ECDH_AUTO)
    /* We use SSL_CTX_set1_curves_list() to specify the curve used in ECDH. It
     * allows to specify multiple curve names and OpenSSL will select
     * automatically from them. In OpenSSL 1.0.2, the automatic selection has to
     * be enabled explicitly. But OpenSSL 1.1.0 removed the knob and it is
     * always enabled. To uniform the behavior, we enable the automatic
     * selection also in 1.0.2. Users can still disable ECDH by removing ECDH
     * cipher suites by SSLContext#ciphers=. */
    if (!SSL_CTX_set_ecdh_auto(ctx, 1))
	ossl_raise(eSSLError, "DTLS_CTX_set_ecdh_auto");
#endif

    return obj;
}

#ifndef OPENSSL_NO_SOCK
static VALUE
ossl_dtls_setup(VALUE self)
{
    VALUE io;
    SSL *ssl;
    rb_io_t *fptr;
    BIO *bio = NULL;

    GetSSL(self, ssl);
    if (ssl_started(ssl))
	return Qtrue;

    io = rb_attr_get(self, id_i_io);
    GetOpenFile(io, fptr);
    rb_io_check_readable(fptr);
    rb_io_check_writable(fptr);

    printf("dtls setup for fd: %d\n", TO_SOCKET(fptr->fd));
    bio = BIO_new_dgram(TO_SOCKET(fptr->fd), BIO_NOCLOSE);
    if(bio == NULL) {
      ossl_raise(eSSLError, "ossl_dtls_setup");
    }
    SSL_set_bio(ssl, bio, bio);

    return Qtrue;
}

/*
 * call-seq:
 *    ssl.accept => self
 *
 * Waits for a SSL/TLS client to initiate a handshake.  The handshake may be
 * started after unencrypted data has been sent over the socket.
 */
static VALUE
ossl_dtls_accept(VALUE self)
{
    ossl_dtls_setup(self);

    return ossl_start_ssl(self, SSL_accept, "SSL_accept", Qfalse);
}

#if 0
/*
 * call-seq:
 *    SSLSocket.new(io) => aSSLSocket
 *    SSLSocket.new(io, ctx) => aSSLSocket
 *
 * Creates a new SSL socket from _io_ which must be a real IO object (not an
 * IO-like object that responds to read/write).
 *
 * If _ctx_ is provided the SSL Sockets initial params will be taken from
 * the context.
 *
 * The OpenSSL::Buffering module provides additional IO methods.
 *
 * This method will freeze the SSLContext if one is provided;
 * however, session management is still allowed in the frozen SSLContext.
 */
static VALUE
ossl_dtls_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE io, v_ctx, verify_cb;
    SSL *ssl;
    SSL_CTX *ctx;

    TypedData_Get_Struct(self, SSL, &ossl_ssl_type, ssl);
    if (ssl)
	ossl_raise(eSSLError, "SSL already initialized");

    if (rb_scan_args(argc, argv, "11", &io, &v_ctx) == 1)
	v_ctx = rb_funcall(cSSLContext, rb_intern("new"), 0);

    GetSSLCTX(v_ctx, ctx);
    rb_ivar_set(self, id_i_context, v_ctx);
    ossl_sslctx_setup(v_ctx);

    if (rb_respond_to(io, rb_intern("nonblock=")))
	rb_funcall(io, rb_intern("nonblock="), 1, Qtrue);
    rb_ivar_set(self, id_i_io, io);

    ssl = SSL_new(ctx);
    if (!ssl)
	ossl_raise(eSSLError, NULL);
    RTYPEDDATA_DATA(self) = ssl;

    SSL_set_ex_data(ssl, ossl_ssl_ex_ptr_idx, (void *)self);
    SSL_set_info_callback(ssl, ssl_info_cb);
    verify_cb = rb_attr_get(v_ctx, id_i_verify_callback);
    SSL_set_ex_data(ssl, ossl_ssl_ex_vcb_idx, (void *)verify_cb);

    rb_call_super(0, NULL);

    return self;
}

/*
 * call-seq:
 *    ssl.connect_nonblock([options]) => self
 *
 * Initiates the SSL/TLS handshake as a client in non-blocking manner.
 *
 *   # emulates blocking connect
 *   begin
 *     ssl.connect_nonblock
 *   rescue IO::WaitReadable
 *     IO.select([s2])
 *     retry
 *   rescue IO::WaitWritable
 *     IO.select(nil, [s2])
 *     retry
 *   end
 *
 * By specifying a keyword argument _exception_ to +false+, you can indicate
 * that connect_nonblock should not raise an IO::WaitReadable or
 * IO::WaitWritable exception, but return the symbol +:wait_readable+ or
 * +:wait_writable+ instead.
 */
static VALUE
ossl_dtls_connect_nonblock(int argc, VALUE *argv, VALUE self)
{
    VALUE opts;
    rb_scan_args(argc, argv, "0:", &opts);

    ossl_dtls_setup(self);

    return ossl_start_ssl(self, SSL_connect, "SSL_connect", opts);
}

/*
 * call-seq:
 *    ssl.accept_nonblock([options]) => self
 *
 * Initiates the SSL/TLS handshake as a server in non-blocking manner.
 *
 *   # emulates blocking accept
 *   begin
 *     ssl.accept_nonblock
 *   rescue IO::WaitReadable
 *     IO.select([s2])
 *     retry
 *   rescue IO::WaitWritable
 *     IO.select(nil, [s2])
 *     retry
 *   end
 *
 * By specifying a keyword argument _exception_ to +false+, you can indicate
 * that accept_nonblock should not raise an IO::WaitReadable or
 * IO::WaitWritable exception, but return the symbol +:wait_readable+ or
 * +:wait_writable+ instead.
 */
static VALUE
ossl_dtls_accept_nonblock(int argc, VALUE *argv, VALUE self)
{
    VALUE opts;

    rb_scan_args(argc, argv, "0:", &opts);
    ossl_dtls_setup(self);

    return ossl_start_ssl(self, SSL_accept, "SSL_accept", opts);
}

#endif /* 0 */
#endif /* !defined(OPENSSL_NO_SOCK) */

#undef rb_intern
#define rb_intern(s) rb_intern_const(s)
void
Init_ossl_dtls(void)
{
    /* Document-module: OpenSSL::SSL
     *
     * Use SSLContext to set up the parameters for a TLS (former SSL)
     * connection. Both client and server TLS connections are supported,
     * SSLSocket and SSLServer may be used in conjunction with an instance
     * of SSLContext to set up connections.
     */
    mSSL = rb_define_module_under(mOSSL, "SSL");
    eSSLError = rb_define_class_under(mSSL, "SSLError", eOSSLError);

    /* Document-class: OpenSSL::SSL::DTLSContext
     *
     * A DTLSContext is used to set various options regarding certificates,
     * algorithms, verification, session caching, etc.  The DTLSContext is
     * used to create a DTLSSocket.
     *
     * All attributes must be set before creating a DTLSSocket as the
     * DTLSContext will be frozen afterward.
     */
    cDTLSContext = rb_define_class_under(mSSL, "DTLSContext", cSSLContext);
    rb_define_alloc_func(cDTLSContext, ossl_dtlsctx_s_alloc);
    rb_undef_method(cDTLSContext, "initialize_copy");

    cDTLSSocket = rb_define_class_under(mSSL, "DTLSSocket", cSSLSocket);
    rb_define_method(cDTLSSocket, "accept",     ossl_dtls_accept, 0);
}
