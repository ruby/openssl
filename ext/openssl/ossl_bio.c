/*
 * 'OpenSSL for Ruby' team members
 * Copyright (C) 2003
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

BIO *
ossl_obj2bio(volatile VALUE *pobj)
{
    VALUE obj = *pobj;
    BIO *bio;

    if (RB_TYPE_P(obj, T_FILE))
	obj = rb_funcallv(obj, rb_intern("read"), 0, NULL);
    StringValue(obj);
    bio = BIO_new_mem_buf(RSTRING_PTR(obj), RSTRING_LENINT(obj));
    if (!bio)
	ossl_raise(eOSSLError, "BIO_new_mem_buf");
    *pobj = obj;
    return bio;
}

VALUE
ossl_membio2str(BIO *bio)
{
    VALUE ret;
    int state;
    BUF_MEM *buf;

    BIO_get_mem_ptr(bio, &buf);
    ret = ossl_str_new(buf->data, buf->length, &state);
    BIO_free(bio);
    if (state)
	rb_jump_tag(state);

    return ret;
}

int
ossl_membio_sock_read(BIO* bio, VALUE io) {
    VALUE nonblock_kwargs = rb_hash_new();
    rb_hash_aset(nonblock_kwargs, ID2SYM(rb_intern("exception")), Qfalse);

    printf("reading...\n");

    VALUE fargs[] = { INT2NUM(4096), nonblock_kwargs };
    VALUE ret = rb_funcallv_public_kw(io, rb_intern("read_nonblock"), 2, fargs, RB_PASS_KEYWORDS);
    printf("just read...\n");
    int len;
    char *bstr;

    if (RB_TYPE_P(ret, T_STRING)) {
        len = RSTRING_LENINT(ret);
        bstr = RSTRING_PTR(ret);
        printf("read the nonblock: %d...\n", len);
    }
    else if (ret == ID2SYM(rb_intern("wait_readable"))) {
        // BIO_set_retry_read(bio);
        return SSL_ERROR_WANT_READ;
    }
    else if (ret == ID2SYM(rb_intern("wait_writable"))) {
        // BIO_set_retry_write(bio);
        return SSL_ERROR_WANT_WRITE;
    }
    else if (NIL_P(ret)) {
        printf("fuck the nil\n");
        return SSL_ERROR_ZERO_RETURN;
    }
    else {
        printf("elsing\n");
        rb_raise(rb_eTypeError, "write_nonblock must return an Integer, "
                 ":wait_readable, or :wait_writable");
    }

    while (len > 0) {
        int n = BIO_write(bio, bstr, len);
        BIO_clear_retry_flags(bio);

        if (n<=0)
            return SSL_ERROR_SYSCALL; // unrecoverable

        bstr += n;
        len -= n;

        // // finish handshake if required
        // if (!SSL_is_init_finished(client.ssl)) {
        //     if (do_ssl_handshake() == SSLSTATUS_FAIL)
        //         return SSL_ERROR_SYSCALL;
        //     if (!SSL_is_init_finished(client.ssl))
        //         // assume there are bytes missing
        //         return SSL_ERROR_WANT_READ;
        // }
    }
    return SSL_ERROR_NONE;
}

int
ossl_membio_sock_write(BIO* bio, VALUE io) {
    char buf[4096];
    char *p = buf;

    int n = BIO_read(bio, p, 4096);
    BIO_clear_retry_flags(bio);
    if (n <= 0) {
       if (!BIO_should_retry(bio))
            // TODO: raise exception
            return -1;
    }

    printf("writing to bio 2: %d\n", n);

    VALUE nonblock_kwargs = rb_hash_new();
    rb_hash_aset(nonblock_kwargs, ID2SYM(rb_intern("exception")), Qfalse);

    VALUE fargs[] = { rb_str_new_static(buf, n), nonblock_kwargs };

    // rb_io_write(rb_stdout ,rb_sprintf("%s\n", RSTRING_PTR(*biobuf)));
    // rb_p(*biobuf);
    VALUE ret = rb_funcallv_public_kw(io, rb_intern("write_nonblock"), 2, fargs, RB_PASS_KEYWORDS);

    if (RB_INTEGER_TYPE_P(ret)) {
        // TODO: resize buffer
        return SSL_ERROR_NONE;
    }
    else if (ret == ID2SYM(rb_intern("wait_readable"))) {
        printf("wred\n");
        // BIO_set_retry_read(bio);
        return SSL_ERROR_WANT_READ;
    }
    else if (ret == ID2SYM(rb_intern("wait_writable"))) {
        printf("wwrit\n");
        // BIO_set_retry_write(bio);
        return SSL_ERROR_WANT_WRITE;
    } else if (NIL_P(ret)) {
        printf("closed\n");
        return SSL_ERROR_ZERO_RETURN;
    }
    else {
        rb_raise(rb_eTypeError, "write_nonblock must return an Integer, "
                 ":wait_readable, or :wait_writable");
    }
}