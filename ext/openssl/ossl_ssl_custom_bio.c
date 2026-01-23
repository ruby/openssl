/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2026  Sharon Rosner <sharon@noteflakes.com>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'COPYING'.)
*/
#include "ossl.h"

#ifdef HAVE_BIO_METH_NEW

#include "ossl_ssl_custom_bio.h"
#include "ruby/io/buffer.h"

extern VALUE eSSLError;
static ID id_read, id_write, id_call, id_eof_p;

static int
ossl_ssl_custom_bio_in_read(BIO *bio, char *buf, int blen)
{
    VALUE target = (VALUE)BIO_get_data(bio);

    switch(TYPE(target)) {
        case T_FILE:
        case T_OBJECT:
        case T_STRUCT: {
            VALUE str = rb_funcall(target, id_read, 1, INT2NUM(blen));
            int slen = RSTRING_LEN(str);
            memcpy(buf, RSTRING_PTR(str), slen);
            RB_GC_GUARD(str);
            return slen;
        }
        case T_ARRAY: {
            VALUE read_proc = rb_ary_entry(target, 0);
            VALUE buffer = rb_io_buffer_new(buf, blen, RB_IO_BUFFER_LOCKED);
            VALUE len = rb_funcall(read_proc, id_call, 2, buffer, INT2NUM(blen));
            rb_io_buffer_free_locked(buffer);
            return NUM2INT(len);
        }
        default:
            rb_raise(eSSLError, "Invalid BIO target");
    }
}

static int
ossl_ssl_custom_bio_out_write(BIO *bio, const char *buf, int blen)
{
    VALUE target = (VALUE)BIO_get_data(bio);
    switch(TYPE(target)) {
        case T_FILE:
        case T_OBJECT:
        case T_STRUCT: {
            VALUE str = rb_str_new(buf, blen);
            VALUE res = rb_funcall(target, id_write, 1, str);
            RB_GC_GUARD(str);
            return NUM2SIZET(res);
        }
        case T_ARRAY: {
            VALUE write_proc = rb_ary_entry(target, 1);
            VALUE buffer = rb_io_buffer_new((char *)buf, blen, RB_IO_BUFFER_LOCKED | RB_IO_BUFFER_READONLY);
            VALUE len = rb_funcall(write_proc, id_call, 2, buffer, INT2NUM(blen));
            RB_GC_GUARD(buffer);
            rb_io_buffer_free_locked(buffer);
            return NUM2INT(len);
        }
        default:
            rb_raise(eSSLError, "Invalid BIO target");
    }
}

static long
ossl_ssl_custom_bio_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    VALUE target = (VALUE)BIO_get_data(bio);

    switch(cmd) {
        case BIO_CTRL_GET_CLOSE:
            return (long)BIO_get_shutdown(bio);
        case BIO_CTRL_SET_CLOSE:
            BIO_set_shutdown(bio, (int)num);
            return 1;
        case BIO_CTRL_FLUSH:
            // we don't buffer writes, so noop
            return 1;
        case BIO_CTRL_EOF: {
            switch(TYPE(target)) {
                case T_FILE:
                case T_OBJECT:
                case T_STRUCT: {
                    VALUE eof = rb_funcall(target, id_eof_p, 0);
                    return RTEST(eof);
                }
                default:
                    return 0;
            }
        }
        default:
            return 0;
    }
}

BIO_METHOD *
ossl_ssl_create_custom_bio_method()
{
    BIO_METHOD *m = BIO_meth_new(BIO_TYPE_MEM, "OpenSSL Ruby BIO");
    if(m) {
        BIO_meth_set_write(m, &ossl_ssl_custom_bio_out_write);
        BIO_meth_set_read(m, &ossl_ssl_custom_bio_in_read);
        BIO_meth_set_ctrl(m, &ossl_ssl_custom_bio_ctrl);
    }
    return m;
}


static BIO_METHOD *custom_bio_method = NULL;

void
ossl_ssl_set_custom_bio(SSL *ssl, VALUE target)
{
    if (!custom_bio_method) {
        custom_bio_method = ossl_ssl_create_custom_bio_method();
        id_read   = rb_intern_const("read");
        id_write  = rb_intern_const("write");
        id_call   = rb_intern_const("call");
        id_eof_p  = rb_intern_const("eof?");
    }

    BIO *bio = BIO_new(custom_bio_method);
    if(!bio)
        rb_raise(eSSLError, "Failed to create custom BIO");

    BIO_set_data(bio, (void *)target);
#ifdef HAVE_SSL_SET0_RBIO
    BIO_up_ref(bio);
    SSL_set0_rbio(ssl, bio);
    SSL_set0_wbio(ssl, bio);
#else
    SSL_set_bio(ssl, bio, bio);
#endif
}

#endif
