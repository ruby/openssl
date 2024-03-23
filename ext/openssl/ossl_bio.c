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
#include <openssl/bio.h>

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

BIO_METHOD *ossl_bio_meth;
static int bio_state_idx, bio_errinfo_idx, bio_eof_idx;
static VALUE nonblock_kwargs;

static void
bio_save_error(BIO *bio, int state)
{
    VALUE errinfo = Qnil;
    if (state) {
        errinfo = rb_errinfo();
        if (rb_obj_is_kind_of(errinfo, rb_eException))
            rb_set_errinfo(Qnil);
        else
            errinfo = Qnil;
    }
    BIO_set_ex_data(bio, bio_state_idx, (void *)(uintptr_t)state);
    BIO_set_ex_data(bio, bio_errinfo_idx, (void *)errinfo);
}

int
ossl_bio_restore_error(BIO *bio)
{
    int state = (int)(uintptr_t)BIO_get_ex_data(bio, bio_state_idx);
    if (!state)
        return 0;

    VALUE errinfo = (VALUE)BIO_get_ex_data(bio, bio_errinfo_idx);
    BIO_set_ex_data(bio, bio_state_idx, (void *)(uintptr_t)0);
    BIO_set_ex_data(bio, bio_errinfo_idx, (void *)Qnil);
    if (!NIL_P(errinfo))
        rb_set_errinfo(errinfo);
    return state;
}

struct bwrite_args {
    BIO *bio;
    const char *data;
    int dlen;
    int written;
};

static VALUE
bio_bwrite0(VALUE args)
{
    struct bwrite_args *p = (void *)args;
    VALUE io = (VALUE)BIO_get_data(p->bio);
    BIO_clear_retry_flags(p->bio);

    VALUE fargs[] = { rb_str_new_static(p->data, p->dlen), nonblock_kwargs };
    VALUE ret = rb_funcallv_public_kw(io, rb_intern("write_nonblock"),
                                      2, fargs, RB_PASS_KEYWORDS);

    if (RB_INTEGER_TYPE_P(ret)) {
        p->written = NUM2INT(ret);
        return INT2FIX(1);
    }
    else if (ret == ID2SYM(rb_intern("wait_readable"))) {
        BIO_set_retry_read(p->bio);
        return INT2FIX(0);
    }
    else if (ret == ID2SYM(rb_intern("wait_writable"))) {
        BIO_set_retry_write(p->bio);
        return INT2FIX(0);
    }
    else {
        rb_raise(rb_eTypeError, "write_nonblock must return an Integer, "
                 ":wait_readable, or :wait_writable");
    }
}

static int
bio_bwrite(BIO *bio, const char *data, int dlen)
{
    struct bwrite_args args = { bio, data, dlen, 0 };
    int state;

    VALUE ret = rb_protect(bio_bwrite0, (VALUE)&args, &state);
    bio_save_error(bio, state);
    if (state)
        return 0;
    if (FIX2INT(ret))
        return args.written;
    return -1;
}

struct bread_args {
    BIO *bio;
    char *data;
    int dlen;
    int readbytes;
};

static VALUE
bio_bread0(VALUE args)
{
    struct bread_args *p = (void *)args;
    VALUE io = (VALUE)BIO_get_data(p->bio);
    BIO_clear_retry_flags(p->bio);

    VALUE fargs[] = { INT2NUM(p->dlen), nonblock_kwargs };
    VALUE ret = rb_funcallv_public_kw(io, rb_intern("read_nonblock"),
                                      2, fargs, RB_PASS_KEYWORDS);

    if (RB_TYPE_P(ret, T_STRING)) {
        int len = RSTRING_LENINT(ret);
        if (len > p->dlen)
            rb_raise(rb_eTypeError, "read_nonblock returned too much data");
        memcpy(p->data, RSTRING_PTR(ret), len);
        p->readbytes = len;
        return INT2FIX(1);
    }
    else if (NIL_P(ret)) {
        // In OpenSSL 3.0 or later: BIO_set_flags(p->bio, BIO_FLAGS_IN_EOF);
        BIO_set_ex_data(p->bio, bio_eof_idx, (void *)1);
        return INT2FIX(0);
    }
    else if (ret == ID2SYM(rb_intern("wait_readable"))) {
        BIO_set_retry_read(p->bio);
        return INT2FIX(0);
    }
    else if (ret == ID2SYM(rb_intern("wait_writable"))) {
        BIO_set_retry_write(p->bio);
        return INT2FIX(0);
    }
    else {
        rb_raise(rb_eTypeError, "write_nonblock must return an Integer, "
                 ":wait_readable, or :wait_writable");
    }
}

static int
bio_bread(BIO *bio, char *data, int dlen)
{
    struct bread_args args = { bio, data, dlen, 0 };
    int state;

    VALUE ret = rb_protect(bio_bread0, (VALUE)&args, &state);
    bio_save_error(bio, state);
    if (state)
        return 0;
    if (FIX2INT(ret))
        return args.readbytes;
    return -1;
}

static VALUE
bio_flush0(VALUE vbio)
{
    VALUE io = (VALUE)BIO_get_data((BIO *)vbio);
    return rb_funcallv_public(io, rb_intern("flush"), 0, NULL);
}

static long
bio_ctrl(BIO *bio, int cmd, long larg, void *parg)
{
    int state;

    switch (cmd) {
      case BIO_CTRL_EOF:
        return (int)(uintptr_t)BIO_get_ex_data(bio, bio_eof_idx);
      case BIO_CTRL_FLUSH:
        rb_protect(bio_flush0, (VALUE)bio, &state);
        bio_save_error(bio, state);
        return !state;
      default:
        return 0;
    }
}

void
Init_ossl_bio(void)
{
    if ((bio_state_idx = BIO_get_ex_new_index(0, NULL, NULL, NULL, NULL)) < 0 ||
        (bio_errinfo_idx = BIO_get_ex_new_index(0, NULL, NULL, NULL, NULL)) < 0 ||
        (bio_eof_idx = BIO_get_ex_new_index(0, NULL, NULL, NULL, NULL)) < 0)
        ossl_raise(eOSSLError, "BIO_get_ex_new_index");

    ossl_bio_meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Ruby IO-like object");
    if (!ossl_bio_meth)
        ossl_raise(eOSSLError, "BIO_meth_new");
    if (!BIO_meth_set_write(ossl_bio_meth, bio_bwrite) ||
        !BIO_meth_set_read(ossl_bio_meth, bio_bread) ||
        !BIO_meth_set_ctrl(ossl_bio_meth, bio_ctrl)) {
        BIO_meth_free(ossl_bio_meth);
        ossl_bio_meth = NULL;
        ossl_raise(eOSSLError, "BIO_meth_set_*");
    }

    nonblock_kwargs = rb_hash_new();
    rb_hash_aset(nonblock_kwargs, ID2SYM(rb_intern("exception")), Qfalse);
    rb_global_variable(&nonblock_kwargs);
}
