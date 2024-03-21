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

BIO_METHOD *ossl_bio_meth;
static int bio_state_idx, bio_errinfo_idx;

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
    size_t dlen;
    size_t *written;
};

static VALUE
bio_bwrite0(VALUE args)
{
    struct bwrite_args *p = (void *)args;
    VALUE io = (VALUE)BIO_get_data(p->bio);
    BIO_clear_retry_flags(p->bio);

    VALUE str = rb_str_new_static(p->data, p->dlen);
    VALUE kwargs = rb_hash_new();
    rb_hash_aset(kwargs, ID2SYM(rb_intern("exception")), Qfalse);
    VALUE funcallargs[] = { str, kwargs };
    VALUE ret = rb_funcallv_public_kw(io, rb_intern("write_nonblock"),
                                      2, funcallargs, RB_PASS_KEYWORDS);

    if (RB_INTEGER_TYPE_P(ret)) {
        *p->written = NUM2SIZET(ret);
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
bio_bwrite(BIO *bio, const char *data, size_t dlen, size_t *written)
{
    struct bwrite_args args = { bio, data, dlen, written };
    int state;

    VALUE ret = rb_protect(bio_bwrite0, (VALUE)&args, &state);
    bio_save_error(bio, state);
    if (state)
        return 0;
    return FIX2INT(ret);
}

struct bread_args {
    BIO *bio;
    char *data;
    size_t dlen;
    size_t *readbytes;
};

static VALUE
bio_bread0(VALUE args)
{
    struct bread_args *p = (void *)args;
    VALUE io = (VALUE)BIO_get_data(p->bio);
    BIO_clear_retry_flags(p->bio);

    VALUE kwargs = rb_hash_new();
    rb_hash_aset(kwargs, ID2SYM(rb_intern("exception")), Qfalse);
    VALUE funcallargs[] = { SIZET2NUM(p->dlen), kwargs };
    VALUE ret = rb_funcallv_public_kw(io, rb_intern("read_nonblock"),
                                      2, funcallargs, RB_PASS_KEYWORDS);

    if (RB_TYPE_P(ret, T_STRING)) {
        size_t len = (size_t)RSTRING_LEN(ret);
        if (len > p->dlen)
            rb_raise(rb_eTypeError, "read_nonblock returned too much data");
        memcpy(p->data, RSTRING_PTR(ret), len);
        *p->readbytes = len;
        return INT2FIX(1);
    }
    else if (NIL_P(ret)) {
        BIO_set_flags(p->bio, BIO_FLAGS_IN_EOF);
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
bio_bread(BIO *bio, char *data, size_t dlen, size_t *readbytes)
{
    struct bread_args args = { bio, data, dlen, readbytes };
    int state;

    VALUE ret = rb_protect(bio_bread0, (VALUE)&args, &state);
    bio_save_error(bio, state);
    if (state)
        return 0;
    return FIX2INT(ret);
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
        return BIO_test_flags(bio, BIO_FLAGS_IN_EOF);
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
        (bio_errinfo_idx = BIO_get_ex_new_index(0, NULL, NULL, NULL, NULL)) < 0)
        ossl_raise(eOSSLError, "BIO_get_ex_new_index");

    ossl_bio_meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Ruby IO-like object");
    if (!ossl_bio_meth)
        ossl_raise(eOSSLError, "BIO_meth_new");
    if (!BIO_meth_set_write_ex(ossl_bio_meth, bio_bwrite) ||
        !BIO_meth_set_read_ex(ossl_bio_meth, bio_bread) ||
        !BIO_meth_set_ctrl(ossl_bio_meth, bio_ctrl)) {
        BIO_meth_free(ossl_bio_meth);
        ossl_bio_meth = NULL;
        ossl_raise(eOSSLError, "BIO_meth_set_*");
    }
}
