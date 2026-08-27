/*
 * Ruby/OpenSSL Project
 * Copyright (C) 2025  Kazuki Yamaguchi <k@rhe.jp>
 */
#include "ossl.h"

static BIO_METHOD *ossl_bio_meth;
static VALUE nonblock_kwargs, sym_wait_readable, sym_wait_writable;

BIO *
ossl_ssl_bio_setup(struct ossl_ssl_data *p)
{
    BIO *bio = BIO_new(ossl_bio_meth);
    if (!bio)
        ossl_raise(eOSSLError, "BIO_new");

    BIO_set_data(bio, p);
    BIO_set_init(bio, 1);
    return bio;
}

struct call0_args {
    VALUE (*func)(VALUE);
    VALUE args;
    VALUE ret;
};

static VALUE
do_nothing(VALUE _)
{
    return Qnil;
}

static VALUE
call_protect1(VALUE args_)
{
    struct call0_args *args = (void *)args_;
    rb_set_errinfo(Qnil);
    args->ret = args->func(args->args);
    return Qnil;
}

static VALUE
call_protect0(VALUE args_)
{
    rb_ensure(do_nothing, Qnil, call_protect1, args_);
    return Qnil;
}

static VALUE
call_protect(VALUE (*func)(VALUE), VALUE args, int *state, int current)
{
    if (!current)
        return rb_protect(func, args, state);

    VALUE errinfo = rb_errinfo();
    struct call0_args call0_args = { func, args, Qnil };
    rb_protect(call_protect0, (VALUE)&call0_args, state);
    if (*state) {
        if (!rb_obj_is_kind_of(errinfo, rb_eException))
            errinfo = rb_str_new_cstr("(unknown)");
        rb_warn("BIO callback raised an exception, pending jump suppressed: " \
                "state=%d, errinfo=%+"PRIsVALUE, current, errinfo);
    }
    return call0_args.ret;
}


struct bwrite_args {
    struct ossl_ssl_data *p;
    BIO *bio;
    const char *data;
    int dlen;
    int written;
};

static VALUE
bio_bwrite0(VALUE args_)
{
    struct bwrite_args *args = (void *)args_;
    struct ossl_ssl_data *p = args->p;

    BIO_clear_retry_flags(args->bio);

    VALUE fargs[] = { rb_str_new_static(args->data, args->dlen), nonblock_kwargs };
    VALUE ret = rb_funcallv_kw(p->io, rb_intern("write_nonblock"),
                               2, fargs, RB_PASS_KEYWORDS);

    if (RB_INTEGER_TYPE_P(ret)) {
        args->written = NUM2INT(ret);
        return Qtrue;
    }
    else if (ret == sym_wait_readable) {
        BIO_set_retry_read(args->bio);
        return Qfalse;
    }
    else if (ret == sym_wait_writable) {
        BIO_set_retry_write(args->bio);
        return Qfalse;
    }
    else {
        rb_raise(rb_eTypeError, "write_nonblock must return an Integer, "
                 ":wait_readable, or :wait_writable");
    }
}

static int
bio_bwrite(BIO *bio, const char *data, int dlen)
{
    struct ossl_ssl_data *p = BIO_get_data(bio);

    struct bwrite_args args = { p, bio, data, dlen, 0 };
    int state;
    VALUE ok = call_protect(bio_bwrite0, (VALUE)&args, &state, p->cb_state);
    if (state) {
        p->cb_state = state;
        return -1;
    }
    if (RTEST(ok))
        return args.written;
    return -1;
}

struct bread_args {
    struct ossl_ssl_data *p;
    BIO *bio;
    char *data;
    int dlen;
    int readbytes;
};

static VALUE
bio_bread0(VALUE args_)
{
    struct bread_args *args = (void *)args_;
    struct ossl_ssl_data *p = args->p;

    BIO_clear_retry_flags(args->bio);

    VALUE fargs[] = { INT2NUM(args->dlen), nonblock_kwargs };
    VALUE ret = rb_funcallv_kw(p->io, rb_intern("read_nonblock"),
                               2, fargs, RB_PASS_KEYWORDS);

    if (RB_TYPE_P(ret, T_STRING)) {
        int len = RSTRING_LENINT(ret);
        if (len > args->dlen)
            rb_raise(rb_eTypeError, "read_nonblock returned too much data");
        memcpy(args->data, RSTRING_PTR(ret), len);
        args->readbytes = len;
        return Qtrue;
    }
    else if (NIL_P(ret)) {
        // In OpenSSL 3.0 or later: BIO_set_flags(args->bio, BIO_FLAGS_IN_EOF);
        p->bio_eof = 1;
        return Qtrue;
    }
    else if (ret == sym_wait_readable) {
        BIO_set_retry_read(args->bio);
        return Qfalse;
    }
    else if (ret == sym_wait_writable) {
        BIO_set_retry_write(args->bio);
        return Qfalse;
    }
    else {
        rb_raise(rb_eTypeError, "write_nonblock must return an Integer, "
                 ":wait_readable, or :wait_writable");
    }
}

static int
bio_bread(BIO *bio, char *data, int dlen)
{
    struct ossl_ssl_data *p = BIO_get_data(bio);

    struct bread_args args = { p, bio, data, dlen, 0 };
    int state;
    VALUE ok = call_protect(bio_bread0, (VALUE)&args, &state, p->cb_state);
    if (state) {
        p->cb_state = state;
        return -1;
    }
    if (RTEST(ok))
        return args.readbytes;
    return -1;
}

static VALUE
bio_flush0(VALUE p_)
{
    struct ossl_ssl_data *p = (void *)p_;
    /*
     * If the underlying IO-like object does not respond to flush, let's just
     * assume that it does not need to be flushed.
     */
    return rb_check_funcall(p->io, rb_intern("flush"), 0, NULL);
}

static long
bio_ctrl(BIO *bio, int cmd, long larg, void *parg)
{
    struct ossl_ssl_data *p = BIO_get_data(bio);
    int state;

    switch (cmd) {
      case BIO_CTRL_EOF:
        return p->bio_eof;
      case BIO_CTRL_FLUSH:
        call_protect(bio_flush0, (VALUE)p, &state, p->cb_state);
        if (state) {
            p->cb_state = state;
            return 0;
        }
        return 1;
      default:
        return 0;
    }
}

void
Init_ossl_ssl_bio(void)
{
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
    rb_hash_aset(nonblock_kwargs, ID2SYM(rb_intern_const("exception")), Qfalse);
    rb_global_variable(&nonblock_kwargs);

    sym_wait_readable = ID2SYM(rb_intern_const("wait_readable"));
    sym_wait_writable = ID2SYM(rb_intern_const("wait_writable"));
}

