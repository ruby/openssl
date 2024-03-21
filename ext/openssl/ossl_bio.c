/*
 * 'OpenSSL for Ruby' team members
 * Copyright (C) 2003
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'COPYING'.)
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

static BIO_METHOD *ossl_bio_meth;
static VALUE nonblock_kwargs, sym_wait_readable, sym_wait_writable;

struct ossl_bio_ctx {
    VALUE io;
    int state;
    int eof;
};

static void
bio_free(void *ptr)
{
    BIO_free(ptr);
}

static void
bio_mark(void *ptr)
{
    struct ossl_bio_ctx *ctx = BIO_get_data(ptr);
    rb_gc_mark_movable(ctx->io);
}

static void
bio_compact(void *ptr)
{
    struct ossl_bio_ctx *ctx = BIO_get_data(ptr);
    ctx->io = rb_gc_location(ctx->io);
}

static const rb_data_type_t ossl_bio_type = {
    "OpenSSL/BIO",
    {
        .dmark = bio_mark,
        .dfree = bio_free,
        .dcompact = bio_compact,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

VALUE
ossl_bio_new(VALUE io)
{
    VALUE obj = TypedData_Wrap_Struct(rb_cObject, &ossl_bio_type, NULL);
    BIO *bio = BIO_new(ossl_bio_meth);
    if (!bio)
        ossl_raise(eOSSLError, "BIO_new");

    struct ossl_bio_ctx *ctx = BIO_get_data(bio);
    ctx->io = io;
    BIO_set_init(bio, 1);
    RTYPEDDATA_DATA(obj) = bio;
    return obj;
}

BIO *
ossl_bio_get(VALUE obj)
{
    BIO *bio;
    TypedData_Get_Struct(obj, BIO, &ossl_bio_type, bio);
    return bio;
}

int
ossl_bio_state(VALUE obj)
{
    BIO *bio;
    TypedData_Get_Struct(obj, BIO, &ossl_bio_type, bio);

    struct ossl_bio_ctx *ctx = BIO_get_data(bio);
    int state = ctx->state;
    ctx->state = 0;
    return state;
}

static int
bio_create(BIO *bio)
{
    struct ossl_bio_ctx *ctx = OPENSSL_malloc(sizeof(*ctx));
    if (!ctx)
        return 0;
    memset(ctx, 0, sizeof(*ctx));
    BIO_set_data(bio, ctx);

    return 1;
}

static int
bio_destroy(BIO *bio)
{
    struct ossl_bio_ctx *ctx = BIO_get_data(bio);
    if (ctx) {
        OPENSSL_free(ctx);
        BIO_set_data(bio, NULL);
    }

    return 1;
}

struct bwrite_args {
    BIO *bio;
    struct ossl_bio_ctx *ctx;
    const char *data;
    int dlen;
    int written;
};

static VALUE
bio_bwrite0(VALUE args)
{
    struct bwrite_args *p = (void *)args;
    BIO_clear_retry_flags(p->bio);

    VALUE fargs[] = { rb_str_new_static(p->data, p->dlen), nonblock_kwargs };
    VALUE ret = rb_funcallv_kw(p->ctx->io, rb_intern("write_nonblock"),
                               2, fargs, RB_PASS_KEYWORDS);

    if (RB_INTEGER_TYPE_P(ret)) {
        p->written = NUM2INT(ret);
        return Qtrue;
    }
    else if (ret == sym_wait_readable) {
        BIO_set_retry_read(p->bio);
        return Qfalse;
    }
    else if (ret == sym_wait_writable) {
        BIO_set_retry_write(p->bio);
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
    struct ossl_bio_ctx *ctx = BIO_get_data(bio);
    struct bwrite_args args = { bio, ctx, data, dlen, 0 };
    int state;

    if (ctx->state)
        return -1;

    VALUE ok = rb_protect(bio_bwrite0, (VALUE)&args, &state);
    if (state) {
        ctx->state = state;
        return -1;
    }
    if (RTEST(ok))
        return args.written;
    return -1;
}

struct bread_args {
    BIO *bio;
    struct ossl_bio_ctx *ctx;
    char *data;
    int dlen;
    int readbytes;
};

static VALUE
bio_bread0(VALUE args)
{
    struct bread_args *p = (void *)args;
    BIO_clear_retry_flags(p->bio);

    VALUE fargs[] = { INT2NUM(p->dlen), nonblock_kwargs };
    VALUE ret = rb_funcallv_kw(p->ctx->io, rb_intern("read_nonblock"),
                               2, fargs, RB_PASS_KEYWORDS);

    if (RB_TYPE_P(ret, T_STRING)) {
        int len = RSTRING_LENINT(ret);
        if (len > p->dlen)
            rb_raise(rb_eTypeError, "read_nonblock returned too much data");
        memcpy(p->data, RSTRING_PTR(ret), len);
        p->readbytes = len;
        return Qtrue;
    }
    else if (NIL_P(ret)) {
        // In OpenSSL 3.0 or later: BIO_set_flags(p->bio, BIO_FLAGS_IN_EOF);
        p->ctx->eof = 1;
        return Qtrue;
    }
    else if (ret == sym_wait_readable) {
        BIO_set_retry_read(p->bio);
        return Qfalse;
    }
    else if (ret == sym_wait_writable) {
        BIO_set_retry_write(p->bio);
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
    struct ossl_bio_ctx *ctx = BIO_get_data(bio);
    struct bread_args args = { bio, ctx, data, dlen, 0 };
    int state;

    if (ctx->state)
        return -1;

    VALUE ok = rb_protect(bio_bread0, (VALUE)&args, &state);
    if (state) {
        ctx->state = state;
        return -1;
    }
    if (RTEST(ok))
        return args.readbytes;
    return -1;
}

static VALUE
bio_flush0(VALUE vctx)
{
    struct ossl_bio_ctx *ctx = (void *)vctx;
    return rb_funcallv(ctx->io, rb_intern("flush"), 0, NULL);
}

static long
bio_ctrl(BIO *bio, int cmd, long larg, void *parg)
{
    struct ossl_bio_ctx *ctx = BIO_get_data(bio);
    int state;

    if (ctx->state)
        return 0;

    switch (cmd) {
      case BIO_CTRL_EOF:
        return ctx->eof;
      case BIO_CTRL_FLUSH:
        rb_protect(bio_flush0, (VALUE)ctx, &state);
        ctx->state = state;
        return !state;
      default:
        return 0;
    }
}

void
Init_ossl_bio(void)
{
    ossl_bio_meth = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Ruby IO-like object");
    if (!ossl_bio_meth)
        ossl_raise(eOSSLError, "BIO_meth_new");
    if (!BIO_meth_set_create(ossl_bio_meth, bio_create) ||
        !BIO_meth_set_destroy(ossl_bio_meth, bio_destroy) ||
        !BIO_meth_set_write(ossl_bio_meth, bio_bwrite) ||
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
