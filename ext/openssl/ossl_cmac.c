#include "ossl.h"

#define NewCMAC(klass)                                  \
    TypedData_Wrap_Struct((klass), &ossl_cmac_type, 0)
#define SetCMAC(obj, ctx) do {                                          \
        if (!(ctx))                                                     \
            ossl_raise(rb_eRuntimeError, "CMAC wasn't initialized");    \
        RTYPEDDATA_DATA(obj) = (ctx);                                   \
    } while (0)
#define GetCMAC(obj, ctx) do {                                          \
        TypedData_Get_Struct((obj), CMAC_CTX, &ossl_cmac_type, (ctx));  \
        if (!(ctx))                                                     \
            ossl_raise(rb_eRuntimeError, "CMAC wasn't initialized");    \
    } while (0)

/*
 * Classes
 */
VALUE cCMAC;
VALUE eCMACError;

/*
 * Public
 */

/*
 * Private
 */
static void
ossl_cmac_free(void *ctx)
{
    CMAC_CTX_free(ctx);
}

static const rb_data_type_t ossl_cmac_type = {
    "OpenSSL/CMAC",
    {
        0, ossl_cmac_free,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

static VALUE
ossl_cmac_alloc(VALUE klass)
{
    VALUE obj;
    CMAC_CTX *ctx;

    obj = NewCMAC(klass);
    ctx = CMAC_CTX_new();
    if (!ctx)
        ossl_raise(eCMACError, "CMAC_CTX_new");
    SetCMAC(obj, ctx);

    return obj;
}

static VALUE
ossl_cmac_initialize(int argc, VALUE *argv, VALUE self)
{
    VALUE vkey, vcipher;
    CMAC_CTX *ctx;
    const EVP_CIPHER *cipher;

    rb_scan_args(argc, argv, "11", &vkey, &vcipher);

    GetCMAC(self, ctx);
    StringValue(vkey);
    cipher = NIL_P(vcipher) ? EVP_aes_128_cbc() : ossl_evp_get_cipherbyname(vcipher);
    if (CMAC_Init(ctx, RSTRING_PTR(vkey), RSTRING_LEN(vkey), cipher, NULL) != 1)
        ossl_raise(eCMACError, "CMAC_Init");

    return self;
}

static VALUE
ossl_cmac_copy(VALUE self, VALUE other)
{
    CMAC_CTX *ctx1, *ctx2;

    rb_check_frozen(self);
    if (self == other)
        return self;

    GetCMAC(self, ctx1);
    GetCMAC(other, ctx2);
    if (CMAC_CTX_copy(ctx1, ctx2) != 1)
        ossl_raise(eCMACError, "CMAC_CTX_copy");

    return self;
}

static VALUE
ossl_cmac_update(VALUE self, VALUE chunk)
{
    CMAC_CTX *ctx;

    GetCMAC(self, ctx);
    StringValue(chunk);
    if (CMAC_Update(ctx, RSTRING_PTR(chunk), RSTRING_LEN(chunk)) != 1)
        ossl_raise(eCMACError, "CMAC_Update");

    return self;
}

static VALUE
ossl_cmac_mac(VALUE self)
{
    VALUE ret;
    CMAC_CTX *ctx;
    size_t len;

    GetCMAC(self, ctx);
    if (CMAC_Final(ctx, NULL, &len) != 1)
        ossl_raise(eCMACError, "CMAC_Final");
    ret = rb_str_new(NULL, len);
    if (CMAC_Final(ctx, (unsigned char *)RSTRING_PTR(ret), &len) != 1)
        ossl_raise(eCMACError, "CMAC_Final");
    if (CMAC_resume(ctx) != 1)
        ossl_raise(eCMACError, "CMAC_resume");

    return ret;
}

/*
 * INIT
 */
void
Init_ossl_cmac(void)
{
    cCMAC = rb_define_class_under(mOSSL, "CMAC", rb_cObject);
    eCMACError = rb_define_class_under(mOSSL, "CMACError", eOSSLError);
    rb_define_alloc_func(cCMAC, ossl_cmac_alloc);
    rb_define_method(cCMAC, "initialize", ossl_cmac_initialize, -1);
    rb_define_method(cCMAC, "initialize_copy", ossl_cmac_copy, 1);
    rb_define_method(cCMAC, "update", ossl_cmac_update, 1);
    rb_define_alias(cCMAC, "<<", "update");
    rb_define_method(cCMAC, "mac", ossl_cmac_mac, 0);
}
