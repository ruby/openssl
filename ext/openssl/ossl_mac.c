#include "ossl.h"

#if OSSL_OPENSSL_PREREQ(3, 0, 0)

#define NewMAC(klass)                                   \
    TypedData_Wrap_Struct((klass), &ossl_mac_type, 0)
#define SetMAC(obj, ctx) do {                                           \
        if (!(ctx))                                                     \
            ossl_raise(rb_eRuntimeError, "MAC wasn't initialized");     \
        RTYPEDDATA_DATA(obj) = (ctx);                                   \
    } while (0)
#define GetMAC(obj, ctx) do {                                           \
        TypedData_Get_Struct((obj), EVP_MAC_CTX, &ossl_mac_type, (ctx)); \
        if (!(ctx))                                                     \
            ossl_raise(rb_eRuntimeError, "MAC wasn't initialized");     \
    } while (0)

/*
 * Classes
 */
static VALUE cMAC;
static VALUE cCMAC;
static VALUE eMACError;

/*
 * Public
 */

/*
 * Private
 */
static void
ossl_mac_free(void *ctx)
{
    EVP_MAC_CTX_free(ctx);
}

static const rb_data_type_t ossl_mac_type = {
    "OpenSSL/MAC",
    {
        0, ossl_mac_free,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY | RUBY_TYPED_WB_PROTECTED,
};

static VALUE
ossl_mac_alloc(VALUE klass)
{
    return NewMAC(klass);
}

static VALUE
ossl_mac_initialize(VALUE self, VALUE algorithm)
{
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;

    mac = EVP_MAC_fetch(NULL, StringValueCStr(algorithm), NULL);
    if (!mac)
        ossl_raise(eMACError, "EVP_MAC_fetch");
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        ossl_raise(eMACError, "EVP_MAC_CTX_new");
    }
    SetMAC(self, ctx);

    return self;
}

static VALUE
ossl_cmac_initialize(VALUE self, VALUE cipher, VALUE key)
{
    EVP_MAC_CTX *ctx;
    VALUE algorithm;
    OSSL_PARAM params[2];

    algorithm = rb_str_new_literal("CMAC");
    rb_call_super(1, &algorithm);

    GetMAC(self, ctx);
    StringValue(key);
    params[0] = OSSL_PARAM_construct_utf8_string("cipher", StringValueCStr(cipher), 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(ctx, (unsigned char *)RSTRING_PTR(key), RSTRING_LEN(key), params) != 1)
        ossl_raise(eMACError, "EVP_MAC_init");

    return self;
}

static VALUE
ossl_mac_copy(VALUE self, VALUE other)
{
    EVP_MAC_CTX *ctx1, *ctx2;

    rb_check_frozen(self);
    if (self == other)
        return self;

    GetMAC(other, ctx1);
    ctx2 = EVP_MAC_CTX_dup(ctx1);
    if (!ctx2)
        ossl_raise(eMACError, "EVP_MAC_CTX_dup");
    SetMAC(self, ctx2);

    return self;
}

static VALUE
ossl_mac_update(VALUE self, VALUE chunk)
{
    EVP_MAC_CTX *ctx;

    GetMAC(self, ctx);
    StringValue(chunk);
    if (EVP_MAC_update(ctx, (unsigned char *)RSTRING_PTR(chunk), RSTRING_LEN(chunk)) != 1)
        ossl_raise(eMACError, "EVP_MAC_update");

    return self;
}

static VALUE
ossl_mac_mac(VALUE self)
{
    VALUE ret;
    EVP_MAC_CTX *ctx1, *ctx2;
    size_t len;

    GetMAC(self, ctx1);
    if (EVP_MAC_final(ctx1, NULL, &len, 0) != 1)
        ossl_raise(eMACError, "EVP_MAC_final");
    ret = rb_str_new(NULL, len);
    ctx2 = EVP_MAC_CTX_dup(ctx1);
    if (!ctx2)
        ossl_raise(eMACError, "EVP_MAC_CTX_dup");
    if (EVP_MAC_final(ctx2, (unsigned char *)RSTRING_PTR(ret), &len, RSTRING_LEN(ret)) != 1) {
        EVP_MAC_CTX_free(ctx2);
        ossl_raise(eMACError, "EVP_MAC_final");
    }
    EVP_MAC_CTX_free(ctx2);

    return ret;
}

/*
 * INIT
 */
void
Init_ossl_mac(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    eOSSLError = rb_define_class_under(mOSSL, "OpenSSLError", rb_eStandardError);
#endif

    cMAC = rb_define_class_under(mOSSL, "MAC", rb_cObject);
    rb_define_alloc_func(cMAC, ossl_mac_alloc);
    rb_define_method(cMAC, "initialize", ossl_mac_initialize, 1);
    rb_define_method(cMAC, "initialize_copy", ossl_mac_copy, 1);
    rb_define_method(cMAC, "update", ossl_mac_update, 1);
    rb_define_alias(cMAC, "<<", "update");
    rb_define_method(cMAC, "mac", ossl_mac_mac, 0);

    cCMAC = rb_define_class_under(cMAC, "CMAC", cMAC);
    rb_define_method(cCMAC, "initialize", ossl_cmac_initialize, 2);

    eMACError = rb_define_class_under(mOSSL, "MACError", eOSSLError);
}
#else
void
Init_ossl_mac(void)
{
}
#endif
