#include "ossl.h"

#define NewCMAC(klass)                                  \
    TypedData_Wrap_Struct((klass), &ossl_cmac_type, 0)
#define SetCMAC(obj, ctx) do {                                          \
        if (!(ctx))                                                     \
            ossl_raise(rb_eRuntimeError, "CMAC wasn't initialized");    \
        RTYPEDDATA_DATA(obj) = (ctx);                                   \
    } while (0)
#if OSSL_OPENSSL_PREREQ(3, 0, 0)
#define GetCMAC(obj, ctx) do {                                          \
        TypedData_Get_Struct((obj), EVP_MAC_CTX, &ossl_cmac_type, (ctx)); \
        if (!(ctx))                                                     \
            ossl_raise(rb_eRuntimeError, "CMAC wasn't initialized");    \
    } while (0)
#else
#define GetCMAC(obj, ctx) do {                                          \
        TypedData_Get_Struct((obj), CMAC_CTX, &ossl_cmac_type, (ctx));  \
        if (!(ctx))                                                     \
            ossl_raise(rb_eRuntimeError, "CMAC wasn't initialized");    \
    } while (0)
#endif

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
#if OSSL_OPENSSL_PREREQ(3, 0, 0)
    EVP_MAC_CTX_free(ctx);
#else
    CMAC_CTX_free(ctx);
#endif
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
#if OSSL_OPENSSL_PREREQ(3, 0, 0)
    VALUE obj;
    EVP_MAC *mac;
    EVP_MAC_CTX *ctx;

    obj = NewCMAC(klass);
    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac)
        ossl_raise(eCMACError, "EVP_MAC_fetch");
    ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        ossl_raise(eCMACError, "EVP_MAC_CTX_new");
    }
    SetCMAC(obj, ctx);

    return obj;
#else
    VALUE obj;
    CMAC_CTX *ctx;

    obj = NewCMAC(klass);
    ctx = CMAC_CTX_new();
    if (!ctx)
        ossl_raise(eCMACError, "CMAC_CTX_new");
    SetCMAC(obj, ctx);

    return obj;
#endif
}

/*
 *  call-seq:
 *    CMAC.new(key, cipher = "AES-128-CBC") -> new_cmac
 *
 * Returns an OpenSSL::CMAC for a message.
 */
static VALUE
ossl_cmac_initialize(int argc, VALUE *argv, VALUE self)
{
#if OSSL_OPENSSL_PREREQ(3, 0, 0)
    VALUE vkey, vcipher;
    EVP_MAC_CTX *ctx;
    OSSL_PARAM params[] = {
        OSSL_PARAM_END,
        OSSL_PARAM_END,
    };

    rb_scan_args(argc, argv, "11", &vkey, &vcipher);

    GetCMAC(self, ctx);
    StringValue(vkey);
    if (NIL_P(vcipher))
        vcipher = rb_str_new_cstr("AES-128-CBC");
    else if (rb_obj_is_kind_of(vcipher, cCipher))
        vcipher = rb_funcall(vcipher, rb_intern("name"), 0);
    params[0] = OSSL_PARAM_construct_utf8_string("cipher", StringValueCStr(vcipher), 0);
    if (EVP_MAC_init(ctx, (unsigned char *)RSTRING_PTR(vkey), RSTRING_LEN(vkey), params) != 1)
        ossl_raise(eCMACError, "EVP_MAC_init");

    return self;
#else
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
#endif
}

/* :nodoc: */
static VALUE
ossl_cmac_copy(VALUE self, VALUE other)
{
#if OSSL_OPENSSL_PREREQ(3, 0, 0)
    EVP_MAC_CTX *ctx1, *ctx2, *ctx3;

    rb_check_frozen(self);
    if (self == other)
        return self;

    GetCMAC(self, ctx1);
    GetCMAC(other, ctx2);
    ctx3 = EVP_MAC_CTX_dup(ctx2);
    if (!ctx3)
        ossl_raise(eCMACError, "EVP_MAC_CTX_dup");
    SetCMAC(self, ctx3);
    EVP_MAC_CTX_free(ctx1);

    return self;
#else
    CMAC_CTX *ctx1, *ctx2;

    rb_check_frozen(self);
    if (self == other)
        return self;

    GetCMAC(self, ctx1);
    GetCMAC(other, ctx2);
    if (CMAC_CTX_copy(ctx1, ctx2) != 1)
        ossl_raise(eCMACError, "CMAC_CTX_copy");

    return self;
#endif
}

/*
 *  call-seq:
 *    update(chunk) -> self
 *
 * Updates +self+ with a chunk of the message.
 */
static VALUE
ossl_cmac_update(VALUE self, VALUE chunk)
{
#if OSSL_OPENSSL_PREREQ(3, 0, 0)
    EVP_MAC_CTX *ctx;

    GetCMAC(self, ctx);
    StringValue(chunk);
    if (EVP_MAC_update(ctx, (unsigned char *)RSTRING_PTR(chunk), RSTRING_LEN(chunk)) != 1)
        ossl_raise(eCMACError, "EVP_MAC_update");

    return self;
#else
    CMAC_CTX *ctx;

    GetCMAC(self, ctx);
    StringValue(chunk);
    if (CMAC_Update(ctx, RSTRING_PTR(chunk), RSTRING_LEN(chunk)) != 1)
        ossl_raise(eCMACError, "CMAC_Update");

    return self;
#endif
}

/*
 *  call-seq:
 *    mac -> string
 *
 * Returns the MAC.
 */
static VALUE
ossl_cmac_mac(VALUE self)
{
#if OSSL_OPENSSL_PREREQ(3, 0, 0)
    VALUE ret;
    EVP_MAC_CTX *ctx1, *ctx2;
    size_t len;

    GetCMAC(self, ctx1);
    if (EVP_MAC_final(ctx1, NULL, &len, 0) != 1)
        ossl_raise(eCMACError, "EVP_MAC_final");
    ret = rb_str_new(NULL, len);
    ctx2 = EVP_MAC_CTX_dup(ctx1);
    if (!ctx2)
        ossl_raise(eCMACError, "EVP_MAC_CTX_dup");
    if (EVP_MAC_final(ctx2, (unsigned char *)RSTRING_PTR(ret), &len, RSTRING_LEN(ret)) != 1) {
        EVP_MAC_CTX_free(ctx2);
        ossl_raise(eCMACError, "EVP_MAC_final");
    }
    EVP_MAC_CTX_free(ctx2);

    return ret;
#else
    VALUE ret;
    CMAC_CTX *ctx1, *ctx2;
    size_t len;

    GetCMAC(self, ctx1);
    if (CMAC_Final(ctx1, NULL, &len) != 1)
        ossl_raise(eCMACError, "CMAC_Final");
    ret = rb_str_new(NULL, len);
    ctx2 = CMAC_CTX_new();
    if (!ctx2)
        ossl_raise(eCMACError, "CMAC_CTX_new");
    if (CMAC_CTX_copy(ctx2, ctx1) != 1) {
        CMAC_CTX_free(ctx2);
        ossl_raise(eCMACError, "CMAC_CTX_copy");
    }
    if (CMAC_Final(ctx2, (unsigned char *)RSTRING_PTR(ret), &len) != 1) {
        CMAC_CTX_free(ctx2);
        ossl_raise(eCMACError, "CMAC_Final");
    }
    CMAC_CTX_free(ctx2);

    return ret;
#endif
}

/*
 * INIT
 */
void
Init_ossl_cmac(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    eOSSLError = rb_define_class_under(mOSSL, "OpenSSLError", rb_eStandardError);
#endif

    /*
     * Document-class: OpenSSL::CMAC
     *
     * OpenSSL::CMAC provides generation of \CMAC message authentication codes (MACs).
     * The cipher algorithm to be used can be specified as a String or an OpenSSL::Cipher.
     * OpenSSL::CMAC has a similar interface to OpenSSL::HMAC.
     *
     * === Examples
     *
     *   key = ["8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"].pack("H*")
     *   message = ["6bc1bee22e409f96e93d7e117393172a"].pack("H*")
     *
     *   OpenSSL::CMAC.mac(key, message, "AES-192-CBC")
     *   #=> "\x9E\x99\xA7\xBF1\xE7\x10\x90\x06b\xF6^a|Q\x84"
     *   OpenSSL::CMAC.hexmac(key, message, "AES-192-CBC")
     *   #=> "9e99a7bf31e710900662f65e617c5184"
     *   OpenSSL::CMAC.base64mac(key, message, "AES-192-CBC")
     *   #=> "npmnvzHnEJAGYvZeYXxRhA=="
     *
     *   cmac = OpenSSL::CMAC.new(key, OpenSSL::Cipher.new("AES-192-CBC"))
     *   cmac.update(message[..11])
     *   cmac.update(message[12..])
     *   cmac.mac
     *   #=> "\x9E\x99\xA7\xBF1\xE7\x10\x90\x06b\xF6^a|Q\x84"
     *   cmac.hexmac
     *   #=> "9e99a7bf31e710900662f65e617c5184"
     *   cmac.base64mac
     *   #=> "npmnvzHnEJAGYvZeYXxRhA=="
     *
     */
    cCMAC = rb_define_class_under(mOSSL, "CMAC", rb_cObject);

    /*
     * Document-class: OpenSSL::CMACError
     *
     * Raised when a \CMAC operation fails.
     * See OpenSSL::CMAC.
     */
    eCMACError = rb_define_class_under(mOSSL, "CMACError", eOSSLError);

    rb_define_alloc_func(cCMAC, ossl_cmac_alloc);
    rb_define_method(cCMAC, "initialize", ossl_cmac_initialize, -1);
    rb_define_method(cCMAC, "initialize_copy", ossl_cmac_copy, 1);
    rb_define_method(cCMAC, "update", ossl_cmac_update, 1);
    rb_define_alias(cCMAC, "<<", "update");
    rb_define_method(cCMAC, "mac", ossl_cmac_mac, 0);
}
