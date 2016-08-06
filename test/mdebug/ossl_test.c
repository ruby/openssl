#include <ruby.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/err.h>

static VALUE mOSSL;

#if !defined(OPENSSL_NO_MDEBUG)
/*
 * call-seq:
 *   OpenSSL.print_mem_leaks -> nil
 *
 * For debugging this openssl library. Prints memory leaks recorded by OpenSSL
 * to stderr. This is available only when OpenSSL is compiled with
 * crypto-mdebug. This methods cleanups the global state of OpenSSL thus you
 * mustn't use any methods of the library after calling this.
 *
 * === Example
 *   OpenSSL.debug = true
 *   NOT_GCED = OpenSSL::PKey::RSA.new(256)
 *
 *   END {
 *     GC.start
 *     OpenSSL.print_mem_leaks # will print the leakage
 *   }
 */
static VALUE
print_mem_leaks(VALUE self)
{
    extern BN_CTX *ossl_bn_ctx;

    BN_CTX_free(ossl_bn_ctx);
    ossl_bn_ctx = NULL;

    CRYPTO_mem_leaks_fp(stderr);

    ossl_bn_ctx = BN_CTX_new();
    if (!ossl_bn_ctx)
	rb_raise(rb_eRuntimeError, "BN_CTX_new");

    return Qnil;
}
#endif

void
Init_mdebug(void)
{
    mOSSL = rb_path2class("OpenSSL");

#if !defined(OPENSSL_NO_MDEBUG)
    rb_define_module_function(mOSSL, "print_mem_leaks", print_mem_leaks, 0);

    /*
     * Prepare for OpenSSL.print_mem_leaks. Below are all dirty hack and may
     * not work depending the version of OpenSSL.
     */
    {
	int i;
	/*
	 * See crypto/ex_data.c; call def_get_class()
	 * 100 is the maximum number that is used as the class index in OpenSSL
	 * 1.0.2.
	 */
#if defined(CRYPTO_EX_INDEX__COUNT)
	for (i = 0; i < CRYPTO_EX_INDEX__COUNT; i++) {
#else
	for (i = 0; i <= 100; i++) {
#endif
	    if (CRYPTO_get_ex_new_index(i, 0, (void *)"mdebug-tmp",
					0, 0, 0) < 0)
		rb_raise(rb_eRuntimeError, "CRYPTO_get_ex_new_index for "
			 "class index %d failed", i);
	}

#if defined(V_CRYPTO_MDEBUG_ALL)
	/*
	 * Show full information in OpenSSL.print_mem_leaks
	 */
	CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
#endif
    }

    /* Then, enable memcheck */
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
}
