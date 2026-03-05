/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2026  Sharon Rosner <sharon@noteflakes.com>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'COPYING'.)
*/
#if !defined(_OSSL_SSL_CUSTOM_BIO_H_)
#define _OSSL_SSL_CUSTOM_BIO_H_

#include "ossl.h"

void ossl_ssl_set_custom_bio(SSL *ssl, VALUE target);

#endif /* _OSSL_SSL_CUSTOM_BIO_H_ */
