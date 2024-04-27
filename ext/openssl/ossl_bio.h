/*
 * 'OpenSSL for Ruby' team members
 * Copyright (C) 2003
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_BIO_H_)
#define _OSSL_BIO_H_

BIO *ossl_obj2bio(volatile VALUE *);
VALUE ossl_membio2str(BIO*);

extern BIO_METHOD *ossl_bio_meth;
int ossl_bio_restore_error(BIO *bio);

void Init_ossl_bio(void);

#endif
