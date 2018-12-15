/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#if !defined(_OSSL_CMS_H_)
#define _OSSL_CMS_H_

extern VALUE cCMS;
extern VALUE cCMSContentInfo;
extern VALUE cCMSSigner;
extern VALUE cCMSRecipient;
extern VALUE eCMSError;

void Init_ossl_cms(void);

#endif /* _OSSL_CMS_H_ */
