/*
 *
 * Copyright (C) 2010 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */

#if !defined(_OSSL_TS_H_)
#define _OSSL_TS_H_

extern VALUE mTimestamp;
extern VALUE eTimestampError;
extern VALUE eCertValidationError;

extern VALUE cTimestampRequest;
extern VALUE cTimestampResponse;
extern VALUE cTimestampFactory;

void Init_ossl_ts(void);
TS_RESP *GetTsRespPtr(VALUE obj);

#endif
