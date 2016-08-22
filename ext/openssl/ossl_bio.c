/*
 * 'OpenSSL for Ruby' team members
 * Copyright (C) 2003
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

BIO *
ossl_obj2bio(VALUE obj)
{
    BIO *bio;

    if (RB_TYPE_P(obj, T_FILE)) {
	rb_io_t *fptr;
	FILE *fp;
	int fd;

	GetOpenFile(obj, fptr);
	rb_io_check_readable(fptr);
	if ((fd = rb_cloexec_dup(fptr->fd)) < 0){
	    rb_sys_fail(0);
	}
        rb_update_max_fd(fd);
	if (!(fp = fdopen(fd, "r"))){
	    int e = errno;
	    close(fd);
	    rb_syserr_fail(e, 0);
	}
	if (!(bio = BIO_new_fp(fp, BIO_CLOSE))){
	    fclose(fp);
	    ossl_raise(eOSSLError, NULL);
	}
    }
    else {
	StringValue(obj);
	bio = BIO_new_mem_buf(RSTRING_PTR(obj), RSTRING_LENINT(obj));
	if (!bio) ossl_raise(eOSSLError, NULL);
    }

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
