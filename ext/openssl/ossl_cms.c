/*
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2018       Michael Richardson <mcr@sandelman.ca>
 * copied from ossl_pkcs7.c:
 *   Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include "ossl.h"

#if defined(HAVE_CMS_SIGN)
/*
 * The CMS_ContentInfo is the primary data structure which this module creates and maintains
 * Is is called OpenSSL::CMS::ContentInfo in ruby.
 *
 */

#define NewCMSContentInfo(klass) \
    TypedData_Wrap_Struct((klass), &ossl_cms_content_info_type, 0)
#define SetCMSContentInfo(obj, cmsci) do { \
    if (!(cmsci)) { \
	ossl_raise(rb_eRuntimeError, "CMS wasn't initialized."); \
    } \
    RTYPEDDATA_DATA(obj) = (cmsci); \
} while (0)
#define GetCMSContentInfo(obj, cmsci) do { \
    TypedData_Get_Struct((obj), CMS_ContentInfo, &ossl_cms_content_info_type, (cmsci)); \
    if (!(cmsci)) {                                                \
	ossl_raise(rb_eRuntimeError, "CMS wasn't initialized."); \
    } \
} while (0)

#define NewCMSsi(klass) \
    TypedData_Wrap_Struct((klass), &ossl_cms_signer_info_type, 0)
#define SetCMSsi(obj, cmssi) do { \
    if (!(cmssi)) { \
	ossl_raise(rb_eRuntimeError, "CMSsi wasn't initialized."); \
    } \
    RTYPEDDATA_DATA(obj) = (cmssi); \
} while (0)
#define GetCMSsi(obj, cmssi) do { \
    TypedData_Get_Struct((obj), CMS_SignerInfo, &ossl_cms_signer_info_type, (cmssi)); \
    if (!(cmssi)) { \
	ossl_raise(rb_eRuntimeError, "CMSsi wasn't initialized."); \
    } \
} while (0)


#define ossl_cmsci_set_data(o,v)       rb_iv_set((o), "@data", (v))
#define ossl_cmsci_get_data(o)         rb_iv_get((o), "@data")
#define ossl_cmsci_set_err_string(o,v) rb_iv_set((o), "@error_string", (v))
#define ossl_cmsci_get_err_string(o)   rb_iv_get((o), "@error_string")

VALUE cCMS;
VALUE cCMSContentInfo;
VALUE cCMSSignerInfo;
VALUE cCMSRecipient;
VALUE eCMSError;


static void
ossl_cms_content_info_free(void *ptr)
{
    CMS_ContentInfo_free(ptr);
}

static const rb_data_type_t ossl_cms_content_info_type = {
    "OpenSSL/CMS/ContentInfo",
    {
	0, ossl_cms_content_info_free,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};

static void
ossl_cms_signer_info_free(void *ptr)
{
  /* nothing, only internal pointers are ever returned */
}

static const rb_data_type_t ossl_cms_signer_info_type = {
    "OpenSSL/CMS/SignerInfo",
    {
	0, ossl_cms_signer_info_free,
    },
    0, 0, RUBY_TYPED_FREE_IMMEDIATELY,
};



static VALUE
ossl_cmsci_to_pem(VALUE self)
{
    CMS_ContentInfo *cmsci;
    BIO *out;
    VALUE str;

    GetCMSContentInfo(self, cmsci);
    if (!(out = BIO_new(BIO_s_mem()))) {
	ossl_raise(eCMSError, NULL);
    }
    if (!PEM_write_bio_CMS(out, cmsci)) {
	BIO_free(out);
	ossl_raise(ePKCS7Error, NULL);
    }
    str = ossl_membio2str(out);

    return str;
}

/*
 * call-seq:
 *    cmsci.to_der => binary
 */
static VALUE
ossl_cmsci_to_der(VALUE self)
{
    CMS_ContentInfo *cmsci;
    VALUE str;
    long len;
    unsigned char *p;

    GetCMSContentInfo(self, cmsci);
    if((len = i2d_CMS_ContentInfo(cmsci, NULL)) <= 0)
	ossl_raise(eCMSError, NULL);
    str = rb_str_new(0, len);
    p = (unsigned char *)RSTRING_PTR(str);
    if(i2d_CMS_ContentInfo(cmsci, &p) <= 0)
	ossl_raise(eCMSError, NULL);
    ossl_str_adjust(str, p);

    return str;
}


static VALUE
ossl_cmsci_alloc(VALUE klass)
{
    CMS_ContentInfo *cms;
    VALUE obj;

    obj = NewCMSContentInfo(klass);
    if (!(cms = CMS_ContentInfo_new())) {
	ossl_raise(eCMSError, NULL);
    }
    SetCMSContentInfo(obj, cms);

    return obj;
}

/*
 * call-seq:
 *    CMS::ContentInfo.new => cmsci
 *    CMS::ContentInfo.new(string) => cmsi
 *
 * Create a new ContentInfo object. With argument decode from PEM or DER
 * format CMS object.
 *
 */
static VALUE
ossl_cmsci_initialize(int argc, VALUE *argv, VALUE self)
{
    CMS_ContentInfo *c1, *cms = DATA_PTR(self);
    BIO *in;
    VALUE arg;

    //GetCMSContentInfo(self, cms);
    if(rb_scan_args(argc, argv, "01", &arg) == 0)
	return self;
    arg = ossl_to_der_if_possible(arg);
    in = ossl_obj2bio(&arg);
    c1 = PEM_read_bio_CMS(in, &cms, NULL, NULL);
    if (!c1) {
	OSSL_BIO_reset(in);
        c1 = d2i_CMS_bio(in, &cms);
	if (!c1) {
	    BIO_free(in);
	    CMS_ContentInfo_free(cms);
	    DATA_PTR(self) = NULL;
	    ossl_raise(rb_eArgError, "Could not parse the CMS");
	}
    }
    SetCMSContentInfo(self, cms);
    BIO_free(in);
    ossl_cmsci_set_data(self, Qnil);
    ossl_cmsci_set_err_string(self, Qnil);

    return self;
}

static VALUE
ossl_cmsci_verify(int argc, VALUE *argv, VALUE self)
{
    VALUE certs, store, indata, flags;
    STACK_OF(X509) *x509s;
    X509_STORE *x509st;
    int flg, ok, status = 0;
    BIO *in, *out;
    CMS_ContentInfo *cmsci;
    VALUE data;
    const char *msg;

    GetCMSContentInfo(self, cmsci);
    rb_scan_args(argc, argv, "22", &certs, &store, &indata, &flags);
    x509st = GetX509StorePtr(store);
    flg = NIL_P(flags) ? 0 : NUM2INT(flags);
    if(NIL_P(indata)) indata = ossl_cmsci_get_data(self);
    in = NIL_P(indata) ? NULL : ossl_obj2bio(&indata);
    if(NIL_P(certs)) x509s = NULL;
    else{
	x509s = ossl_protect_x509_ary2sk(certs, &status);
	if(status){
	    BIO_free(in);
	    rb_jump_tag(status);
	}
    }
    if(!(out = BIO_new(BIO_s_mem()))){
	BIO_free(in);
	sk_X509_pop_free(x509s, X509_free);
	ossl_raise(eCMSError, NULL);
    }
    ok = CMS_verify(cmsci, x509s, x509st, in, out, flg);
    BIO_free(in);
    sk_X509_pop_free(x509s, X509_free);
    if (ok < 0) ossl_raise(eCMSError, "CMS_verify");
    msg = ERR_reason_error_string(ERR_peek_error());
    ossl_cmsci_set_err_string(self, msg ? rb_str_new2(msg) : Qnil);
    ossl_clear_error();
    data = ossl_membio2str(out);
    ossl_cmsci_set_data(self, data);

    return (ok == 1) ? Qtrue : Qfalse;
}


static STACK_OF(X509) *
cmsci_get_certs(VALUE self)
{
    CMS_ContentInfo *cms;
    STACK_OF(X509) *certs;

    GetCMSContentInfo(self, cms);
    certs = CMS_get1_certs(cms);
    return certs;
}

static VALUE
ossl_cmsci_add_certificate(VALUE self, VALUE cert)
{
    CMS_ContentInfo *cms;
    X509 *x509;

    GetCMSContentInfo(self, cms);
    x509 = GetX509CertPtr(cert);    /* NO NEED TO DUP */
    if (!CMS_add1_cert(cms, x509)){ /* add1() takes reference */
	ossl_raise(eCMSError, NULL);
    }

    return self;
}

static VALUE
ossl_cmsci_set_certs_i(RB_BLOCK_CALL_FUNC_ARGLIST(i, arg))
{
    return ossl_cmsci_add_certificate(arg, i);
}

static VALUE
ossl_cmsci_set_certificates(VALUE self, VALUE ary)
{
    STACK_OF(X509) *certs;
    X509 *cert;

    certs = cmsci_get_certs(self);
    while((cert = sk_X509_pop(certs))) X509_free(cert);
    rb_block_call(ary, rb_intern("each"), 0, 0, ossl_cmsci_set_certs_i, self);

    return ary;
}

static VALUE
ossl_cmsci_get_certificates(VALUE self)
{
    return ossl_x509_sk2ary(cmsci_get_certs(self));
}

/*
 * CMS SignerInfo is not a first class object, but part of the
 * CMS ContentInfo.  It can be wrapped in a ruby object, but it can
 * not be created or freed directly.
 */
static VALUE
ossl_cmssi_new(CMS_SignerInfo *cmssi)
{
    VALUE obj;

    obj = NewCMSsi(cCMSSignerInfo);
    SetCMSsi(obj, cmssi);

    return obj;
}

static VALUE
ossl_cmssi_get_issuer(VALUE self)
{
    CMS_SignerInfo *cmssi;
    ASN1_OCTET_STRING *keyid;
    X509_NAME *issuer;
    ASN1_INTEGER *sno;

    GetCMSsi(self, cmssi);

    if(CMS_SignerInfo_get0_signer_id(cmssi,&keyid,&issuer, &sno)!=1) {
      ossl_raise(eCMSError, "get0_signer_id failed");
    }

    /* XXX keyid may be set instead */
    if(issuer) {
      return ossl_x509name_new(issuer);
    } else {
      return Qnil;
    }
}

static VALUE
ossl_cmssi_get_serial(VALUE self)
{
    CMS_SignerInfo *cmssi;
    ASN1_OCTET_STRING *keyid;
    X509_NAME *issuer;
    ASN1_INTEGER *sno;

    GetCMSsi(self, cmssi);

    if(CMS_SignerInfo_get0_signer_id(cmssi,&keyid,&issuer, &sno)!=1) {
      ossl_raise(eCMSError, "get0_signer_id failed");
    }

    /* XXX keyid may be set */
    if(sno) {
      return asn1integer_to_num(sno);
    } else {
      return Qnil;
    }
}

static VALUE
ossl_cmsci_get_signers(VALUE self)
{
    CMS_ContentInfo *cms;
    STACK_OF(CMS_SignerInfo) *sk;
    CMS_SignerInfo *si;
    int num, i;
    VALUE ary;

    GetCMSContentInfo(self, cms);
    if (!(sk = CMS_get0_SignerInfos(cms))) {
	OSSL_Debug("OpenSSL::CMS#get_signer_info == NULL!");
	return rb_ary_new();
    }
    if ((num = sk_CMS_SignerInfo_num(sk)) < 0) {
	ossl_raise(eCMSError, "Negative number of signers!");
    }
    ary = rb_ary_new2(num);
    for (i=0; i<num; i++) {
	si = sk_CMS_SignerInfo_value(sk, i);
	rb_ary_push(ary, ossl_cmssi_new(si));
    }

    return ary;
}

/*
 * call-seq:
 *    CMS.sign(signcert, key, data, [certs, flags]) => cms
 *
 * CMS.sign creates and returns a CMS SignedData structure.
 * The data will be signed with *key* (An OpenSSL::PKey instance), and the list of
 * certs (if any) will be included in the structure as additional
 * anchors.
 *
 * The flags come from the set of XYZ.
 *
 */
static VALUE
ossl_cms_s_sign(int argc, VALUE *argv, VALUE klass)
{
    VALUE cert, key, data, certs, flags;
    X509 *x509;
    EVP_PKEY *pkey;
    BIO *in;
    STACK_OF(X509) *x509s;
    int flg, status = 0;
    CMS_ContentInfo *cms_cinfo;
    VALUE ret;

    rb_scan_args(argc, argv, "32", &cert, &key, &data, &certs, &flags);
    x509 = GetX509CertPtr(cert); /* NO NEED TO DUP */
    pkey = GetPrivPKeyPtr(key);  /* NO NEED TO DUP */
    flg = NIL_P(flags) ? 0 : NUM2INT(flags);
    ret = NewCMSContentInfo(cCMSContentInfo);
    in  = ossl_obj2bio(&data);
    if(NIL_P(certs)) x509s = NULL;
    else{
	x509s = ossl_protect_x509_ary2sk(certs, &status);
	if(status){
	    BIO_free(in);
	    rb_jump_tag(status);
	}
    }
    if(!(cms_cinfo = CMS_sign(x509, pkey, x509s, in, flg))){
	BIO_free(in);
	sk_X509_pop_free(x509s, X509_free);
	ossl_raise(ePKCS7Error, NULL);
    }
    SetCMSContentInfo(ret, cms_cinfo);
    ossl_cmsci_set_data(ret, data);
    ossl_cmsci_set_err_string(ret, Qnil);
    BIO_free(in);
    sk_X509_pop_free(x509s, X509_free);

    return ret;
}

/*
 * INIT
 */
void
Init_ossl_cms(void)
{
    cCMS = rb_define_class_under(mOSSL, "CMS", rb_cObject);
    rb_define_singleton_method(cCMS, "sign",  ossl_cms_s_sign, -1);

    eCMSError = rb_define_class_under(cCMS, "CMSError", eOSSLError);

    cCMSContentInfo = rb_define_class_under(cCMS, "ContentInfo", rb_cObject);
    rb_define_alloc_func(cCMSContentInfo, ossl_cmsci_alloc);
    rb_define_method(cCMSContentInfo, "to_pem", ossl_cmsci_to_pem, 0);
    rb_define_alias(cCMSContentInfo,  "to_s", "to_pem");
    rb_define_method(cCMSContentInfo, "to_der", ossl_cmsci_to_der, 0);
    rb_define_method(cCMSContentInfo, "initialize", ossl_cmsci_initialize, -1);

    rb_define_method(cCMSContentInfo, "certificates=", ossl_cmsci_set_certificates, 1);
    rb_define_method(cCMSContentInfo, "certificates", ossl_cmsci_get_certificates, 0);
    rb_define_method(cCMSContentInfo, "signers", ossl_cmsci_get_signers, 0);
    rb_define_method(cCMSContentInfo, "verify", ossl_cmsci_verify, -1);
    rb_attr(cCMSContentInfo, rb_intern("data"), 1, 0, Qfalse);
    rb_attr(cCMSContentInfo, rb_intern("error_string"), 1, 1, Qfalse);
#if 0
    rb_define_method(cCMSContentInfo, "add_signer", ossl_cmsci_add_signer, 1);
#endif

    cCMSSignerInfo = rb_define_class_under(cCMS, "SignerInfo", rb_cObject);
    rb_define_method(cCMSSignerInfo,"issuer", ossl_cmssi_get_issuer, 0);
    rb_define_alias(cCMSSignerInfo, "name", "issuer");
    rb_define_method(cCMSSignerInfo,"serial", ossl_cmssi_get_serial,0);

#if 0
    rb_define_singleton_method(cCMS, "read_smime", ossl_cms_s_read_smime, 1);
    rb_define_singleton_method(cCMS, "write_smime", ossl_cms_s_write_smime, -1);
    rb_define_singleton_method(cCMS, "encrypt", ossl_cms_s_encrypt, -1);
    rb_define_method(cCMS, "initialize_copy", ossl_cms_copy, 1);
    rb_define_method(cCMS, "detached=", ossl_cms_set_detached, 1);
    rb_define_method(cCMS, "detached", ossl_cms_get_detached, 0);
    rb_define_method(cCMS, "detached?", ossl_cms_detached_p, 0);
    rb_define_method(cCMS, "cipher=", ossl_cms_set_cipher, 1);
    rb_define_method(cCMS, "add_recipient", ossl_cms_add_recipient, 1);
    rb_define_method(cCMS, "recipients", ossl_cms_get_recipient, 0);
    rb_define_method(cCMS, "add_certificate", ossl_cms_add_certificate, 1);
    rb_define_method(cCMS, "add_crl", ossl_cms_add_crl, 1);
    rb_define_method(cCMS, "crls=", ossl_cms_set_crls, 1);
    rb_define_method(cCMS, "crls", ossl_cms_get_crls, 0);
    rb_define_method(cCMS, "add_data", ossl_cms_add_data, 1);
    rb_define_alias(cCMS,  "data=", "add_data");
    rb_define_method(cCMS, "decrypt", ossl_cms_decrypt, -1);

    cCMSRecipient = rb_define_class_under(cCMS,"RecipientInfo",rb_cObject);
    rb_define_alloc_func(cCMSRecipient, ossl_cmsri_alloc);
    rb_define_method(cCMSRecipient, "initialize", ossl_cmsri_initialize,1);
    rb_define_method(cCMSRecipient, "issuer", ossl_cmsri_get_issuer,0);
    rb_define_method(cCMSRecipient, "serial", ossl_cmsri_get_serial,0);
    rb_define_method(cCMSRecipient, "enc_key", ossl_cmsri_get_enc_key,0);
#endif

#define DefCMSConst(x) rb_define_const(cCMS, #x, INT2NUM(CMS_##x))

    DefCMSConst(TEXT);
    DefCMSConst(NOCERTS);
    DefCMSConst(DETACHED);
    DefCMSConst(BINARY);
    DefCMSConst(NOATTR);
    DefCMSConst(NOSMIMECAP);
    DefCMSConst(USE_KEYID);
    DefCMSConst(STREAM);
    DefCMSConst(PARTIAL);
}

#endif /* HAVE_CMS_SIGN */
