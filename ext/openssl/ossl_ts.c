/*
 * 
 * Copyright (C) 2010 Martin Bosslet <Martin.Bosslet@googlemail.com>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */

#include <openssl/asn1.h>
#include <openssl/ossl_typ.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/x509_vfy.h>

#include "ossl.h"

#if OPENSSL_VERSION_NUMBER >= 0x10000000L

#define WrapTS_REQ(klass, obj, tsreq) do { \
    if (!tsreq) { \
	ossl_raise(rb_eRuntimeError, "TimestampRequest wasn't initialized."); \
    } \
    obj = Data_Wrap_Struct(klass, 0, TS_REQ_free, tsreq); \
} while (0)
#define GetTS_REQ(obj, tsreq) do { \
    Data_Get_Struct(obj, TS_REQ, tsreq); \
    if (!tsreq) { \
	ossl_raise(rb_eRuntimeError, "TimestampRequest wasn't initialized."); \
    } \
} while (0)
#define SafeGetTS_REQ(obj, ts_req) do { \
    OSSL_Check_Kind(obj, cTimestampRequest); \
    GetTS_REQ(obj, ts_req); \
} while (0)

#define WrapTS_RESP(klass, obj, tsresp) do { \
    if (!tsresp) { \
	ossl_raise(rb_eRuntimeError, "TimestampResponse wasn't initialized."); \
    } \
    obj = Data_Wrap_Struct(klass, 0, TS_RESP_free, tsresp); \
} while (0)
#define GetTS_RESP(obj, tsresp) do { \
    Data_Get_Struct(obj, TS_RESP, tsresp); \
    if (!tsresp) { \
	ossl_raise(rb_eRuntimeError, "TimestampResponse wasn't initialized."); \
    } \
} while (0)
#define SafeGetTS_RESP(obj, ts_resp) do { \
    OSSL_Check_Kind(obj, cTimestampResponse); \
    GetTS_RESP(obj, ts_resp); \
} while (0)

#define ossl_tsfac_get_default_policy_id(o)      rb_attr_get((o),rb_intern("@default_policy_id"))
#define ossl_tsfac_get_serial_number(o)          rb_attr_get((o),rb_intern("@serial_number"))
#define ossl_tsfac_get_gen_time(o)               rb_attr_get((o),rb_intern("@gen_time"))
#define ossl_tsfac_get_additional_certs(o)       rb_attr_get((o),rb_intern("@additional_certs"))

VALUE mTimestamp;

VALUE eTimestampError, eCertValidationError;

VALUE cTimestampRequest;
VALUE cTimestampResponse;
VALUE cTimestampFactory;

static ID sBAD_ALG, sBAD_REQUEST, sBAD_DATA_FORMAT, sTIME_NOT_AVAILABLE;
static ID sUNACCEPTED_POLICY, sUNACCEPTED_EXTENSION, sADD_INFO_NOT_AVAILABLE;
static ID sSYSTEM_FAILURE;

static VALUE
asn1_to_der(void *template, int (*i2d)(void *template, unsigned char **pp))
{
    VALUE str;
    int len;
    unsigned char *p;

    if((len = i2d(template, NULL)) <= 0) {
	ossl_raise(eTimestampError, "Error when encoding to DER");
        return Qnil;
    }
    str = rb_str_new(0, len);
    p = (unsigned char *)RSTRING_PTR(str);
    if(i2d(template, &p) <= 0) {
	ossl_raise(eTimestampError, "Error when encoding to DER");
        return Qnil;
    }
    rb_str_set_len(str, p - (unsigned char*)RSTRING_PTR(str));

    return str;
}

static ASN1_OBJECT*
obj_to_asn1obj(VALUE obj)
{
    ASN1_OBJECT *a1obj;

    StringValue(obj);
    a1obj = OBJ_txt2obj(RSTRING_PTR(obj), 0);
    if(!a1obj) a1obj = OBJ_txt2obj(RSTRING_PTR(obj), 1);
    if(!a1obj) ossl_raise(eASN1Error, "invalid OBJECT ID");

    return a1obj;
}

static ASN1_STRING*
obj_to_asn1str(VALUE obj)
{
    ASN1_STRING *str;

    StringValue(obj);
    if(!(str = ASN1_STRING_new()))
	ossl_raise(eASN1Error, NULL);
    ASN1_STRING_set(str, RSTRING_PTR(obj), RSTRING_LEN(obj));

    return str;
}

static VALUE
get_asn1obj(ASN1_OBJECT *obj)
{
    BIO *out;
    VALUE ret;
    int nid;
    if ((nid = OBJ_obj2nid(obj)) != NID_undef)
	ret = rb_str_new2(OBJ_nid2sn(nid));
    else{
	if (!(out = BIO_new(BIO_s_mem())))
	    ossl_raise(eX509AttrError, NULL);
	i2a_ASN1_OBJECT(out, obj);
	ret = ossl_membio2str(out);
    }

    return ret;
}

TS_REQ *
GetTsReqPtr(VALUE obj)
{
    TS_REQ *req;

    SafeGetTS_REQ(obj, req);

    return req;
}

static VALUE
ossl_tsreq_alloc(VALUE klass)
{
    TS_REQ *req;
    VALUE obj;

    if (!(req = TS_REQ_new())) {
        ossl_raise(eTimestampError, NULL);
        return Qnil;
    }
    req->version = ASN1_INTEGER_new();
    ASN1_INTEGER_set(req->version, 1);
    req->extensions = NULL;
    if (!(req->msg_imprint = TS_MSG_IMPRINT_new())) {
        ossl_raise(eTimestampError, NULL);
        return Qnil;
    }
    req->msg_imprint->hash_algo = NULL;
    req->msg_imprint->hashed_msg = NULL;
    req->nonce = NULL;
    req->policy_id = NULL;
    /* Intentional default */
    req->cert_req = 1;
    WrapTS_REQ(klass, obj, req);

    return obj;
}

/*
 * When creating a Request with the +File+ or +string+ parameter, the
 * corresponding +File+ or +string+ must be DER-encoded.
 *
 * call-seq:
 *       OpenSSL::Timestamp::Request.new(file)    -> request
 *       OpenSSL::Timestamp::Request.new(string)  -> request
 *       OpenSSL::Timestamp::Request.new          -> empty request
 */
static VALUE
ossl_tsreq_initialize(int argc, VALUE *argv, VALUE self)
{
    TS_REQ *ts_req = DATA_PTR(self);
    BIO *in;
    VALUE arg;

    if(rb_scan_args(argc, argv, "01", &arg) == 0) {
        return self;
    }

    arg = ossl_to_der_if_possible(arg);
    in = ossl_obj2bio(arg);
    if (!d2i_TS_REQ_bio(in, &ts_req)) {
        ossl_raise(eTimestampError,
                   "Error when decoding the timestamp request");
        return self;
    }
    DATA_PTR(self) = ts_req;

    return self;
}

/*
 * Returns the 'short name' of the object identifier that represents the
 * algorithm that was used to create the message imprint digest.
 *
 *  call-seq:
 *       request.get_algorithm    -> string or nil
 */
static VALUE
ossl_tsreq_get_algorithm(VALUE self)
{
    TS_REQ *req;
    TS_MSG_IMPRINT *mi;
    X509_ALGOR *algor;

    GetTS_REQ(self, req);
    mi = req->msg_imprint;
    if (!mi->hash_algo)
        return Qnil;
    algor = TS_MSG_IMPRINT_get_algo(mi);
    return get_asn1obj(algor->algorithm);
}

/*
 * Allows to set the object identifier  or the 'short name' of the
 * algorithm that was used to create the message imprint digest.
 *
 * ===Example:
 *      request.algorithm = "SHA1"
 *
 *  call-seq:
 *       request.algorithm = "string"    -> string
 */
static VALUE
ossl_tsreq_set_algorithm(VALUE self, VALUE algo)
{
    TS_REQ *req;
    TS_MSG_IMPRINT *mi;
    ASN1_OBJECT *obj;
    X509_ALGOR *algor;
    ASN1_TYPE *type;

    GetTS_REQ(self, req);
    obj = obj_to_asn1obj(algo);
    if (!(algor = X509_ALGOR_new())) {
        ossl_raise(rb_eRuntimeError, NULL);
        return algo;
    }
    if (!(type = ASN1_TYPE_new())) {
        ossl_raise(rb_eRuntimeError, NULL);
        return algo;
    }
    algor->algorithm = obj;
    type->type = V_ASN1_NULL;
    type->value.ptr = NULL;
    algor->parameter = type;

    mi = req->msg_imprint;
    TS_MSG_IMPRINT_set_algo(mi, algor);

    return algo;
}

/*
 * Returns the message imprint (digest) of the data to be timestamped.
 *
 * call-seq:
 *       request.message_imprint    -> string or nil
 */
static VALUE
ossl_tsreq_get_msg_imprint(VALUE self)
{
    TS_REQ *req;
    TS_MSG_IMPRINT *mi;
    ASN1_OCTET_STRING *hashed_msg;
    VALUE ret;

    GetTS_REQ(self, req);
    mi = req->msg_imprint;
    if (!req->msg_imprint->hashed_msg)
        return Qnil;
    hashed_msg = TS_MSG_IMPRINT_get_msg(mi);

    ret = rb_str_new((const char *)hashed_msg->data, hashed_msg->length);

    return ret;
}

/*
 * Set the message imprint digest.
 *
 *  call-seq:
 *       request.message_imprint = "string"    -> string
 */
static VALUE
ossl_tsreq_set_msg_imprint(VALUE self, VALUE hash)
{
    TS_REQ *req;
    TS_MSG_IMPRINT *mi;
    StringValue(hash);

    GetTS_REQ(self, req);
    mi = req->msg_imprint;
    if (mi->hashed_msg)
        ASN1_OCTET_STRING_free(mi->hashed_msg);
    if (!(mi->hashed_msg = ASN1_OCTET_STRING_new())) {
        ossl_raise(eTimestampError, NULL);
        return self;
    }
    TS_MSG_IMPRINT_set_msg(mi, RSTRING_PTR(hash), RSTRING_LEN(hash));

    return hash;
}

/*
 * Returns the version of this request. +1+ is the default value.
 *
 * call-seq:
 *       request.version -> Fixnum
 */
static VALUE
ossl_tsreq_get_version(VALUE self)
{
    TS_REQ *req;

    GetTS_REQ(self, req);
    return asn1integer_to_num(req->version);
}

/*
 * Sets the version number for this Request. This should be +1+ for compliant
 * servers.
 *
 * call-seq:
 *       request.algorithm = number    -> Fixnum
 */
static VALUE
ossl_tsreq_set_version(VALUE self, VALUE num)
{
    TS_REQ *req;

    GetTS_REQ(self, req);
    if (req->version) {
        ASN1_INTEGER_free(req->version);
    }

    req->version = num_to_asn1integer(num, NULL);
    return num;
}

/*
 * Returns the 'short name' of the object identifier that represents the
 * timestamp policy under which the server shall create the timestamp.
 *
 * call-seq:
 *       request.policy_id    -> string or nil
 */
static VALUE
ossl_tsreq_get_policy_id(VALUE self)
{
    TS_REQ *req;

    GetTS_REQ(self, req);
    if (!req->policy_id)
        return Qnil;
    return get_asn1obj(req->policy_id);
}

/*
 * Allows to set the object identifier that represents the
 * timestamp policy under which the server shall create the timestamp. This
 * may be left +nil+, implying that the timestamp server will issue the
 * timestamp using some default policy.
 *
 * ===Example:
 *      request.policy_id = "1.2.3.4.5"
 *
 * call-seq:
 *       request.policy_id = "string"   -> string
 */
static VALUE
ossl_tsreq_set_policy_id(VALUE self, VALUE oid)
{
    TS_REQ *req;
    ASN1_OBJECT *obj;

    GetTS_REQ(self, req);
    if (req->policy_id)
        ASN1_OBJECT_free(req->policy_id);
    obj = obj_to_asn1obj(oid);
    req->policy_id = obj;
}

/*
 * Returns the nonce (number used once) that the server shall include in its
 * response.
 *
 * call-seq:
 *       request.nonce    -> Fixnum or nil
 */
static VALUE
ossl_tsreq_get_nonce(VALUE self)
{
    TS_REQ *req;

    GetTS_REQ(self, req);
    if (!req->nonce)
        return Qnil;
    return asn1integer_to_num(req->nonce);
}

/*
 * Sets the nonce (number used once) that the server shall include in its
 * response. This can be +nil+, implying that the server shall not return
 * a nonce in the Response. If the nonce is set, the server must return the
 * same nonce value in a valid Response.
 *
 * call-seq:
 *       request.nonce = number    -> Fixnum
 */
static VALUE
ossl_tsreq_set_nonce(VALUE self, VALUE num)
{
    TS_REQ *req;

    GetTS_REQ(self, req);
    if (req->nonce) {
        ASN1_INTEGER_free(req->nonce);
        req->nonce = NULL;
    }
    if (num == Qnil) {
        req->nonce = NULL;
        return Qnil;
    }
    TS_REQ_set_nonce(req, num_to_asn1integer(num, req->nonce));
    return num;
}

/*
 * Indicates whether the response shall contain the timestamp authority's
 * certificate or not.
 *
 * call-seq:
 *       request.cert_requested?  -> true or false
 */
static VALUE
ossl_tsreq_get_cert_requested(VALUE self)
{
    TS_REQ *req;

    GetTS_REQ(self, req);
    return req->cert_req == 0 ? Qfalse : Qtrue;
}

/*
 * Specify whether the response shall contain the timestamp authority's
 * certificate or not. The default value is +true+.
 *
 * call-seq:
 *       request.cert_requested = boolean -> true or false
 */
static VALUE
ossl_tsreq_set_cert_requested(VALUE self, VALUE requested)
{
    TS_REQ *req;

    GetTS_REQ(self, req);
    req->cert_req = (RTEST(requested) ? 0xff : 0x0);

    return requested;
}

/*
 * DER-encodes this Request.
 *
 * call-seq:
 *       request.to_der    -> DER-encoded string
 */
static VALUE
ossl_tsreq_to_der(VALUE self)
{
    TS_REQ *req;

    GetTS_REQ(self, req);
    if (!(req->msg_imprint->hash_algo && req->msg_imprint->hashed_msg)) {
        ossl_raise(eTimestampError, "Invalid message imprint. One or both "
                                    "of the values is nil");
    }
    return asn1_to_der((void *)req, (int (*)(void *, unsigned char **))i2d_TS_REQ);
}

TS_RESP *
GetTsRespPtr(VALUE obj)
{
    TS_RESP *resp;

    SafeGetTS_RESP(obj, resp);

    return resp;
}

static VALUE
ossl_tsresp_alloc(VALUE klass)
{
    TS_RESP *resp;
    VALUE obj;

    resp = TS_RESP_new();
    if (!resp) ossl_raise(eTimestampError, NULL);

    WrapTS_RESP(klass, obj, resp);

    return obj;
}

/*
 * Creates a Response from a +File+ or +string+ parameter, the
 * corresponding +File+ or +string+ must be DER-encoded. Please note
 * that Response is an immutable read-only class. If you'd like to create
 * timestamps please refer to Factory instead.
 *
 * call-seq:
 *       OpenSSL::Timestamp::Response.new(file)    -> response
 *       OpenSSL::Timestamp::Response.new(string)  -> response
 */
static VALUE
ossl_ts_initialize(VALUE self, VALUE der) {
    TS_RESP *ts_resp = DATA_PTR(self);
    BIO *in;

    der = ossl_to_der_if_possible(der);
    in  = ossl_obj2bio(der);
    if (!d2i_TS_RESP_bio(in, &ts_resp)) {
        ossl_raise(eTimestampError,
                   "Error when decoding the timestamp response");
        return self;
    }
    DATA_PTR(self) = ts_resp;

    return self;
}

/*
 * Returns one of GRANTED, GRANTED_WITH_MODS, REJECTION, WAITING,
 * REVOCATION_WARNING or REVOCATION_NOTIFICATION. A timestamp token has
 * been created only in case +status+ is equal to GRANTED or GRANTED_WITH_MODS.
 *
 * call-seq:
 *       response.status -> Fixnum (never nil)
 */
static VALUE
ossl_ts_get_status(VALUE self)
{
    TS_RESP *resp;

    GetTS_RESP(self, resp);
    return asn1integer_to_num(resp->status_info->status);
}

/*
 * In cases no timestamp token has been created, this field contains further
 * info about the reason why response creation failed. The method returns either
 * nil (the request was successful and a timestamp token was created) or one of
 * the following:
 * * :BAD_ALG - Indicates that the timestamp server rejects the message
 *   imprint algorithm used in the Request
 * * :BAD_REQUEST - Indicates that the timestamp server was not able to process
 *   the Request properly
 * * :BAD_DATA_FORMAT - Indicates that the timestamp server was not able to
 *   parse certain data in the Request
 * * :TIME_NOT_AVAILABLE - Indicates that the server could not access its time
 *   source
 * * :UNACCEPTED_POLICY - Indicates that the requested policy identifier is not
 *   recognized or supported by the timestamp server
 * * :UNACCEPTED_EXTENSIION - Indicates that an extension in the Request is
 *   not supported by the timestamp server
 * * :ADD_INFO_NOT_AVAILABLE -Indicates that additional information requested
 *   is either not understood or currently not available
 * * :SYSTEM_FAILURE - Timestamp creation failed due to an internal error that
 *   occurred on the timestamp server
 *
 * call-seq:
 *       response.failure_info -> nil or symbol
 */
static VALUE
ossl_ts_get_failure_info(VALUE self)
{
    TS_RESP *resp;
    ASN1_BIT_STRING *fi;

    GetTS_RESP(self, resp);
    fi = resp->status_info->failure_info;
    if (!fi)
        return Qnil;
    if (ASN1_BIT_STRING_get_bit(fi, TS_INFO_BAD_ALG))
        return sBAD_ALG;
    if (ASN1_BIT_STRING_get_bit(fi, TS_INFO_BAD_REQUEST))
        return sBAD_REQUEST;
    if (ASN1_BIT_STRING_get_bit(fi, TS_INFO_BAD_DATA_FORMAT))
        return sBAD_DATA_FORMAT;
    if (ASN1_BIT_STRING_get_bit(fi, TS_INFO_TIME_NOT_AVAILABLE))
        return sTIME_NOT_AVAILABLE;
    if (ASN1_BIT_STRING_get_bit(fi, TS_INFO_UNACCEPTED_POLICY))
        return sUNACCEPTED_POLICY;
    if (ASN1_BIT_STRING_get_bit(fi, TS_INFO_UNACCEPTED_EXTENSION))
        return sUNACCEPTED_EXTENSION;
    if (ASN1_BIT_STRING_get_bit(fi, TS_INFO_ADD_INFO_NOT_AVAILABLE))
        return sADD_INFO_NOT_AVAILABLE;
    if (ASN1_BIT_STRING_get_bit(fi, TS_INFO_SYSTEM_FAILURE))
        return sSYSTEM_FAILURE;

    ossl_raise(eTimestampError, "Unrecognized failure info.");
    return Qnil;
}

/*
 * In cases of failure this field may contain an array of strings further
 * describing the origin of the failure.
 *
 * call-seq:
 *       response.status_text -> Array of strings or nil
 */
static VALUE
ossl_ts_get_status_text(VALUE self)
{
    TS_RESP *resp;
    STACK_OF(ASN1_UTF8STRING) *text;
    ASN1_UTF8STRING *current;
    VALUE ret;
    int i;

    GetTS_RESP(self, resp);
    text = resp->status_info->text;
    if (!text)
        return Qnil;
    ret = rb_ary_new();
    for (i = 0; i < sk_ASN1_UTF8STRING_num(text); i++) {
        current = sk_ASN1_UTF8STRING_value(text, i);
        rb_ary_push(ret, asn1str_to_str(current));
    }

    return ret;
}

/*
 * If a timestamp token is present, this returns it in the form of a
 * OpenSSL::PKCS7.
 *
 * call-seq:
 *       response.pkcs7 -> nil or OpenSSL::PKCS7
 */
static VALUE
ossl_ts_get_pkcs7(VALUE self)
{
    TS_RESP *resp;
    PKCS7 *p7;
    unsigned char *p;
    int len;

    GetTS_RESP(self, resp);
    p7 = resp->token;
    if (!p7)
        return Qnil;

    return Data_Wrap_Struct(cPKCS7, 0, PKCS7_free, PKCS7_dup(p7));
}

/*
 * Returns the version number of the timestamp token. With compliant servers,
 * this value should be +1+ if present. If status is GRANTED or
 * GRANTED_WITH_MODS, this is never +nil+.
 *
 * call-seq:
 *       response.version -> Fixnum or nil
 */
static VALUE
ossl_ts_get_version(VALUE self)
{
    TS_RESP *resp;
    TS_TST_INFO *tst;

    GetTS_RESP(self, resp);
    tst = resp->tst_info;
    if (!tst)
        return Qnil;
    return asn1integer_to_num(tst->version);
}

/*
 * Returns the timestamp policy object identifier of the policy this timestamp
 * was created under. If status is GRANTED or GRANTED_WITH_MODS, this is never
 * +nil+.
 *
 * ===Example:
 *      id = response.policy_id
 *      puts id                 -> "1.2.3.4.5"
 *
 * call-seq:
 *       response.policy_id -> string or nil
 */
static VALUE
ossl_ts_get_policy_id(VALUE self)
{
    TS_RESP *resp;
    TS_TST_INFO *tst;

    GetTS_RESP(self, resp);
    tst = resp->tst_info;
    if (!tst)
        return Qnil;
    return get_asn1obj(tst->policy_id);
}

/*
 * Returns the 'short name' of the object identifier representing the algorithm
 * that was used to derive the message imprint digest. For valid timestamps,
 * this is the same value that was already given in the Request. If status is
 * GRANTED or GRANTED_WITH_MODS, this is never +nil+.
 *
 * ===Example:
 *      algo = request.algorithm
 *      puts algo                -> "SHA1"
 *
 * call-seq:
 *       response.algorithm -> string or nil
 */
static VALUE
ossl_ts_get_algorithm(VALUE self)
{
    TS_RESP *resp;
    TS_TST_INFO *tst;
    TS_MSG_IMPRINT *mi;
    X509_ALGOR *algo;

    GetTS_RESP(self, resp);
    tst = resp->tst_info;
    if (!tst)
        return Qnil;
    mi = tst->msg_imprint;
    algo = TS_MSG_IMPRINT_get_algo(mi);
    return get_asn1obj(algo->algorithm);
}

/*
 * Returns the message imprint digest. For valid timestamps,
 * this is the same value that was already given in the Request.
 * If status is GRANTED or GRANTED_WITH_MODS, this is never +nil+.
 *
 * ===Example:
 *      algo = request.algorithm
 *      puts algo                -> "SHA1"
 *
 * call-seq:
 *       response.algorithm -> string or nil
 */
static VALUE
ossl_ts_get_msg_imprint(VALUE self)
{
    TS_RESP *resp;
    TS_TST_INFO *tst;
    TS_MSG_IMPRINT *mi;
    ASN1_OCTET_STRING *hashed_msg;
    VALUE ret;

    GetTS_RESP(self, resp);
    tst = resp->tst_info;
    if (!tst)
        return Qnil;
    mi = tst->msg_imprint;
    hashed_msg = TS_MSG_IMPRINT_get_msg(mi);
    ret = rb_str_new((const char *)hashed_msg->data, hashed_msg->length);

    return ret;
}

/*
 * Returns serial number of the timestamp token. This value shall never be the
 * same for two timestamp tokens issued by a dedicated timestamp authority.
 * If status is GRANTED or GRANTED_WITH_MODS, this is never +nil+.
 *
 * call-seq:
 *       response.serial_number -> number or nil
 */
static VALUE
ossl_ts_get_serial_number(VALUE self)
{
    TS_RESP *resp;
    TS_TST_INFO *tst;

    GetTS_RESP(self, resp);
    tst = resp->tst_info;
    if (!tst)
        return Qnil;
    return asn1integer_to_num(tst->serial);
}

/*
 * Returns time when this timestamp token was created. If status is GRANTED or
 * GRANTED_WITH_MODS, this is never +nil+.
 *
 * call-seq:
 *       response.gen_time -> Time
 */
static VALUE
ossl_ts_get_gen_time(VALUE self)
{
    TS_RESP *resp;
    TS_TST_INFO *tst;

    GetTS_RESP(self, resp);
    tst = resp->tst_info;
    if (!tst)
        return Qnil;
    return asn1time_to_time(tst->time);
}

/*
 * If the ordering field is missing, or if the ordering field is present
 * and set to false, then the genTime field only indicates the time at
 * which the time-stamp token has been created by the TSA.  In such a
 * case, the ordering of time-stamp tokens issued by the same TSA or
 * different TSAs is only possible when the difference between the
 * genTime of the first time-stamp token and the genTime of the second
 * time-stamp token is greater than the sum of the accuracies of the
 * genTime for each time-stamp token.
 *
 * If the ordering field is present and set to true, every time-stamp
 * token from the same TSA can always be ordered based on the genTime
 * field, regardless of the genTime accuracy.
 *
 * call-seq:
 *       response.ordering -> true, falses or nil
 */
static VALUE
ossl_ts_get_ordering(VALUE self)
{
    TS_RESP *resp;
    TS_TST_INFO *tst;

    GetTS_RESP(self, resp);
    tst = resp->tst_info;
    if (!tst)
        return Qnil;
    return tst->ordering == 0 ? Qfalse : Qtrue;
}

/*
 * If the timestamp token is valid then this field contains the same nonce that
 * was passed to the timestamp server in the initial Request.
 *
 * call-seq:
 *       response.nonce -> number or nil
 */
static VALUE
ossl_ts_get_nonce(VALUE self)
{
    TS_RESP *resp;
    TS_TST_INFO *tst;

    GetTS_RESP(self, resp);
    tst = resp->tst_info;
    if (!tst || !tst->nonce)
        return Qnil;

    return asn1integer_to_num(tst->nonce);
}

/*
 * If the Request specified to request the TSA certificate
 * (Request#cert_requested = true), then this field contains the
 * certificate of the timestamp authority.
 *
 * call-seq:
 *       response.tsa_certificate -> OpenSSL::X509::Certificate or nil
 */
static VALUE
ossl_ts_get_tsa_certificate(VALUE self)
{
    TS_RESP *resp;
    PKCS7 *p7;
    PKCS7_SIGNER_INFO *ts_info;
    X509 *cert;
    
    GetTS_RESP(self, resp);
    p7 = resp->token;
    if (!p7)
        return Qnil;
    ts_info = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
    cert = PKCS7_cert_from_signer_info(p7, ts_info);
    if (!cert)
        return Qnil;
    return ossl_x509_new(cert);
}

/*
 * Returns the Response in DER-encoded form.
 *
 * call-seq:
 *       response.to_der -> string
 */
static VALUE
ossl_ts_to_der(VALUE self)
{
    TS_RESP *resp;

    GetTS_RESP(self, resp);
    return asn1_to_der((void *)resp, (int (*)(void *, unsigned char **))i2d_TS_RESP);
}

static void
int_ossl_handle_verify_errors()
{
    const char *msg = NULL;
    int is_validation_err = 0;
    unsigned long e;
    VALUE err;
    VALUE err_class;

    e = ERR_get_error_line_data(NULL, NULL, &msg, NULL);
    if (ERR_GET_LIB(e) == ERR_LIB_TS) {
        if (ERR_GET_REASON(e) == TS_R_CERTIFICATE_VERIFY_ERROR)
            is_validation_err = 1;
    }

    if (is_validation_err)
        err_class = eCertValidationError;
    else
        err_class = eTimestampError;

    if (!msg || strcmp("", msg) == 0)
        msg = ERR_reason_error_string(e);
    if (!msg || strcmp("", msg) == 0)
        msg = "Invalid timestamp token.";

    err = rb_exc_new(err_class, msg, strlen(msg));
    rb_exc_raise(err);
    ERR_clear_error();
}

static void int_ossl_init_roots(VALUE roots, X509_STORE * store)
{
    STACK_OF(X509_INFO) *inf;
    X509_INFO *itmp;
    BIO *in;
    int i, count = 0;

    if (roots == Qnil) {
        ossl_raise(rb_eTypeError, "roots must not be nil.");
        return;
    }
    else if (rb_obj_is_kind_of(roots, rb_cArray)) {
        for (i=0; i < RARRAY_LEN(roots); i++) {
            VALUE cert = rb_ary_entry(roots, i);
            X509_STORE_add_cert(store, GetX509CertPtr(cert));
        }
    }
    else if (rb_obj_is_kind_of(roots, cX509Cert)) {
        X509_STORE_add_cert(store, GetX509CertPtr(roots));
    }
    else {
        in = ossl_obj2bio(roots);
        inf = PEM_X509_INFO_read_bio(in, NULL, NULL, NULL);
	BIO_free(in);
	if(!inf) {
            ossl_raise(eTimestampError, "Could not parse root certificates.");
            return;
        }
        for (i = 0; i < sk_X509_INFO_num(inf); i++) {
            itmp = sk_X509_INFO_value(inf, i);
            if (itmp->x509) {
                X509_STORE_add_cert(store, itmp->x509);
                count++;
            }
            /* ignore CRLs deliberately */
        }
        sk_X509_INFO_pop_free(inf, X509_INFO_free);
    }
}

void
int_ossl_verify_ctx_set_certs(TS_VERIFY_CTX *ctx, STACK_OF(X509) * certs)
{
    int i;

    if (ctx->certs) {
        sk_X509_pop_free(ctx->certs, X509_free);
        ctx->certs = NULL;
    }
    if (!certs)
        return;
    if (!(ctx->certs = sk_X509_dup(certs))) {
        ossl_raise(eTimestampError, NULL);
    }
    for (i = 0; i < sk_X509_num(ctx->certs); ++i) {
        X509 *cert = sk_X509_value(ctx->certs, i);
        CRYPTO_add(&cert->references, +1, CRYPTO_LOCK_X509);
    }
}

/*
 * Verifies a timestamp token by checking the signature, validating the
 * certificate chain implied by tsa_certificate and by checking conformance to
 * a given Request. Mandatory parameters are the Request associated to this
 * Response, and one or more root certificates (self-signed). The root
 * certificates can be passed in various forms:
 * * a single OpenSSL::X509::Certificate
 * * an Array of OpenSSL::X509::Certificate
 * * a File instance containing a list of PEM-encoded certificates
 * * a +string+ containing a list of PEM-encoded certificates
 *
 * Furthermore, intermediate certificates can optionally be supplied for
 * creating the certificate chain. These intermediate certificates must all be
 * instances of OpenSSL::X509::Certificate.
 *
 * If validation fails, several kinds of exceptions can be raised:
 * * TypeError if types don't fit
 * * TimestampError if something is wrong with the timestamp token itself or if
 *   it is not conformant to the Request
 * * CertificateValidationError if validation of the timestamp certificate chain
 *   fails.
 *
 * call-seq:
 *       response.verify(Request, root_certificate) -> Response
 *       response.verify(Request, root_certificate, intermediate_cert1, intermediate_cert2, ...) -> Response
 *       response.verify(Request, [ root_certificate1, root_certificate2 ])                      -> Response
 *       response.verify(Request, [ root_cert1, root_cert2 ]. intermediate1, intermediate2, ...) -> Response
 *       response.verify(Request, File)                                                          -> Response
 *       response.verify(Request, File, intermediate1, intermediate2, ...)                       -> Response
 *       response.verify(Request, string)                                                        -> Response
 *       response.verify(Request, string, intermediate1, intermediate2, ...)                     -> Response
 */
static VALUE
ossl_ts_verify(int argc, VALUE *argv, VALUE self)
{
    VALUE ret = Qnil;
    VALUE untrusted = Qnil;
    VALUE ts_cert;
    VALUE roots;
    VALUE ts_req;
    TS_RESP *resp;
    TS_VERIFY_CTX *ctx;
    TS_REQ *req;
    STACK_OF(X509) *certs;
    VALUE cert;
    int i;

    rb_scan_args(argc, argv, "2*", &ts_req, &roots, &untrusted);

    GetTS_RESP(self, resp);
    req = GetTsReqPtr(ts_req);
    if (!(ctx = TS_REQ_to_TS_VERIFY_CTX(req, NULL))) {
        ossl_raise(eTimestampError, "Error when creating the verification context.");
        return Qnil;
    }

    if (!(ctx->store = X509_STORE_new())) {
        ossl_raise(eTimestampError, NULL);
        goto end;
    }

    int_ossl_init_roots(roots, ctx->store);

    ts_cert = ossl_ts_get_tsa_certificate(self);
    if (ts_cert != Qnil || untrusted != Qnil) {
        if (!(certs = sk_X509_new_null())) {
            ossl_raise(eTimestampError, NULL);
            goto end;
        }
        if (ts_cert != Qnil) {
            for (i=0; i < sk_X509_num(resp->token->d.sign->cert); i++) {
                sk_X509_push(certs, sk_X509_value(resp->token->d.sign->cert, i));
            }
        }
        if (untrusted != Qnil) {
            if (rb_obj_is_kind_of(untrusted, rb_cArray)) {
                for (i=0; i < RARRAY_LEN(untrusted); i++) {
                    cert = rb_ary_entry(untrusted, i);
                    sk_X509_push(certs, GetX509CertPtr(cert));
                }
            }
            else {
                sk_X509_push(certs, GetX509CertPtr(untrusted));
            }
        }
    }

    int_ossl_verify_ctx_set_certs(ctx, certs);
    ctx->flags |= TS_VFY_SIGNATURE;

    if (!TS_RESP_verify_response(ctx, resp)) {
        int_ossl_handle_verify_errors();
        goto end;
    }

    ret = self;

end:
    TS_VERIFY_CTX_free(ctx);
    return ret;
}

/*
 * Creates a Factory.
 *
 * call-seq:
 *       OpenSSL::Timestamp::Factory.new    -> Factory
 */
static VALUE
ossl_tsfac_initialize(VALUE self)
{
    return self;
}

static ASN1_INTEGER *
ossl_tsfac_serial_cb(struct TS_resp_ctx *ctx, void *data) {
    VALUE serial = *((VALUE *)data);
    ASN1_INTEGER *num;
    if (!(num = ASN1_INTEGER_new())) {
        TSerr(TS_F_DEF_SERIAL_CB, ERR_R_MALLOC_FAILURE);
        TS_RESP_CTX_set_status_info(ctx, TS_STATUS_REJECTION,
            "Error during serial number generation.");
        return NULL;
    }
    return num_to_asn1integer(serial, num);
}

static int
ossl_tsfac_time_cb(struct TS_resp_ctx *ctx, void *data, long *sec, long *usec)
{
    VALUE time = *((VALUE *)data);
    time_t secs = time_to_time_t(time);
    *sec = (long) secs;
    *usec = 0;
    return 1;
}

/*
 * Creates a Response with the help of an OpenSSL::PKey, an
 * OpenSSL::X509::Certificate and a Request.
 *
 * The Request message imprint may have only been created using one of the
 * following algorithms:
 * * MD5
 * * SHA1
 * * SHA224
 * * SHA256
 * * SHA384
 * * SHA512
 * Otherwise creation of the timestamp token will fail and a TimestampError
 * will be raised.
 *
 * Mandatory parameters for timestamp creation that need to be set in the
 * Request:
 *
 * * Request#algorithm
 * * Request#message_imprint
 *
 * Mandatory parameters that need to be set in the Factory:
 * * Factory#serial_number
 * * Factory#gen_time
 *
 * In addition one of either Request#policy_id or Factory#default_policy_id
 * must be set.
 * 
 * Raises a TimestampError if creation fails.
 *
 * call-seq:
 *       factory.create_timestamp(key, certificate, request) -> Response
 */
static VALUE
ossl_tsfac_create_ts(VALUE self, VALUE key, VALUE certificate, VALUE request)
{
    VALUE serial_number, def_policy_id, gen_time, additional_certs;
    VALUE str, cert;
    STACK_OF(X509) *inter_certs;
    VALUE ret;
    EVP_PKEY *sign_key;
    X509 *tsa_cert;
    TS_REQ *req;
    TS_RESP *response = NULL;
    TS_RESP_CTX *ctx = NULL;
    BIO *req_bio;
    const char * err_msg = NULL;
    int i;

    tsa_cert = GetX509CertPtr(certificate);
    sign_key = GetPrivPKeyPtr(key);
    req = GetTsReqPtr(request);

    if (!(ctx = TS_RESP_CTX_new())) {
        err_msg = "Memory allocation failed.";
        goto end;
    }
    serial_number = ossl_tsfac_get_serial_number(self);
    if (serial_number == Qnil) {
        err_msg = "@serial_number must be set.";
        goto end;
    }
    gen_time = ossl_tsfac_get_gen_time(self);
    if (gen_time == Qnil) {
        err_msg = "@gen_time must be set.";
        goto end;
    }
    def_policy_id = ossl_tsfac_get_default_policy_id(self);
    if (def_policy_id == Qnil && !req->policy_id) {
        err_msg = "No policy id in the request and no default policy set";
        goto end;
    }

    TS_RESP_CTX_set_serial_cb(ctx, ossl_tsfac_serial_cb, &serial_number);
    TS_RESP_CTX_set_signer_cert(ctx, tsa_cert);
    if (!ctx->signer_cert) {
        err_msg = "Certificate does not contain the timestamping extension";
        goto end;
    }

    additional_certs = ossl_tsfac_get_additional_certs(self);
    if (additional_certs != Qnil) {
        if (!(inter_certs = sk_X509_new_null())) goto end;
        if (tsa_cert)
        if (rb_obj_is_kind_of(additional_certs, rb_cArray)) {
            for (i = 0; i < RARRAY_LEN(additional_certs); i++) {
                cert = rb_ary_entry(additional_certs, i);
                sk_X509_push(inter_certs, GetX509CertPtr(cert));
            }
        }
        else {
            sk_X509_push(inter_certs, GetX509CertPtr(additional_certs));
        }
        TS_RESP_CTX_set_certs(ctx, inter_certs);
    }

    TS_RESP_CTX_set_signer_key(ctx, sign_key);
    if (def_policy_id != Qnil && !req->policy_id)
        TS_RESP_CTX_set_def_policy(ctx, obj_to_asn1obj(def_policy_id));
    if (req->policy_id)
        TS_RESP_CTX_set_def_policy(ctx, req->policy_id);
    TS_RESP_CTX_set_time_cb(ctx, ossl_tsfac_time_cb, &gen_time);

    TS_RESP_CTX_add_md(ctx, EVP_get_digestbyname(OBJ_nid2sn(NID_md5)));
    TS_RESP_CTX_add_md(ctx, EVP_get_digestbyname(OBJ_nid2sn(NID_sha1)));
    TS_RESP_CTX_add_md(ctx, EVP_get_digestbyname(OBJ_nid2sn(NID_sha224)));
    TS_RESP_CTX_add_md(ctx, EVP_get_digestbyname(OBJ_nid2sn(NID_sha256)));
    TS_RESP_CTX_add_md(ctx, EVP_get_digestbyname(OBJ_nid2sn(NID_sha384)));
    TS_RESP_CTX_add_md(ctx, EVP_get_digestbyname(OBJ_nid2sn(NID_sha512)));

    str = rb_funcall(request, rb_intern("to_der"), 0);
    req_bio = ossl_obj2bio(str);
    response = TS_RESP_create_response(ctx, req_bio);
    if (!response) {
        err_msg = "Error during response generation";
        goto end;
    }

    WrapTS_RESP(cTimestampResponse, ret, response);

end:
    if (ctx) TS_RESP_CTX_free(ctx);
    if (err_msg) {
        if (response) TS_RESP_free(response);
        ossl_raise(eTimestampError, err_msg);
        return Qnil;
    }
    return ret;
}

/*
 * INIT
 */
void
Init_ossl_ts()
{
    #if 0
    mOSSL = rb_define_module("OpenSSL"); /* let rdoc know about mOSSL */
    #endif

    /*
     * Possible return value for +Response#failure_info+. Indicates that the
     * timestamp server rejects the message imprint algorithm used in the
     * +Request+
     */
    sBAD_ALG = rb_intern("BAD_ALG");

    /*
     * Possible return value for +Response#failure_info+. Indicates that the
     * timestamp server was not able to process the +Request+ properly.
     */
    sBAD_REQUEST = rb_intern("BAD_REQUEST");
    /*
     * Possible return value for +Response#failure_info+. Indicates that the
     * timestamp server was not able to parse certain data in the +Request+.
     */
    sBAD_DATA_FORMAT = rb_intern("BAD_DATA_FORMAT");

    sTIME_NOT_AVAILABLE = rb_intern("TIME_NOT_AVAILABLE");
    sUNACCEPTED_POLICY = rb_intern("UNACCEPTED_POLICY");
    sUNACCEPTED_EXTENSION = rb_intern("UNACCEPTED_EXTENSION");
    sADD_INFO_NOT_AVAILABLE = rb_intern("ADD_INFO_NOT_AVAILABLE");
    sSYSTEM_FAILURE = rb_intern("SYSTEM_FAILURE");

    /* Document-class: OpenSSL::Timestamp
     * Provides classes and methods to request, create and validate
     * {RFC3161-compliant}[http://www.ietf.org/rfc/rfc3161.txt] timestamps.
     * Request may be used to either create requests from scratch or to parse
     * existing requests that again can be used to request timestamps from a
     * timestamp server, e.g. via the net/http. The resulting timestamp
     * response may be parsed using Response.
     *
     * Please note that Response is read-only and immutable. To create a
     * Response, an instance of Factory as well as a valid Request are needed.
     *
     * ===Create a Response:
     *      #Assumes ts.p12 is a PKCS#12-compatible file with a private key
     *      #and a certificate that has an extended key usage of 'timeStamping'
     *      p12 = OpenSSL::PKCS12.new(File.open('ts.p12', 'rb'), 'pwd')
     *      md = OpenSSL::Digest::SHA1.new
     *      hash = md.digest(data) #some binary data to be timestamped
     *      req = OpenSSL::Timestamp::Request.new
     *      req.algorithm = 'SHA1'
     *      req.message_imprint = hash
     *      req.policy_id = "1.2.3.4.5"
     *      req.nonce = 42
     *      fac = OpenSSL::Timestamp::Factory.new
     *      fac.gen_time = Time.now
     *      fac.serial_number = 1
     *      timestamp = fac.create_timestamp(p12.key, p12.certificate, req)
     *
     * ===Verify a timestamp response:
     *      #Assume we have a timestamp token in a file called ts.der
     *      ts = OpenSSL::Timestamp::Response.new(File.open('ts.der', 'rb')
     *      #Assume we have the Request for this token in a file called req.der
     *      req = OpenSSL::Timestamp::Request.new(File.open('req.der', 'rb')
     *      # Assume the associated root CA certificate is contained in a
     *      # DER-encoded file named root.cer
     *      root = OpenSSL::X509::Certificate.new(File.open('root.cer', 'rb')
     *      # get the necessary intermediate certificates, available in
     *      # DER-encoded form in inter1.cer and inter2.cer
     *      inter1 = OpenSSL::X509::Certificate.new(File.open('inter1.cer', 'rb')
     *      inter2 = OpenSSL::X509::Certificate.new(File.open('inter2.cer', 'rb')
     *      ts.verify(req, root, inter1, inter2) -> ts or raises an exception if validation fails
     *
     */
    mTimestamp = rb_define_module_under(mOSSL, "Timestamp");

    /* Document-class: OpenSSL::Timestamp::TimestampError
     * Generic exception class of the Timestamp module.
     */
    eTimestampError = rb_define_class_under(mTimestamp, "TimestampError", eOSSLError);

    /* Document-class: OpenSSL::Timestamp::CertificateValidationError
     * Raised only in Response#verify, in cases when the timestamp validation
     * failed due to an error during the validation of the certificate chain
     * used for creating the timestamp. This exception can be used to
     * distinguish these cases from those where problems are related the
     * timestamp itself.
     */
    eCertValidationError = rb_define_class_under(mTimestamp, "CertificateValidationError", eOSSLError);

    /* Document-class: OpenSSL::Timestamp::Response
     * Immutable and read-only representation of a timestamp response returned
     * from a timestamp server after receiving an associated Request. Allows
     * access to specific information about the response but also allows to
     * verify the Response.
     */
    cTimestampResponse = rb_define_class_under(mTimestamp, "Response", rb_cObject);
    rb_define_alloc_func(cTimestampResponse, ossl_tsresp_alloc);
    rb_define_method(cTimestampResponse, "initialize", ossl_ts_initialize, 1);
    rb_define_method(cTimestampResponse, "status", ossl_ts_get_status, 0);
    rb_define_method(cTimestampResponse, "failure_info", ossl_ts_get_failure_info, 0);
    rb_define_method(cTimestampResponse, "status_text", ossl_ts_get_status_text, 0);
    rb_define_method(cTimestampResponse, "pkcs7", ossl_ts_get_pkcs7, 0);
    rb_define_method(cTimestampResponse, "tsa_certificate", ossl_ts_get_tsa_certificate, 0);
    rb_define_method(cTimestampResponse, "version", ossl_ts_get_version, 0);
    rb_define_method(cTimestampResponse, "policy_id", ossl_ts_get_policy_id, 0);
    rb_define_method(cTimestampResponse, "algorithm", ossl_ts_get_algorithm, 0);
    rb_define_method(cTimestampResponse, "message_imprint", ossl_ts_get_msg_imprint, 0);
    rb_define_method(cTimestampResponse, "serial_number", ossl_ts_get_serial_number, 0);
    rb_define_method(cTimestampResponse, "gen_time", ossl_ts_get_gen_time, 0);
    rb_define_method(cTimestampResponse, "ordering", ossl_ts_get_ordering, 0);
    rb_define_method(cTimestampResponse, "nonce", ossl_ts_get_nonce, 0);
    rb_define_method(cTimestampResponse, "to_der", ossl_ts_to_der, 0);
    rb_define_method(cTimestampResponse, "verify", ossl_ts_verify, -1);

    /* Document-class: OpenSSL::Timestamp::Request
     * Allows to create timestamp requests or parse existing ones. A Request is
     * also needed for creating timestamps from scratch with Factory. When
     * created from scratch, some default values are set:
     * * version is set to +1+
     * * cert_requested is set to +true+
     * * algorithm, message_imprint, policy_id, and nonce are set to +false+
     */
    cTimestampRequest = rb_define_class_under(mTimestamp, "Request", rb_cObject);
    rb_define_alloc_func(cTimestampRequest, ossl_tsreq_alloc);
    rb_define_method(cTimestampRequest, "initialize", ossl_tsreq_initialize, -1);
    rb_define_method(cTimestampRequest, "version=", ossl_tsreq_set_version, 1);
    rb_define_method(cTimestampRequest, "version", ossl_tsreq_get_version, 0);
    rb_define_method(cTimestampRequest, "algorithm=", ossl_tsreq_set_algorithm, 1);
    rb_define_method(cTimestampRequest, "algorithm", ossl_tsreq_get_algorithm, 0);
    rb_define_method(cTimestampRequest, "message_imprint=", ossl_tsreq_set_msg_imprint, 1);
    rb_define_method(cTimestampRequest, "message_imprint", ossl_tsreq_get_msg_imprint, 0);
    rb_define_method(cTimestampRequest, "policy_id=", ossl_tsreq_set_policy_id, 1);
    rb_define_method(cTimestampRequest, "policy_id", ossl_tsreq_get_policy_id, 0);
    rb_define_method(cTimestampRequest, "nonce=", ossl_tsreq_set_nonce, 1);
    rb_define_method(cTimestampRequest, "nonce", ossl_tsreq_get_nonce, 0);
    rb_define_method(cTimestampRequest, "cert_requested=", ossl_tsreq_set_cert_requested, 1);
    rb_define_method(cTimestampRequest, "cert_requested?", ossl_tsreq_get_cert_requested, 0);
    rb_define_method(cTimestampRequest, "to_der", ossl_tsreq_to_der, 0);

    /*
     * Indicates a successful response. Equal to +0+.
     */
    rb_define_const(cTimestampResponse, "GRANTED", INT2NUM(TS_STATUS_GRANTED));
    /*
     * Indicates a successful response that probably contains modifications
     * from the initial request. Equal to +1+.
     */
    rb_define_const(cTimestampResponse, "GRANTED_WITH_MODS", INT2NUM(TS_STATUS_GRANTED_WITH_MODS));
    /*
     * Indicates a failure. No timestamp token was created. Equal to +2+.
     */
    rb_define_const(cTimestampResponse, "REJECTION", INT2NUM(TS_STATUS_REJECTION));
    /*
     * Indicates a failure. No timestamp token was created. Equal to +3+.
     */
    rb_define_const(cTimestampResponse, "WAITING", INT2NUM(TS_STATUS_WAITING));
    /*
     * Indicates a failure. No timestamp token was created. Revocation of a
     * certificate is imminent. Equal to +4+.
     */
    rb_define_const(cTimestampResponse, "REVOCATION_WARNING", INT2NUM(TS_STATUS_REVOCATION_WARNING));
    /*
     * Indicates a failure. No timestamp token was created. A certificate
     * has been revoked. Equal to +5+.
     */
    rb_define_const(cTimestampResponse, "REVOCATION_NOTIFICATION", INT2NUM(TS_STATUS_REVOCATION_NOTIFICATION));

    /* Document-class: OpenSSL::Timestamp::Factory
     *
     * Used to generate a Response from scratch.
     *
     * Please bear in mind that the implementation will always apply and prefer
     * the policy object identifier given in the request over the default policy
     * id specified in the Factory. As a consequence, +default_policy_id+ will
     * only be applied if no Request#policy_id was given. But this also means
     * that one needs to check the policy identifier in the request manually
     * before creating the Response, e.g. to check whether it complies to a
     * specific set of acceptable policies.
     *
     * There exists also the possibility to add certificates (instances of
     * OpenSSL::X509::Certificate) besides the timestamping certificate
     * that will be included in the resulting timestamp token if
     * Request#cert_requested? is +true+. Ideally, one would also include any
     * intermediate certificates (the root certificate can be left out - in
     * order to trust it any verifying party will have to be in its possession
     * anyway). This simplifies validation of the timestamp since these
     * intermediate certificates are "already there" and need not be passed as
     * external parameters to Response#verify anymore, thus minimizing external
     * resources needed for verification.
     *
     * ===Example: Inclusion of (untrusted) intermediate certificates
     *
     * Assume we received a timestamp request that has set Request#policy_id to
     * +nil+ and Request#cert_requested? to true. The raw request bytes are
     * stored in a variable called +req_raw+. We'd still like to integrate
     * the necessary intermediate certificates (in +inter1.cer+ and
     * +inter2.cer+) to simplify validation of the resulting Response. +ts.p12+
     * is a PKCS#12-compatible file including the private key and the
     * timestamping certificate.
     *
     *      req = OpenSSL::Timestamp::Request.new(raw_bytes)
     *      p12 = OpenSSL::PKCS12.new(File.open('ts.p12', 'rb'), 'pwd')
     *      inter1 = OpenSSL::X509::Certificate.new(File.open('inter1.cer', 'rb')
     *      inter2 = OpenSSL::X509::Certificate.new(File.open('inter2.cer', 'rb')
     *      fac = OpenSSL::Timestamp::Factory.new
     *      fac.gen_time = Time.now
     *      fac.serial_number = 1
     *      #needed because the Request contained no policy identifier
     *      fac.default_policy_id = '1.2.3.4.5'
     *      fac.additional_certificates = [ inter1, inter2 ]
     *      timestamp = fac.create_timestamp(p12.key, p12.certificate, req)
     *
     * ==Attributes
     *
     * ===default_policy_id
     *
     * Request#policy_id will always be preferred over this if present in the
     * Request, only if Request#policy_id is nil default_policy will be used.
     * If none of both is present, a TimestampError will be raised when trying
     * to create a Response.
     *
     * call-seq:
     *       factory.default_policy_id = "string" -> string
     *       factory.default_policy_id            -> string or nil
     *
     * ===serial_number
     *
     * Sets or retrieves the serial number to be used for timestamp creation.
     * Must be present for timestamp creation.
     *
     * call-seq:
     *       factory.serial_number = number -> number
     *       factory.serial_number          -> number or nil
     *
     * ===gen_time
     *
     * Sets or retrieves the Time value to be used in the Response. Must be
     * present for timestamp creation.
     *
     * call-seq:
     *       factory.gen_time = Time -> Time
     *       factory.gen_time        -> Time or nil
     *
     * ===additional_certs
     *
     * Sets or retrieves additional certificates apart from the timestamp
     * certificate (e.g. intermediate certificates) to be added to the Response.
     * May be a single OpenSSL::X509::Certificate or an Array of these.
     *
     * call-seq:
     *       factory.additional_certs = cert            -> cert
     *       factory.additional_certs = [ cert1, cert2] -> [ cert1, cert2 ]
     *       factory.additional_certs                   -> single cert, array or nil
     *
     */
    cTimestampFactory = rb_define_class_under(mTimestamp, "Factory", rb_cObject);
    rb_define_method(cTimestampFactory, "initialize", ossl_tsfac_initialize, 0);
    rb_attr(cTimestampFactory, rb_intern("default_policy_id"), 1, 1, 0);
    rb_attr(cTimestampFactory, rb_intern("serial_number"), 1, 1, 0);
    rb_attr(cTimestampFactory, rb_intern("gen_time"), 1, 1, 0);
    rb_attr(cTimestampFactory, rb_intern("additional_certs"), 1, 1, 0);
    rb_define_method(cTimestampFactory, "create_timestamp", ossl_tsfac_create_ts, 3);
}

#endif