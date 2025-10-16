/*
 * 'OpenSSL for Ruby' team members
 * Copyright (C) 2003
 * All rights reserved.
 */
/*
 * This program is licensed under the same licence as Ruby.
 * (See the file 'COPYING'.)
 */
#include "ossl.h"

/*
 * DATE conversion
 */
VALUE
asn1time_to_time(const ASN1_TIME *time)
{
    struct tm tm;
    VALUE argv[6];
    int count;

    memset(&tm, 0, sizeof(struct tm));

    switch (time->type) {
    case V_ASN1_UTCTIME:
       count = sscanf((const char *)time->data, "%2d%2d%2d%2d%2d%2dZ",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min,
               &tm.tm_sec);

       if (count == 5) {
           tm.tm_sec = 0;
       } else if (count != 6) {
           ossl_raise(rb_eTypeError, "bad UTCTIME format: \"%s\"",
                   time->data);
       }
       if (tm.tm_year < 50) {
           tm.tm_year += 2000;
       } else {
           tm.tm_year += 1900;
       }
       break;
    case V_ASN1_GENERALIZEDTIME:
       count = sscanf((const char *)time->data, "%4d%2d%2d%2d%2d%2dZ",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min,
               &tm.tm_sec);
       if (count == 5) {
               tm.tm_sec = 0;
       }
       else if (count != 6) {
               ossl_raise(rb_eTypeError, "bad GENERALIZEDTIME format: \"%s\"",
                       time->data);
       }
       break;
    default:
       rb_warning("unknown time format");
        return Qnil;
    }
    argv[0] = INT2NUM(tm.tm_year);
    argv[1] = INT2NUM(tm.tm_mon);
    argv[2] = INT2NUM(tm.tm_mday);
    argv[3] = INT2NUM(tm.tm_hour);
    argv[4] = INT2NUM(tm.tm_min);
    argv[5] = INT2NUM(tm.tm_sec);

    return rb_funcall2(rb_cTime, rb_intern("utc"), 6, argv);
}

void
ossl_time_split(VALUE time, time_t *sec, int *days)
{
    VALUE num = rb_Integer(time);

    if (FIXNUM_P(num)) {
       time_t t = FIX2LONG(num);
       *sec = t % 86400;
       *days = rb_long2int(t / 86400);
    }
    else {
       *days = NUM2INT(rb_funcall(num, rb_intern("/"), 1, INT2FIX(86400)));
       *sec = NUM2TIMET(rb_funcall(num, rb_intern("%"), 1, INT2FIX(86400)));
    }
}

/*
 * STRING conversion
 */
VALUE
asn1str_to_str(const ASN1_STRING *str)
{
    return rb_str_new((const char *)str->data, str->length);
}

VALUE
asn1integer_to_num(const ASN1_INTEGER *ai)
{
    BIGNUM *bn;
    VALUE num;

    if (!ai) {
       ossl_raise(rb_eTypeError, "ASN1_INTEGER is NULL!");
    }
    if (ai->type == V_ASN1_ENUMERATED)
       /* const_cast: workaround for old OpenSSL */
       bn = ASN1_ENUMERATED_to_BN((ASN1_ENUMERATED *)ai, NULL);
    else
       bn = ASN1_INTEGER_to_BN(ai, NULL);

    if (!bn)
       ossl_raise(eOSSLError, NULL);
    num = ossl_bn_new(bn);
    BN_free(bn);

    return num;
}

ASN1_INTEGER *
num_to_asn1integer(VALUE obj, ASN1_INTEGER *ai)
{
    BIGNUM *bn;

    if (NIL_P(obj))
       ossl_raise(rb_eTypeError, "Can't convert nil into Integer");

    bn = GetBNPtr(obj);

    if (!(ai = BN_to_ASN1_INTEGER(bn, ai)))
       ossl_raise(eOSSLError, NULL);

    return ai;
}

/********/
/*
 * ASN1 module
 */
#define ossl_asn1_get_value(o)           rb_attr_get((o),sivVALUE)
#define ossl_asn1_get_tag(o)             rb_attr_get((o),sivTAG)

VALUE mASN1;
VALUE eASN1Error;

VALUE cASN1Data;
static VALUE cASN1Primitive;
static VALUE cASN1Constructive;

static VALUE cASN1ObjectId;                          /* OBJECT IDENTIFIER */

static VALUE sym_IMPLICIT, sym_EXPLICIT;
static VALUE sym_UNIVERSAL, sym_APPLICATION, sym_CONTEXT_SPECIFIC, sym_PRIVATE;
static ID sivVALUE, sivTAG, sivTAG_CLASS, sivTAGGING, sivINDEFINITE_LENGTH, sivUNUSED_BITS;

static ASN1_OBJECT*
obj_to_asn1obj(VALUE obj)
{
    ASN1_OBJECT *a1obj;

    StringValueCStr(obj);
    a1obj = OBJ_txt2obj(RSTRING_PTR(obj), 0);
    if(!a1obj) a1obj = OBJ_txt2obj(RSTRING_PTR(obj), 1);
    if(!a1obj) ossl_raise(eASN1Error, "invalid OBJECT ID %"PRIsVALUE, obj);

    return a1obj;
}

/********/

/*
 * call-seq:
 *    OpenSSL::ASN1::ObjectId.register(object_id, short_name, long_name)
 *
 * This adds a new ObjectId to the internal tables. Where _object_id_ is the
 * numerical form, _short_name_ is the short name, and _long_name_ is the long
 * name.
 *
 * Returns +true+ if successful. Raises an OpenSSL::ASN1::ASN1Error if it fails.
 *
 */
static VALUE
ossl_asn1obj_s_register(VALUE self, VALUE oid, VALUE sn, VALUE ln)
{
    StringValueCStr(oid);
    StringValueCStr(sn);
    StringValueCStr(ln);

    if(!OBJ_create(RSTRING_PTR(oid), RSTRING_PTR(sn), RSTRING_PTR(ln)))
	ossl_raise(eASN1Error, NULL);

    return Qtrue;
}

/*
 * call-seq:
 *    oid.sn -> string
 *    oid.short_name -> string
 *
 * The short name of the ObjectId, as defined in <openssl/objects.h>.
 */
static VALUE
ossl_asn1obj_get_sn(VALUE self)
{
    VALUE val, ret = Qnil;
    int nid;

    val = ossl_asn1_get_value(self);
    if ((nid = OBJ_txt2nid(StringValueCStr(val))) != NID_undef)
	ret = rb_str_new2(OBJ_nid2sn(nid));

    return ret;
}

/*
 * call-seq:
 *    oid.ln -> string
 *    oid.long_name -> string
 *
 * The long name of the ObjectId, as defined in <openssl/objects.h>.
 */
static VALUE
ossl_asn1obj_get_ln(VALUE self)
{
    VALUE val, ret = Qnil;
    int nid;

    val = ossl_asn1_get_value(self);
    if ((nid = OBJ_txt2nid(StringValueCStr(val))) != NID_undef)
	ret = rb_str_new2(OBJ_nid2ln(nid));

    return ret;
}

static VALUE
asn1obj_get_oid_i(VALUE vobj)
{
    ASN1_OBJECT *a1obj = (void *)vobj;
    VALUE str;
    int len;

    str = rb_usascii_str_new(NULL, 127);
    len = OBJ_obj2txt(RSTRING_PTR(str), RSTRING_LENINT(str), a1obj, 1);
    if (len <= 0 || len == INT_MAX)
	ossl_raise(eASN1Error, "OBJ_obj2txt");
    if (len > RSTRING_LEN(str)) {
	/* +1 is for the \0 terminator added by OBJ_obj2txt() */
	rb_str_resize(str, len + 1);
	len = OBJ_obj2txt(RSTRING_PTR(str), len + 1, a1obj, 1);
	if (len <= 0)
	    ossl_raise(eASN1Error, "OBJ_obj2txt");
    }
    rb_str_set_len(str, len);
    return str;
}

/*
 * call-seq:
 *    oid.oid -> string
 *
 * Returns a String representing the Object Identifier in the dot notation,
 * e.g. "1.2.3.4.5"
 */
static VALUE
ossl_asn1obj_get_oid(VALUE self)
{
    VALUE str;
    ASN1_OBJECT *a1obj;
    int state;

    a1obj = obj_to_asn1obj(ossl_asn1_get_value(self));
    str = rb_protect(asn1obj_get_oid_i, (VALUE)a1obj, &state);
    ASN1_OBJECT_free(a1obj);
    if (state)
	rb_jump_tag(state);
    return str;
}

/*
 *  call-seq:
 *     oid == other_oid => true or false
 *
 *  Returns +true+ if _other_oid_ is the same as _oid_.
 */
static VALUE
ossl_asn1obj_eq(VALUE self, VALUE other)
{
    VALUE oid1, oid2;

    if (!rb_obj_is_kind_of(other, cASN1ObjectId))
        return Qfalse;

    oid1 = ossl_asn1obj_get_oid(self);
    oid2 = ossl_asn1obj_get_oid(other);
    return rb_str_equal(oid1, oid2);
}

void
Init_ossl_asn1(void)
{
#undef rb_intern

#if 0
    mOSSL = rb_define_module("OpenSSL");
    eOSSLError = rb_define_class_under(mOSSL, "OpenSSLError", rb_eStandardError);
#endif

    sym_UNIVERSAL = ID2SYM(rb_intern_const("UNIVERSAL"));
    sym_CONTEXT_SPECIFIC = ID2SYM(rb_intern_const("CONTEXT_SPECIFIC"));
    sym_APPLICATION = ID2SYM(rb_intern_const("APPLICATION"));
    sym_PRIVATE = ID2SYM(rb_intern_const("PRIVATE"));
    sym_EXPLICIT = ID2SYM(rb_intern_const("EXPLICIT"));
    sym_IMPLICIT = ID2SYM(rb_intern_const("IMPLICIT"));

    sivVALUE = rb_intern("@value");
    sivTAG = rb_intern("@tag");
    sivTAGGING = rb_intern("@tagging");
    sivTAG_CLASS = rb_intern("@tag_class");
    sivINDEFINITE_LENGTH = rb_intern("@indefinite_length");
    sivUNUSED_BITS = rb_intern("@unused_bits");

    mASN1 = rb_define_module_under(mOSSL, "ASN1");

    /* Document-class: OpenSSL::ASN1::ASN1Error
     *
     * Generic error class for all errors raised in ASN1 and any of the
     * classes defined in it.
     */
    eASN1Error = rb_define_class_under(mASN1, "ASN1Error", eOSSLError);

    cASN1Data = rb_define_class_under(mASN1, "ASN1Data", rb_cObject);
    cASN1Primitive = rb_define_class_under(mASN1, "Primitive", cASN1Data);

    cASN1Constructive = rb_define_class_under(mASN1,"Constructive", cASN1Data);
    cASN1ObjectId = rb_define_class_under(mASN1,"ObjectId", cASN1Primitive);

#if 0
    cASN1ObjectId = rb_define_class_under(mASN1, "ObjectId", cASN1Primitive);  /* let rdoc know */
#endif
    rb_define_singleton_method(cASN1ObjectId, "register", ossl_asn1obj_s_register, 3);
    rb_define_method(cASN1ObjectId, "sn", ossl_asn1obj_get_sn, 0);
    rb_define_method(cASN1ObjectId, "ln", ossl_asn1obj_get_ln, 0);
    rb_define_method(cASN1ObjectId, "oid", ossl_asn1obj_get_oid, 0);
    rb_define_alias(cASN1ObjectId, "short_name", "sn");
    rb_define_alias(cASN1ObjectId, "long_name", "ln");
    rb_define_method(cASN1ObjectId, "==", ossl_asn1obj_eq, 1);
}
