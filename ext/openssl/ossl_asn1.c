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

static VALUE cASN1EndOfContent;
static VALUE cASN1Boolean;                           /* BOOLEAN           */
static VALUE cASN1Integer, cASN1Enumerated;          /* INTEGER           */
static VALUE cASN1BitString;                         /* BIT STRING        */
static VALUE cASN1OctetString, cASN1UTF8String;      /* STRINGs           */
static VALUE cASN1NumericString, cASN1PrintableString;
static VALUE cASN1T61String, cASN1VideotexString;
static VALUE cASN1IA5String, cASN1GraphicString;
static VALUE cASN1ISO64String, cASN1GeneralString;
static VALUE cASN1UniversalString, cASN1BMPString;
static VALUE cASN1Null;                              /* NULL              */
static VALUE cASN1ObjectId;                          /* OBJECT IDENTIFIER */
static VALUE cASN1UTCTime, cASN1GeneralizedTime;     /* TIME              */
static VALUE cASN1Sequence, cASN1Set;                /* CONSTRUCTIVE      */

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

typedef struct {
    const char *name;
    VALUE *klass;
} ossl_asn1_info_t;

static const ossl_asn1_info_t ossl_asn1_info[] = {
    { "EOC",               &cASN1EndOfContent,    },  /*  0 */
    { "BOOLEAN",           &cASN1Boolean,         },  /*  1 */
    { "INTEGER",           &cASN1Integer,         },  /*  2 */
    { "BIT_STRING",        &cASN1BitString,       },  /*  3 */
    { "OCTET_STRING",      &cASN1OctetString,     },  /*  4 */
    { "NULL",              &cASN1Null,            },  /*  5 */
    { "OBJECT",            &cASN1ObjectId,        },  /*  6 */
    { "OBJECT_DESCRIPTOR", NULL,                  },  /*  7 */
    { "EXTERNAL",          NULL,                  },  /*  8 */
    { "REAL",              NULL,                  },  /*  9 */
    { "ENUMERATED",        &cASN1Enumerated,      },  /* 10 */
    { "EMBEDDED_PDV",      NULL,                  },  /* 11 */
    { "UTF8STRING",        &cASN1UTF8String,      },  /* 12 */
    { "RELATIVE_OID",      NULL,                  },  /* 13 */
    { "[UNIVERSAL 14]",    NULL,                  },  /* 14 */
    { "[UNIVERSAL 15]",    NULL,                  },  /* 15 */
    { "SEQUENCE",          &cASN1Sequence,        },  /* 16 */
    { "SET",               &cASN1Set,             },  /* 17 */
    { "NUMERICSTRING",     &cASN1NumericString,   },  /* 18 */
    { "PRINTABLESTRING",   &cASN1PrintableString, },  /* 19 */
    { "T61STRING",         &cASN1T61String,       },  /* 20 */
    { "VIDEOTEXSTRING",    &cASN1VideotexString,  },  /* 21 */
    { "IA5STRING",         &cASN1IA5String,       },  /* 22 */
    { "UTCTIME",           &cASN1UTCTime,         },  /* 23 */
    { "GENERALIZEDTIME",   &cASN1GeneralizedTime, },  /* 24 */
    { "GRAPHICSTRING",     &cASN1GraphicString,   },  /* 25 */
    { "ISO64STRING",       &cASN1ISO64String,     },  /* 26 */
    { "GENERALSTRING",     &cASN1GeneralString,   },  /* 27 */
    { "UNIVERSALSTRING",   &cASN1UniversalString, },  /* 28 */
    { "CHARACTER_STRING",  NULL,                  },  /* 29 */
    { "BMPSTRING",         &cASN1BMPString,       },  /* 30 */
};

enum {ossl_asn1_info_size = (sizeof(ossl_asn1_info)/sizeof(ossl_asn1_info[0]))};

static VALUE class_tag_map;

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

#define OSSL_ASN1_IMPL_FACTORY_METHOD(klass) \
static VALUE ossl_asn1_##klass(int argc, VALUE *argv, VALUE self)\
{ return rb_funcallv_public(cASN1##klass, rb_intern("new"), argc, argv); }

OSSL_ASN1_IMPL_FACTORY_METHOD(Boolean)
OSSL_ASN1_IMPL_FACTORY_METHOD(Integer)
OSSL_ASN1_IMPL_FACTORY_METHOD(Enumerated)
OSSL_ASN1_IMPL_FACTORY_METHOD(BitString)
OSSL_ASN1_IMPL_FACTORY_METHOD(OctetString)
OSSL_ASN1_IMPL_FACTORY_METHOD(UTF8String)
OSSL_ASN1_IMPL_FACTORY_METHOD(NumericString)
OSSL_ASN1_IMPL_FACTORY_METHOD(PrintableString)
OSSL_ASN1_IMPL_FACTORY_METHOD(T61String)
OSSL_ASN1_IMPL_FACTORY_METHOD(VideotexString)
OSSL_ASN1_IMPL_FACTORY_METHOD(IA5String)
OSSL_ASN1_IMPL_FACTORY_METHOD(GraphicString)
OSSL_ASN1_IMPL_FACTORY_METHOD(ISO64String)
OSSL_ASN1_IMPL_FACTORY_METHOD(GeneralString)
OSSL_ASN1_IMPL_FACTORY_METHOD(UniversalString)
OSSL_ASN1_IMPL_FACTORY_METHOD(BMPString)
OSSL_ASN1_IMPL_FACTORY_METHOD(Null)
OSSL_ASN1_IMPL_FACTORY_METHOD(ObjectId)
OSSL_ASN1_IMPL_FACTORY_METHOD(UTCTime)
OSSL_ASN1_IMPL_FACTORY_METHOD(GeneralizedTime)
OSSL_ASN1_IMPL_FACTORY_METHOD(Sequence)
OSSL_ASN1_IMPL_FACTORY_METHOD(Set)
OSSL_ASN1_IMPL_FACTORY_METHOD(EndOfContent)

void
Init_ossl_asn1(void)
{
#undef rb_intern
    VALUE ary;
    int i;

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
    ary = rb_ary_new();

    /*
     * Array storing tag names at the tag's index.
     */
    rb_define_const(mASN1, "UNIVERSAL_TAG_NAME", ary);
    for(i = 0; i < ossl_asn1_info_size; i++){
	if(ossl_asn1_info[i].name[0] == '[') continue;
	rb_define_const(mASN1, ossl_asn1_info[i].name, INT2NUM(i));
	rb_ary_store(ary, i, rb_str_new2(ossl_asn1_info[i].name));
    }


    cASN1Data = rb_define_class_under(mASN1, "ASN1Data", rb_cObject);
    cASN1Primitive = rb_define_class_under(mASN1, "Primitive", cASN1Data);

    cASN1Constructive = rb_define_class_under(mASN1,"Constructive", cASN1Data);
#define OSSL_ASN1_DEFINE_CLASS(name, super) \
do{\
    cASN1##name = rb_define_class_under(mASN1, #name, cASN1##super);\
    rb_define_module_function(mASN1, #name, ossl_asn1_##name, -1);\
}while(0)

    OSSL_ASN1_DEFINE_CLASS(Boolean, Primitive);
    OSSL_ASN1_DEFINE_CLASS(Integer, Primitive);
    OSSL_ASN1_DEFINE_CLASS(Enumerated, Primitive);
    OSSL_ASN1_DEFINE_CLASS(BitString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(OctetString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(UTF8String, Primitive);
    OSSL_ASN1_DEFINE_CLASS(NumericString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(PrintableString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(T61String, Primitive);
    OSSL_ASN1_DEFINE_CLASS(VideotexString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(IA5String, Primitive);
    OSSL_ASN1_DEFINE_CLASS(GraphicString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(ISO64String, Primitive);
    OSSL_ASN1_DEFINE_CLASS(GeneralString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(UniversalString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(BMPString, Primitive);
    OSSL_ASN1_DEFINE_CLASS(Null, Primitive);
    OSSL_ASN1_DEFINE_CLASS(ObjectId, Primitive);
    OSSL_ASN1_DEFINE_CLASS(UTCTime, Primitive);
    OSSL_ASN1_DEFINE_CLASS(GeneralizedTime, Primitive);

    OSSL_ASN1_DEFINE_CLASS(Sequence, Constructive);
    OSSL_ASN1_DEFINE_CLASS(Set, Constructive);

    OSSL_ASN1_DEFINE_CLASS(EndOfContent, Data);


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

    class_tag_map = rb_hash_new();
    rb_hash_aset(class_tag_map, cASN1EndOfContent, INT2NUM(V_ASN1_EOC));
    rb_hash_aset(class_tag_map, cASN1Boolean, INT2NUM(V_ASN1_BOOLEAN));
    rb_hash_aset(class_tag_map, cASN1Integer, INT2NUM(V_ASN1_INTEGER));
    rb_hash_aset(class_tag_map, cASN1BitString, INT2NUM(V_ASN1_BIT_STRING));
    rb_hash_aset(class_tag_map, cASN1OctetString, INT2NUM(V_ASN1_OCTET_STRING));
    rb_hash_aset(class_tag_map, cASN1Null, INT2NUM(V_ASN1_NULL));
    rb_hash_aset(class_tag_map, cASN1ObjectId, INT2NUM(V_ASN1_OBJECT));
    rb_hash_aset(class_tag_map, cASN1Enumerated, INT2NUM(V_ASN1_ENUMERATED));
    rb_hash_aset(class_tag_map, cASN1UTF8String, INT2NUM(V_ASN1_UTF8STRING));
    rb_hash_aset(class_tag_map, cASN1Sequence, INT2NUM(V_ASN1_SEQUENCE));
    rb_hash_aset(class_tag_map, cASN1Set, INT2NUM(V_ASN1_SET));
    rb_hash_aset(class_tag_map, cASN1NumericString, INT2NUM(V_ASN1_NUMERICSTRING));
    rb_hash_aset(class_tag_map, cASN1PrintableString, INT2NUM(V_ASN1_PRINTABLESTRING));
    rb_hash_aset(class_tag_map, cASN1T61String, INT2NUM(V_ASN1_T61STRING));
    rb_hash_aset(class_tag_map, cASN1VideotexString, INT2NUM(V_ASN1_VIDEOTEXSTRING));
    rb_hash_aset(class_tag_map, cASN1IA5String, INT2NUM(V_ASN1_IA5STRING));
    rb_hash_aset(class_tag_map, cASN1UTCTime, INT2NUM(V_ASN1_UTCTIME));
    rb_hash_aset(class_tag_map, cASN1GeneralizedTime, INT2NUM(V_ASN1_GENERALIZEDTIME));
    rb_hash_aset(class_tag_map, cASN1GraphicString, INT2NUM(V_ASN1_GRAPHICSTRING));
    rb_hash_aset(class_tag_map, cASN1ISO64String, INT2NUM(V_ASN1_ISO64STRING));
    rb_hash_aset(class_tag_map, cASN1GeneralString, INT2NUM(V_ASN1_GENERALSTRING));
    rb_hash_aset(class_tag_map, cASN1UniversalString, INT2NUM(V_ASN1_UNIVERSALSTRING));
    rb_hash_aset(class_tag_map, cASN1BMPString, INT2NUM(V_ASN1_BMPSTRING));
    rb_define_const(mASN1, "CLASS_TAG_MAP", class_tag_map);
}
