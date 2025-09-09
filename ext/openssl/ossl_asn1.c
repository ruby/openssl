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

    /*
     * Document-module: OpenSSL::ASN1
     *
     * Abstract Syntax Notation One (or ASN.1) is a notation syntax to
     * describe data structures and is defined in ITU-T X.680. ASN.1 itself
     * does not mandate any encoding or parsing rules, but usually ASN.1 data
     * structures are encoded using the Distinguished Encoding Rules (DER) or
     * less often the Basic Encoding Rules (BER) described in ITU-T X.690. DER
     * and BER encodings are binary Tag-Length-Value (TLV) encodings that are
     * quite concise compared to other popular data description formats such
     * as XML, JSON etc.
     * ASN.1 data structures are very common in cryptographic applications,
     * e.g. X.509 public key certificates or certificate revocation lists
     * (CRLs) are all defined in ASN.1 and DER-encoded. ASN.1, DER and BER are
     * the building blocks of applied cryptography.
     * The ASN1 module provides the necessary classes that allow generation
     * of ASN.1 data structures and the methods to encode them using a DER
     * encoding. The decode method allows parsing arbitrary BER-/DER-encoded
     * data to a Ruby object that can then be modified and re-encoded at will.
     *
     * == ASN.1 class hierarchy
     *
     * The base class representing ASN.1 structures is ASN1Data. ASN1Data offers
     * attributes to read and set the _tag_, the _tag_class_ and finally the
     * _value_ of a particular ASN.1 item. Upon parsing, any tagged values
     * (implicit or explicit) will be represented by ASN1Data instances because
     * their "real type" can only be determined using out-of-band information
     * from the ASN.1 type declaration. Since this information is normally
     * known when encoding a type, all sub-classes of ASN1Data offer an
     * additional attribute _tagging_ that allows to encode a value implicitly
     * (+:IMPLICIT+) or explicitly (+:EXPLICIT+).
     *
     * === Constructive
     *
     * Constructive is, as its name implies, the base class for all
     * constructed encodings, i.e. those that consist of several values,
     * opposed to "primitive" encodings with just one single value. The value of
     * an Constructive is always an Array.
     *
     * ==== ASN1::Set and ASN1::Sequence
     *
     * The most common constructive encodings are SETs and SEQUENCEs, which is
     * why there are two sub-classes of Constructive representing each of
     * them.
     *
     * === Primitive
     *
     * This is the super class of all primitive values. Primitive
     * itself is not used when parsing ASN.1 data, all values are either
     * instances of a corresponding sub-class of Primitive or they are
     * instances of ASN1Data if the value was tagged implicitly or explicitly.
     * Please cf. Primitive documentation for details on sub-classes and
     * their respective mappings of ASN.1 data types to Ruby objects.
     *
     * == Possible values for _tagging_
     *
     * When constructing an ASN1Data object the ASN.1 type definition may
     * require certain elements to be either implicitly or explicitly tagged.
     * This can be achieved by setting the _tagging_ attribute manually for
     * sub-classes of ASN1Data. Use the symbol +:IMPLICIT+ for implicit
     * tagging and +:EXPLICIT+ if the element requires explicit tagging.
     *
     * == Possible values for _tag_class_
     *
     * It is possible to create arbitrary ASN1Data objects that also support
     * a PRIVATE or APPLICATION tag class. Possible values for the _tag_class_
     * attribute are:
     * * +:UNIVERSAL+ (the default for untagged values)
     * * +:CONTEXT_SPECIFIC+ (the default for tagged values)
     * * +:APPLICATION+
     * * +:PRIVATE+
     *
     * == Tag constants
     *
     * There is a constant defined for each universal tag:
     * * OpenSSL::ASN1::EOC (0)
     * * OpenSSL::ASN1::BOOLEAN (1)
     * * OpenSSL::ASN1::INTEGER (2)
     * * OpenSSL::ASN1::BIT_STRING (3)
     * * OpenSSL::ASN1::OCTET_STRING (4)
     * * OpenSSL::ASN1::NULL (5)
     * * OpenSSL::ASN1::OBJECT (6)
     * * OpenSSL::ASN1::ENUMERATED (10)
     * * OpenSSL::ASN1::UTF8STRING (12)
     * * OpenSSL::ASN1::SEQUENCE (16)
     * * OpenSSL::ASN1::SET (17)
     * * OpenSSL::ASN1::NUMERICSTRING (18)
     * * OpenSSL::ASN1::PRINTABLESTRING (19)
     * * OpenSSL::ASN1::T61STRING (20)
     * * OpenSSL::ASN1::VIDEOTEXSTRING (21)
     * * OpenSSL::ASN1::IA5STRING (22)
     * * OpenSSL::ASN1::UTCTIME (23)
     * * OpenSSL::ASN1::GENERALIZEDTIME (24)
     * * OpenSSL::ASN1::GRAPHICSTRING (25)
     * * OpenSSL::ASN1::ISO64STRING (26)
     * * OpenSSL::ASN1::GENERALSTRING (27)
     * * OpenSSL::ASN1::UNIVERSALSTRING (28)
     * * OpenSSL::ASN1::BMPSTRING (30)
     *
     * == UNIVERSAL_TAG_NAME constant
     *
     * An Array that stores the name of a given tag number. These names are
     * the same as the name of the tag constant that is additionally defined,
     * e.g. <tt>UNIVERSAL_TAG_NAME[2] = "INTEGER"</tt> and <tt>OpenSSL::ASN1::INTEGER = 2</tt>.
     *
     * == Example usage
     *
     * === Decoding and viewing a DER-encoded file
     *   require 'openssl'
     *   require 'pp'
     *   der = File.binread('data.der')
     *   asn1 = OpenSSL::ASN1.decode(der)
     *   pp der
     *
     * === Creating an ASN.1 structure and DER-encoding it
     *   require 'openssl'
     *   version = OpenSSL::ASN1::Integer.new(1)
     *   # Explicitly 0-tagged implies context-specific tag class
     *   serial = OpenSSL::ASN1::Integer.new(12345, 0, :EXPLICIT, :CONTEXT_SPECIFIC)
     *   name = OpenSSL::ASN1::PrintableString.new('Data 1')
     *   sequence = OpenSSL::ASN1::Sequence.new( [ version, serial, name ] )
     *   der = sequence.to_der
     */
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

    /* Document-class: OpenSSL::ASN1::ASN1Data
     *
     * The top-level class representing any ASN.1 object. When parsed by
     * ASN1.decode, tagged values are always represented by an instance
     * of ASN1Data.
     *
     * == The role of ASN1Data for parsing tagged values
     *
     * When encoding an ASN.1 type it is inherently clear what original
     * type (e.g. INTEGER, OCTET STRING etc.) this value has, regardless
     * of its tagging.
     * But opposed to the time an ASN.1 type is to be encoded, when parsing
     * them it is not possible to deduce the "real type" of tagged
     * values. This is why tagged values are generally parsed into ASN1Data
     * instances, but with a different outcome for implicit and explicit
     * tagging.
     *
     * === Example of a parsed implicitly tagged value
     *
     * An implicitly 1-tagged INTEGER value will be parsed as an
     * ASN1Data with
     * * _tag_ equal to 1
     * * _tag_class_ equal to +:CONTEXT_SPECIFIC+
     * * _value_ equal to a String that carries the raw encoding
     *   of the INTEGER.
     * This implies that a subsequent decoding step is required to
     * completely decode implicitly tagged values.
     *
     * === Example of a parsed explicitly tagged value
     *
     * An explicitly 1-tagged INTEGER value will be parsed as an
     * ASN1Data with
     * * _tag_ equal to 1
     * * _tag_class_ equal to +:CONTEXT_SPECIFIC+
     * * _value_ equal to an Array with one single element, an
     *   instance of OpenSSL::ASN1::Integer, i.e. the inner element
     *   is the non-tagged primitive value, and the tagging is represented
     *   in the outer ASN1Data
     *
     * == Example - Decoding an implicitly tagged INTEGER
     *   int = OpenSSL::ASN1::Integer.new(1, 0, :IMPLICIT) # implicit 0-tagged
     *   seq = OpenSSL::ASN1::Sequence.new( [int] )
     *   der = seq.to_der
     *   asn1 = OpenSSL::ASN1.decode(der)
     *   # pp asn1 => #<OpenSSL::ASN1::Sequence:0x87326e0
     *   #              @indefinite_length=false,
     *   #              @tag=16,
     *   #              @tag_class=:UNIVERSAL,
     *   #              @tagging=nil,
     *   #              @value=
     *   #                [#<OpenSSL::ASN1::ASN1Data:0x87326f4
     *   #                   @indefinite_length=false,
     *   #                   @tag=0,
     *   #                   @tag_class=:CONTEXT_SPECIFIC,
     *   #                   @value="\x01">]>
     *   raw_int = asn1.value[0]
     *   # manually rewrite tag and tag class to make it an UNIVERSAL value
     *   raw_int.tag = OpenSSL::ASN1::INTEGER
     *   raw_int.tag_class = :UNIVERSAL
     *   int2 = OpenSSL::ASN1.decode(raw_int)
     *   puts int2.value # => 1
     *
     * == Example - Decoding an explicitly tagged INTEGER
     *   int = OpenSSL::ASN1::Integer.new(1, 0, :EXPLICIT) # explicit 0-tagged
     *   seq = OpenSSL::ASN1::Sequence.new( [int] )
     *   der = seq.to_der
     *   asn1 = OpenSSL::ASN1.decode(der)
     *   # pp asn1 => #<OpenSSL::ASN1::Sequence:0x87326e0
     *   #              @indefinite_length=false,
     *   #              @tag=16,
     *   #              @tag_class=:UNIVERSAL,
     *   #              @tagging=nil,
     *   #              @value=
     *   #                [#<OpenSSL::ASN1::ASN1Data:0x87326f4
     *   #                   @indefinite_length=false,
     *   #                   @tag=0,
     *   #                   @tag_class=:CONTEXT_SPECIFIC,
     *   #                   @value=
     *   #                     [#<OpenSSL::ASN1::Integer:0x85bf308
     *   #                        @indefinite_length=false,
     *   #                        @tag=2,
     *   #                        @tag_class=:UNIVERSAL
     *   #                        @tagging=nil,
     *   #                        @value=1>]>]>
     *   int2 = asn1.value[0].value[0]
     *   puts int2.value # => 1
     */
    cASN1Data = rb_define_class_under(mASN1, "ASN1Data", rb_cObject);

    /* Document-class: OpenSSL::ASN1::Primitive
     *
     * The parent class for all primitive encodings. Attributes are the same as
     * for ASN1Data, with the addition of _tagging_.
     * Primitive values can never be encoded with indefinite length form, thus
     * it is not possible to set the _indefinite_length_ attribute for Primitive
     * and its sub-classes.
     *
     * == Primitive sub-classes and their mapping to Ruby classes
     * * OpenSSL::ASN1::EndOfContent    <=> _value_ is always +nil+
     * * OpenSSL::ASN1::Boolean         <=> _value_ is +true+ or +false+
     * * OpenSSL::ASN1::Integer         <=> _value_ is an OpenSSL::BN
     * * OpenSSL::ASN1::BitString       <=> _value_ is a String
     * * OpenSSL::ASN1::OctetString     <=> _value_ is a String
     * * OpenSSL::ASN1::Null            <=> _value_ is always +nil+
     * * OpenSSL::ASN1::Object          <=> _value_ is a String
     * * OpenSSL::ASN1::Enumerated      <=> _value_ is an OpenSSL::BN
     * * OpenSSL::ASN1::UTF8String      <=> _value_ is a String
     * * OpenSSL::ASN1::NumericString   <=> _value_ is a String
     * * OpenSSL::ASN1::PrintableString <=> _value_ is a String
     * * OpenSSL::ASN1::T61String       <=> _value_ is a String
     * * OpenSSL::ASN1::VideotexString  <=> _value_ is a String
     * * OpenSSL::ASN1::IA5String       <=> _value_ is a String
     * * OpenSSL::ASN1::UTCTime         <=> _value_ is a Time
     * * OpenSSL::ASN1::GeneralizedTime <=> _value_ is a Time
     * * OpenSSL::ASN1::GraphicString   <=> _value_ is a String
     * * OpenSSL::ASN1::ISO64String     <=> _value_ is a String
     * * OpenSSL::ASN1::GeneralString   <=> _value_ is a String
     * * OpenSSL::ASN1::UniversalString <=> _value_ is a String
     * * OpenSSL::ASN1::BMPString       <=> _value_ is a String
     *
     * == OpenSSL::ASN1::BitString
     *
     * === Additional attributes
     * _unused_bits_: if the underlying BIT STRING's
     * length is a multiple of 8 then _unused_bits_ is 0. Otherwise
     * _unused_bits_ indicates the number of bits that are to be ignored in
     * the final octet of the BitString's _value_.
     *
     * == OpenSSL::ASN1::ObjectId
     *
     * NOTE: While OpenSSL::ASN1::ObjectId.new will allocate a new ObjectId,
     * it is not typically allocated this way, but rather that are received from
     * parsed ASN1 encodings.
     *
     * === Additional attributes
     * * _sn_: the short name as defined in <openssl/objects.h>.
     * * _ln_: the long name as defined in <openssl/objects.h>.
     * * _oid_: the object identifier as a String, e.g. "1.2.3.4.5"
     * * _short_name_: alias for _sn_.
     * * _long_name_: alias for _ln_.
     *
     * == Examples
     * With the Exception of OpenSSL::ASN1::EndOfContent, each Primitive class
     * constructor takes at least one parameter, the _value_.
     *
     * === Creating EndOfContent
     *   eoc = OpenSSL::ASN1::EndOfContent.new
     *
     * === Creating any other Primitive
     *   prim = <class>.new(value) # <class> being one of the sub-classes except EndOfContent
     *   prim_zero_tagged_implicit = <class>.new(value, 0, :IMPLICIT)
     *   prim_zero_tagged_explicit = <class>.new(value, 0, :EXPLICIT)
     */
    cASN1Primitive = rb_define_class_under(mASN1, "Primitive", cASN1Data);

    /* Document-class: OpenSSL::ASN1::Constructive
     *
     * The parent class for all constructed encodings. The _value_ attribute
     * of a Constructive is always an Array. Attributes are the same as
     * for ASN1Data, with the addition of _tagging_.
     *
     * == SET and SEQUENCE
     *
     * Most constructed encodings come in the form of a SET or a SEQUENCE.
     * These encodings are represented by one of the two sub-classes of
     * Constructive:
     * * OpenSSL::ASN1::Set
     * * OpenSSL::ASN1::Sequence
     * Please note that tagged sequences and sets are still parsed as
     * instances of ASN1Data. Find further details on tagged values
     * there.
     *
     * === Example - constructing a SEQUENCE
     *   int = OpenSSL::ASN1::Integer.new(1)
     *   str = OpenSSL::ASN1::PrintableString.new('abc')
     *   sequence = OpenSSL::ASN1::Sequence.new( [ int, str ] )
     *
     * === Example - constructing a SET
     *   int = OpenSSL::ASN1::Integer.new(1)
     *   str = OpenSSL::ASN1::PrintableString.new('abc')
     *   set = OpenSSL::ASN1::Set.new( [ int, str ] )
     */
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


    /* Document-class: OpenSSL::ASN1::ObjectId
     *
     * Represents the primitive object id for OpenSSL::ASN1
     */
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
