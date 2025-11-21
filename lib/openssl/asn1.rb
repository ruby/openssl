# coding: binary
# frozen_string_literal: true
#--
#
# = Ruby-space definitions that completes C-space funcs for ASN.1
#
# = Licence
# This program is licensed under the same licence as Ruby.
# (See the file 'COPYING'.)
#++

module OpenSSL
  #
  # Abstract Syntax Notation One (or ASN.1) is a notation syntax to
  # describe data structures and is defined in ITU-T X.680. ASN.1 itself
  # does not mandate any encoding or parsing rules, but usually ASN.1 data
  # structures are encoded using the Distinguished Encoding Rules (DER) or
  # less often the Basic Encoding Rules (BER) described in ITU-T X.690. DER
  # and BER encodings are binary Tag-Length-Value (TLV) encodings that are
  # quite concise compared to other popular data description formats such
  # as XML, JSON etc.
  # ASN.1 data structures are very common in cryptographic applications,
  # e.g. X.509 public key certificates or certificate revocation lists
  # (CRLs) are all defined in ASN.1 and DER-encoded. ASN.1, DER and BER are
  # the building blocks of applied cryptography.
  # The ASN1 module provides the necessary classes that allow generation
  # of ASN.1 data structures and the methods to encode them using a DER
  # encoding. The decode method allows parsing arbitrary BER-/DER-encoded
  # data to a Ruby object that can then be modified and re-encoded at will.
  #
  # == ASN.1 class hierarchy
  #
  # The base class representing ASN.1 structures is ASN1Data. ASN1Data offers
  # attributes to read and set the _tag_, the _tag_class_ and finally the
  # _value_ of a particular ASN.1 item. Upon parsing, any tagged values
  # (implicit or explicit) will be represented by ASN1Data instances because
  # their "real type" can only be determined using out-of-band information
  # from the ASN.1 type declaration. Since this information is normally
  # known when encoding a type, all sub-classes of ASN1Data offer an
  # additional attribute _tagging_ that allows to encode a value implicitly
  # (+:IMPLICIT+) or explicitly (+:EXPLICIT+).
  #
  # === Constructive
  #
  # Constructive is, as its name implies, the base class for all
  # constructed encodings, i.e. those that consist of several values,
  # opposed to "primitive" encodings with just one single value. The value of
  # an Constructive is always an Array.
  #
  # ==== ASN1::Set and ASN1::Sequence
  #
  # The most common constructive encodings are SETs and SEQUENCEs, which is
  # why there are two sub-classes of Constructive representing each of
  # them.
  #
  # === Primitive
  #
  # This is the super class of all primitive values. Primitive
  # itself is not used when parsing ASN.1 data, all values are either
  # instances of a corresponding sub-class of Primitive or they are
  # instances of ASN1Data if the value was tagged implicitly or explicitly.
  # Please cf. Primitive documentation for details on sub-classes and
  # their respective mappings of ASN.1 data types to Ruby objects.
  #
  # == Possible values for _tagging_
  #
  # When constructing an ASN1Data object the ASN.1 type definition may
  # require certain elements to be either implicitly or explicitly tagged.
  # This can be achieved by setting the _tagging_ attribute manually for
  # sub-classes of ASN1Data. Use the symbol +:IMPLICIT+ for implicit
  # tagging and +:EXPLICIT+ if the element requires explicit tagging.
  #
  # == Possible values for _tag_class_
  #
  # It is possible to create arbitrary ASN1Data objects that also support
  # a PRIVATE or APPLICATION tag class. Possible values for the _tag_class_
  # attribute are:
  # * +:UNIVERSAL+ (the default for untagged values)
  # * +:CONTEXT_SPECIFIC+ (the default for tagged values)
  # * +:APPLICATION+
  # * +:PRIVATE+
  #
  # == Tag constants
  #
  # There is a constant defined for each universal tag:
  # * OpenSSL::ASN1::EOC (0)
  # * OpenSSL::ASN1::BOOLEAN (1)
  # * OpenSSL::ASN1::INTEGER (2)
  # * OpenSSL::ASN1::BIT_STRING (3)
  # * OpenSSL::ASN1::OCTET_STRING (4)
  # * OpenSSL::ASN1::NULL (5)
  # * OpenSSL::ASN1::OBJECT (6)
  # * OpenSSL::ASN1::ENUMERATED (10)
  # * OpenSSL::ASN1::UTF8STRING (12)
  # * OpenSSL::ASN1::SEQUENCE (16)
  # * OpenSSL::ASN1::SET (17)
  # * OpenSSL::ASN1::NUMERICSTRING (18)
  # * OpenSSL::ASN1::PRINTABLESTRING (19)
  # * OpenSSL::ASN1::T61STRING (20)
  # * OpenSSL::ASN1::VIDEOTEXSTRING (21)
  # * OpenSSL::ASN1::IA5STRING (22)
  # * OpenSSL::ASN1::UTCTIME (23)
  # * OpenSSL::ASN1::GENERALIZEDTIME (24)
  # * OpenSSL::ASN1::GRAPHICSTRING (25)
  # * OpenSSL::ASN1::ISO64STRING (26)
  # * OpenSSL::ASN1::GENERALSTRING (27)
  # * OpenSSL::ASN1::UNIVERSALSTRING (28)
  # * OpenSSL::ASN1::BMPSTRING (30)
  #
  # == UNIVERSAL_TAG_NAME constant
  #
  # An Array that stores the name of a given tag number. These names are
  # the same as the name of the tag constant that is additionally defined,
  # e.g. <tt>UNIVERSAL_TAG_NAME[2] = "INTEGER"</tt> and <tt>OpenSSL::ASN1::INTEGER = 2</tt>.
  #
  # == Example usage
  #
  # === Decoding and viewing a DER-encoded file
  #   require 'openssl'
  #   require 'pp'
  #   der = File.binread('data.der')
  #   asn1 = OpenSSL::ASN1.decode(der)
  #   pp der
  #
  # === Creating an ASN.1 structure and DER-encoding it
  #   require 'openssl'
  #   version = OpenSSL::ASN1::Integer.new(1)
  #   # Explicitly 0-tagged implies context-specific tag class
  #   serial = OpenSSL::ASN1::Integer.new(12345, 0, :EXPLICIT, :CONTEXT_SPECIFIC)
  #   name = OpenSSL::ASN1::PrintableString.new('Data 1')
  #   sequence = OpenSSL::ASN1::Sequence.new( [ version, serial, name ] )
  #   der = sequence.to_der
  #
  module ASN1
    #
    # The top-level class representing any ASN.1 object. When parsed by
    # ASN1.decode, tagged values are always represented by an instance
    # of ASN1Data.
    #
    # == The role of ASN1Data for parsing tagged values
    #
    # When encoding an ASN.1 type it is inherently clear what original
    # type (e.g. INTEGER, OCTET STRING etc.) this value has, regardless
    # of its tagging.
    # But opposed to the time an ASN.1 type is to be encoded, when parsing
    # them it is not possible to deduce the "real type" of tagged
    # values. This is why tagged values are generally parsed into ASN1Data
    # instances, but with a different outcome for implicit and explicit
    # tagging.
    #
    # === Example of a parsed implicitly tagged value
    #
    # An implicitly 1-tagged INTEGER value will be parsed as an
    # ASN1Data with
    # * _tag_ equal to 1
    # * _tag_class_ equal to +:CONTEXT_SPECIFIC+
    # * _value_ equal to a String that carries the raw encoding
    #   of the INTEGER.
    # This implies that a subsequent decoding step is required to
    # completely decode implicitly tagged values.
    #
    # === Example of a parsed explicitly tagged value
    #
    # An explicitly 1-tagged INTEGER value will be parsed as an
    # ASN1Data with
    # * _tag_ equal to 1
    # * _tag_class_ equal to +:CONTEXT_SPECIFIC+
    # * _value_ equal to an Array with one single element, an
    #   instance of OpenSSL::ASN1::Integer, i.e. the inner element
    #   is the non-tagged primitive value, and the tagging is represented
    #   in the outer ASN1Data
    #
    # == Example - Decoding an implicitly tagged INTEGER
    #   int = OpenSSL::ASN1::Integer.new(1, 0, :IMPLICIT) # implicit 0-tagged
    #   seq = OpenSSL::ASN1::Sequence.new( [int] )
    #   der = seq.to_der
    #   asn1 = OpenSSL::ASN1.decode(der)
    #   # pp asn1 => #<OpenSSL::ASN1::Sequence:0x87326e0
    #   #              @indefinite_length=false,
    #   #              @tag=16,
    #   #              @tag_class=:UNIVERSAL,
    #   #              @tagging=nil,
    #   #              @value=
    #   #                [#<OpenSSL::ASN1::ASN1Data:0x87326f4
    #   #                   @indefinite_length=false,
    #   #                   @tag=0,
    #   #                   @tag_class=:CONTEXT_SPECIFIC,
    #   #                   @value="\x01">]>
    #   raw_int = asn1.value[0]
    #   # manually rewrite tag and tag class to make it an UNIVERSAL value
    #   raw_int.tag = OpenSSL::ASN1::INTEGER
    #   raw_int.tag_class = :UNIVERSAL
    #   int2 = OpenSSL::ASN1.decode(raw_int)
    #   puts int2.value # => 1
    #
    # == Example - Decoding an explicitly tagged INTEGER
    #   int = OpenSSL::ASN1::Integer.new(1, 0, :EXPLICIT) # explicit 0-tagged
    #   seq = OpenSSL::ASN1::Sequence.new( [int] )
    #   der = seq.to_der
    #   asn1 = OpenSSL::ASN1.decode(der)
    #   # pp asn1 => #<OpenSSL::ASN1::Sequence:0x87326e0
    #   #              @indefinite_length=false,
    #   #              @tag=16,
    #   #              @tag_class=:UNIVERSAL,
    #   #              @tagging=nil,
    #   #              @value=
    #   #                [#<OpenSSL::ASN1::ASN1Data:0x87326f4
    #   #                   @indefinite_length=false,
    #   #                   @tag=0,
    #   #                   @tag_class=:CONTEXT_SPECIFIC,
    #   #                   @value=
    #   #                     [#<OpenSSL::ASN1::Integer:0x85bf308
    #   #                        @indefinite_length=false,
    #   #                        @tag=2,
    #   #                        @tag_class=:UNIVERSAL
    #   #                        @tagging=nil,
    #   #                        @value=1>]>]>
    #   int2 = asn1.value[0].value[0]
    #   puts int2.value # => 1
    #
    class ASN1Data
      #
      # Carries the value of a ASN.1 type.
      # Please confer Constructive and Primitive for the mappings between
      # ASN.1 data types and Ruby classes.
      #
      attr_accessor :value

      # An Integer representing the tag number of this ASN1Data. Never +nil+.
      attr_accessor :tag

      # A Symbol representing the tag class of this ASN1Data. Never +nil+.
      # See ASN1Data for possible values.
      attr_accessor :tag_class

      #
      # Never +nil+. A boolean value indicating whether the encoding uses
      # indefinite length (in the case of parsing) or whether an indefinite
      # length form shall be used (in the encoding case).
      # In DER, every value uses definite length form. But in scenarios where
      # large amounts of data need to be transferred it might be desirable to
      # have some kind of streaming support available.
      # For example, huge OCTET STRINGs are preferably sent in smaller-sized
      # chunks, each at a time.
      # This is possible in BER by setting the length bytes of an encoding
      # to zero and by this indicating that the following value will be
      # sent in chunks. Indefinite length encodings are always constructed.
      # The end of such a stream of chunks is indicated by sending a EOC
      # (End of Content) tag. SETs and SEQUENCEs may use an indefinite length
      # encoding, but also primitive types such as e.g. OCTET STRINGS or
      # BIT STRINGS may leverage this functionality (cf. ITU-T X.690).
      #
      attr_accessor :indefinite_length

      alias infinite_length indefinite_length
      alias infinite_length= indefinite_length=

      #
      # :call-seq:
      #    OpenSSL::ASN1::ASN1Data.new(value, tag, tag_class) => ASN1Data
      #
      # _value_: Please have a look at Constructive and Primitive to see how Ruby
      # types are mapped to ASN.1 types and vice versa.
      #
      # _tag_: An Integer indicating the tag number.
      #
      # _tag_class_: A Symbol indicating the tag class. Please cf. ASN1 for
      # possible values.
      #
      # == Example
      #   asn1_int = OpenSSL::ASN1Data.new(42, 2, :UNIVERSAL) # => Same as OpenSSL::ASN1::Integer.new(42)
      #   tagged_int = OpenSSL::ASN1Data.new(42, 0, :CONTEXT_SPECIFIC) # implicitly 0-tagged INTEGER
      #
      def initialize(value, tag, tag_class)
        raise ASN1Error, "invalid tag class" unless tag_class.is_a?(Symbol)

        @tag = tag
        @value = value
        @tag_class = tag_class
        @indefinite_length = false
      end

      #
      # :call-seq:
      #    asn1.to_der => DER-encoded String
      #
      # Encodes this ASN1Data into a DER-encoded String value. The result is
      # DER-encoded except for the possibility of indefinite length forms.
      # Indefinite length forms are not allowed in strict DER, so strictly speaking
      # the result of such an encoding would be a BER-encoding.
      #
      def to_der
        if @value.is_a?(Array)
          cons_to_der
        else
          prim_to_der
        end
      end

      private

      # :nodoc:
      def der_value
        raise TypeError, "no implicit conversion of #{self.class} into String" unless @value.respond_to?(:to_str)

        @value.to_str.b
      end

      def cons_to_der
        ary = @value.to_a

        return to_der_internal(nil, true) if ary.empty?

        str = +""

        ary.each_with_index do |item, idx|
          if @indefinite_length && item.is_a?(EndOfContent)
            if idx != ary.size - 1
              raise ASN1Error, "illegal EOC octets in value"
            end

            break
          end

          item = item.to_der if item.respond_to?(:to_der)

          str << item
        end

        to_der_internal(str, true)
      end

      def prim_to_der
        if @indefinite_length
          raise ASN1Error, "indefinite length form cannot be used " \
            "with primitive encoding"
        end
        to_der_internal(der_value)
      end

      def to_der_internal(body, constructed = false)
        tag = default_tag
        body_len = body ? body.size : 0

        if @tagging == :EXPLICIT
          raise ASN1Error, "explicit tagging of unknown tag" unless tag

          inner_obj = ASN1.put_object(constructed, @indefinite_length, body_len, tag, :UNIVERSAL)

          inner_len = body_len + inner_obj.size


          # Put explicit tag
          str = ASN1.put_object(true, @indefinite_length, inner_len, @tag, @tag_class) << inner_obj

          str << body if body
          if @indefinite_length
            str << "\x00\x00\x00\x00"
          end
        else
          str = ASN1.put_object(constructed, @indefinite_length, body_len, @tag, @tag_class)
          str << body if body
          if @indefinite_length
            str << "\x00\x00"
          end
        end

        str
      end

      def default_tag
        return unless self.class.const_defined?(:TAG)

        self.class::TAG
      end
    end

    module TaggedASN1Data
      def self.included(klass)
        klass.singleton_class.class_eval do
          def inherited(subklass)
            base_klassname = subklass.name.delete_prefix("OpenSSL::ASN1::")

            ASN1.define_singleton_method(base_klassname.to_sym) do |*args|
              subklass.new(*args)
            end
          end
        end
      end
      #
      # May be used as a hint for encoding a value either implicitly or
      # explicitly by setting it either to +:IMPLICIT+ or to +:EXPLICIT+.
      # _tagging_ is not set when a ASN.1 structure is parsed using
      # OpenSSL::ASN1.decode.
      #
      attr_accessor :tagging

      # :call-seq:
      #    OpenSSL::ASN1::Primitive.new(value [, tag, tagging, tag_class ]) => Primitive
      #
      # _value_: is mandatory.
      #
      # _tag_: optional, may be specified for tagged values. If no _tag_ is
      # specified, the UNIVERSAL tag corresponding to the Primitive sub-class
      # is used by default.
      #
      # _tagging_: may be used as an encoding hint to encode a value either
      # explicitly or implicitly, see ASN1 for possible values.
      #
      # _tag_class_: if _tag_ and _tagging_ are +nil+ then this is set to
      # +:UNIVERSAL+ by default. If either _tag_ or _tagging_ are set then
      # +:CONTEXT_SPECIFIC+ is used as the default. For possible values please
      # cf. ASN1.
      #
      # == Example
      #   int = OpenSSL::ASN1::Integer.new(42)
      #   zero_tagged_int = OpenSSL::ASN1::Integer.new(42, 0, :IMPLICIT)
      #   private_explicit_zero_tagged_int = OpenSSL::ASN1::Integer.new(42, 0, :EXPLICIT, :PRIVATE)
      #
      def initialize(value, tag = nil, tagging = nil, tag_class = nil)
        tag ||= default_tag

        raise ASN1Error, "must specify tag number" unless tag

        if tagging
          raise ASN1Error, "invalid tagging method" unless tagging.is_a?(Symbol)
        end

        tag_class ||= tagging ? :CONTEXT_SPECIFIC : :UNIVERSAL

        raise ASN1Error, "invalid tag class" unless tag_class.is_a?(Symbol)

        @tagging = tagging
        super(value ,tag, tag_class)
      end
    end

    #
    # The parent class for all primitive encodings. Attributes are the same as
    # for ASN1Data, with the addition of _tagging_.
    # Primitive values can never be encoded with indefinite length form, thus
    # it is not possible to set the _indefinite_length_ attribute for Primitive
    # and its sub-classes.
    #
    # == Primitive sub-classes and their mapping to Ruby classes
    # * OpenSSL::ASN1::EndOfContent    <=> _value_ is always +nil+
    # * OpenSSL::ASN1::Boolean         <=> _value_ is +true+ or +false+
    # * OpenSSL::ASN1::Integer         <=> _value_ is an OpenSSL::BN
    # * OpenSSL::ASN1::BitString       <=> _value_ is a String
    # * OpenSSL::ASN1::OctetString     <=> _value_ is a String
    # * OpenSSL::ASN1::Null            <=> _value_ is always +nil+
    # * OpenSSL::ASN1::Object          <=> _value_ is a String
    # * OpenSSL::ASN1::Enumerated      <=> _value_ is an OpenSSL::BN
    # * OpenSSL::ASN1::UTF8String      <=> _value_ is a String
    # * OpenSSL::ASN1::NumericString   <=> _value_ is a String
    # * OpenSSL::ASN1::PrintableString <=> _value_ is a String
    # * OpenSSL::ASN1::T61String       <=> _value_ is a String
    # * OpenSSL::ASN1::VideotexString  <=> _value_ is a String
    # * OpenSSL::ASN1::IA5String       <=> _value_ is a String
    # * OpenSSL::ASN1::UTCTime         <=> _value_ is a Time
    # * OpenSSL::ASN1::GeneralizedTime <=> _value_ is a Time
    # * OpenSSL::ASN1::GraphicString   <=> _value_ is a String
    # * OpenSSL::ASN1::ISO64String     <=> _value_ is a String
    # * OpenSSL::ASN1::GeneralString   <=> _value_ is a String
    # * OpenSSL::ASN1::UniversalString <=> _value_ is a String
    # * OpenSSL::ASN1::BMPString       <=> _value_ is a String
    #
    # == OpenSSL::ASN1::BitString
    #
    # === Additional attributes
    # _unused_bits_: if the underlying BIT STRING's
    # length is a multiple of 8 then _unused_bits_ is 0. Otherwise
    # _unused_bits_ indicates the number of bits that are to be ignored in
    # the final octet of the BitString's _value_.
    #
    # == OpenSSL::ASN1::ObjectId
    #
    # NOTE: While OpenSSL::ASN1::ObjectId.new will allocate a new ObjectId,
    # it is not typically allocated this way, but rather that are received from
    # parsed ASN1 encodings.
    #
    # === Additional attributes
    # * _sn_: the short name as defined in <openssl/objects.h>.
    # * _ln_: the long name as defined in <openssl/objects.h>.
    # * _oid_: the object identifier as a String, e.g. "1.2.3.4.5"
    # * _short_name_: alias for _sn_.
    # * _long_name_: alias for _ln_.
    #
    # == Examples
    # With the Exception of OpenSSL::ASN1::EndOfContent, each Primitive class
    # constructor takes at least one parameter, the _value_.
    #
    # === Creating EndOfContent
    #   eoc = OpenSSL::ASN1::EndOfContent.new
    #
    # === Creating any other Primitive
    #   prim = <class>.new(value) # <class> being one of the sub-classes except EndOfContent
    #   prim_zero_tagged_implicit = <class>.new(value, 0, :IMPLICIT)
    #   prim_zero_tagged_explicit = <class>.new(value, 0, :EXPLICIT)
    #
    class Primitive < ASN1Data
      include TaggedASN1Data

      undef_method :indefinite_length=
      undef_method :infinite_length=


      def to_der
        prim_to_der
      end
    end

    # The parent class for all constructed encodings. The _value_ attribute
    # of a Constructive is always an Array. Attributes are the same as
    # for ASN1Data, with the addition of _tagging_.
    #
    # == SET and SEQUENCE
    #
    # Most constructed encodings come in the form of a SET or a SEQUENCE.
    # These encodings are represented by one of the two sub-classes of
    # Constructive:
    # * OpenSSL::ASN1::Set
    # * OpenSSL::ASN1::Sequence
    # Please note that tagged sequences and sets are still parsed as
    # instances of ASN1Data. Find further details on tagged values
    # there.
    #
    # === Example - constructing a SEQUENCE
    #   int = OpenSSL::ASN1::Integer.new(1)
    #   str = OpenSSL::ASN1::PrintableString.new('abc')
    #   sequence = OpenSSL::ASN1::Sequence.new( [ int, str ] )
    #
    # === Example - constructing a SET
    #   int = OpenSSL::ASN1::Integer.new(1)
    #   str = OpenSSL::ASN1::PrintableString.new('abc')
    #   set = OpenSSL::ASN1::Set.new( [ int, str ] )
    #
    class Constructive < ASN1Data
      include TaggedASN1Data
      include Enumerable

      # :call-seq:
      #    asn1_ary.each { |asn1| block } => asn1_ary
      #
      # Calls the given block once for each element in self, passing that element
      # as parameter _asn1_. If no block is given, an enumerator is returned
      # instead.
      #
      # == Example
      #   asn1_ary.each do |asn1|
      #     puts asn1
      #   end
      #
      def each(&blk)
        @value.each(&blk)

        self
      end

      def to_der
        cons_to_der
      end
    end

    class Null < Primitive
      TAG = 5

      private

      # :nodoc:
      def der_value
        raise ASN1Error, "nil expected" unless @value == nil
      end
    end

    class Boolean < Primitive
      TAG = 1

      private

      # :nodoc:
      def der_value
        raise TypeError, "Can't convert nil into Boolean" if @value.nil?

        @value ? "\xff" : "\x00"
      end
    end

    class Integer < Primitive
      TAG = 2

      private

      # :nodoc:
      def der_value
        ASN1.put_integer(@value)
      end
    end

    class Enumerated < Primitive
      TAG = 10

      private

      # :nodoc:
      def der_value
        ASN1.put_integer(@value)
      end
    end

    class BitString < Primitive
      TAG = 3

      attr_accessor :unused_bits

      def initialize(*)
        super

        @unused_bits = 0
      end

      private

      # :nodoc:
      def der_value
        if @unused_bits < 0 || @unused_bits > 7
          raise ASN1Error,  "unused_bits for a bitstring value must be in " \
		        "the range 0 to 7"
        end

        return "\x00" if @value.empty?

        @unused_bits.chr.force_encoding(Encoding::BINARY) << super
      end
    end

    class OctetString < Primitive
      TAG = 4
    end

    class UTF8String < Primitive
      TAG = 12
    end

    class NumericString < Primitive
      TAG = 18
    end

    class PrintableString < Primitive
      TAG = 19
    end

    class T61String < Primitive
      TAG = 20
    end

    class VideotexString < Primitive
      TAG = 21
    end

    class IA5String < Primitive
      TAG = 22
    end

    class GraphicString < Primitive
      TAG = 25
    end

    class ISO64String < Primitive
      TAG = 26
    end

    class GeneralString < Primitive
      TAG = 27
    end

    class UniversalString < Primitive
      TAG = 28
    end

    class BMPString < Primitive
      TAG = 30
    end

    #
    # Represents the primitive object id for OpenSSL::ASN1
    #
    class ObjectId < Primitive
      TAG = 6

      private

      # :nodoc:
      def der_value
        value = oid

        dot_index = value.index(".")

        if dot_index == value.size - 1
          return (value.to_i * 40).chr.force_encoding(Encoding::BINARY)
        else
          codes = [value.byteslice(0..dot_index-1).to_i * 40]
        end

        add_to_top = false
        value.byteslice(dot_index+1..-1).split(".") do |sub|
          if add_to_top
            codes << sub.to_i
          else
            codes[0] += sub.to_i
            add_to_top = true
          end
        end

        codes.pack("w*")
      end
    end

    class UTCTime < Primitive
      TAG = 23

      private

      YEAR_RANGE = 1950..2049
      private_constant :YEAR_RANGE

      # :nodoc:
      def der_value
        value = if @value.is_a?(Time)
          @value
        else
          Time.at(Integer(@value))
        end.utc

        raise OpenSSL::ASN1::ASN1Error unless YEAR_RANGE.include?(value.year)

        value.strftime("%y%m%d%H%M%SZ")
      end
    end

    class GeneralizedTime < Primitive
      TAG = 24

      private

      # :nodoc:
      def der_value
        value = if @value.is_a?(Time)
          @value
        else
          Time.at(Integer(@value))
        end.utc

        # per  In X.680 (02/2021) section 46: the year has to be exactly 4 digits for GeneralizedTime.
        raise OpenSSL::ASN1::ASN1Error unless value.year < 10_000

        value.strftime("%Y%m%d%H%M%SZ")
      end
    end

    class EndOfContent < ASN1Data
      TAG = 0

      def initialize
        super("", 0, :UNIVERSAL)
      end

      def to_der
        "\x00\x00"
      end
    end

    class Set < Constructive
      TAG = 17
    end

    class Sequence < Constructive
      TAG = 16
    end

    module_function

    # ruby port of openssl ASN1_put_object
    # :nodoc:
    def put_object(constructed, indefinite_length, length, tag, tag_class)
      xclass = take_asn1_tag_class(tag_class)

      i = constructed ? 0x20 : 0
      i |= (xclass & 0xc0) # PRIVATE

      if tag < 31
        str = (i | tag).chr.force_encoding(Encoding::BINARY)

      else
        str = [i | 0x1f, tag].pack("Cw")
      end

      if constructed && indefinite_length
        str << "\x80"
      else
        str << put_length(length)
      end
      str
    end

    # :nodoc:
    def put_length(length)
      if length < 0x80
        length.chr.force_encoding(Encoding::BINARY)
      else
        data = length.to_bn.to_s(2)
        [data.size | 0x80].pack("C") << data
      end
    end

    # :nodoc:
    def put_integer(value)
      raise TypeError, "Can't convert nil into OpenSSL::BN" if value.nil?

      if value >= 0
        data = value.to_bn.to_s(2)
        data.prepend("\x00") if data.empty? || data.getbyte(0) >= 0x80
      else
        value = value.to_bn
        value += (1 << (value.num_bits + 7) / 8 * 8)
        data = value.to_s(2)
        data.prepend("\xff") if data.empty? || data.getbyte(0) < 0x80
      end

      data
    end

    EOC = EndOfContent::TAG
    BOOLEAN = Boolean::TAG
    INTEGER = Integer::TAG
    BIT_STRING = BitString::TAG
    OCTET_STRING = OctetString::TAG
    NULL = Null::TAG
    OBJECT = ObjectId::TAG
    OBJECT_DESCRIPTOR = 7
    EXTERNAL = 8
    REAL = 9
    ENUMERATED = Enumerated::TAG
    EMBEDDED_PDV = 11
    UTF8STRING = UTF8String::TAG
    RELATIVE_OID = 13
    # [UNIVERSAL 14] = 14
    # [UNIVERSAL 15] = 15
    SEQUENCE = Sequence::TAG
    SET = Set::TAG
    NUMERICSTRING = NumericString::TAG
    PRINTABLESTRING = PrintableString::TAG
    T61STRING = T61String::TAG
    VIDEOTEXSTRING = VideotexString::TAG
    IA5STRING = IA5String::TAG
    UTCTIME = UTCTime::TAG
    GENERALIZEDTIME = GeneralizedTime::TAG
    GRAPHICSTRING = GraphicString::TAG
    ISO64STRING = ISO64String::TAG
    GENERALSTRING = GeneralString::TAG
    UNIVERSALSTRING = UniversalString::TAG
    CHARACTER_STRING = 29
    BMPSTRING = BMPString::TAG

    # :nodoc:
    TAG_CLASS_TYPES = {
      UNIVERSAL: 0x00,
      APPLICATION: 0x40,
      CONTEXT_SPECIFIC: 0x80,
      PRIVATE: 0xc0
    }
    private_constant :TAG_CLASS_TYPES

    # from ossl_asn1.c : ossl_asn1_tag_class
    # :nodoc:
    def take_asn1_tag_class(tag_class)
      tag_class ||= :UNIVERSAL

      TAG_CLASS_TYPES.fetch(tag_class) do
        raise ASN1Error,  "invalid tag class"
      end
    end

    #
    # call-seq:
    #    OpenSSL::ASN1.decode_all(der) -> Array of ASN1Data
    #
    # Similar to #decode with the difference that #decode expects one
    # distinct value represented in _der_. #decode_all on the contrary
    # decodes a sequence of sequential BER/DER values lined up in _der_
    # and returns them as an array.
    #
    # == Example
    #   ders = File.binread('asn1data_seq')
    #   asn1_ary = OpenSSL::ASN1.decode_all(ders)
    #
    def decode_all(data)
      data = data.to_der if data.respond_to?(:to_der)

      datalen = data.size

      objs = []

      loop do
        obj, data = decode0(data)

        if obj.nil?
          raise ASN1Error, "Type mismatch. Total bytes read: #{datalen} Bytes available: #{data.size} Offset: #{datalen - data.size}"
        end

        objs << obj

        break if data.nil? || data.empty?
      end

      objs
    end

    #
    # call-seq:
    #    OpenSSL::ASN1.traverse(asn1) -> nil
    #
    # If a block is given, it prints out each of the elements encountered.
    # Block parameters are (in that order):
    # * depth: The recursion depth, plus one with each constructed value being encountered (Integer)
    # * offset: Current byte offset (Integer)
    # * header length: Combined length in bytes of the Tag and Length headers. (Integer)
    # * length: The overall remaining length of the entire data (Integer)
    # * constructed: Whether this value is constructed or not (Boolean)
    # * tag_class: Current tag class (Symbol)
    # * tag: The current tag number (Integer)
    #
    # == Example
    #   der = File.binread('asn1data.der')
    #   OpenSSL::ASN1.traverse(der) do | depth, offset, header_len, length, constructed, tag_class, tag|
    #     puts "Depth: #{depth} Offset: #{offset} Length: #{length}"
    #     puts "Header length: #{header_len} Tag: #{tag} Tag class: #{tag_class} Constructed: #{constructed}"
    #   end
    #
    def traverse(der, &blk)
      raise LocalJumpError unless blk

      _, remaining = decode0(der, &blk)

      unless remaining.nil? || remaining.empty?
        total_read = der.size - remaining.size
        raise ASN1Error, "Type mismatch. Total bytes read: #{total_read} Bytes available: #{remaining.size} Offset: #{total_read}"
      end

      nil
    end

    #
    # call-seq:
    #    OpenSSL::ASN1.decode(der) -> ASN1Data
    #
    # Decodes a BER- or DER-encoded value and creates an ASN1Data instance. _der_
    # may be a String or any object that features a +.to_der+ method transforming
    # it into a BER-/DER-encoded String+
    #
    # == Example
    #   der = File.binread('asn1data')
    #   asn1 = OpenSSL::ASN1.decode(der)
    #
    def decode(data)
      decode0(data).first
    end

    # :nodoc:
    def decode0(data, depth = 0, offset = 0, &block)
      data = data.to_der if data.respond_to?(:to_der)

      first_byte, length = data.unpack('CC')
      length_bytes = 1
      tag_class = TAG_CLASS_TYPES.key(first_byte & 0xc0) || :UNIVERSAL
      is_constructed = first_byte.anybits?(0x20)
      is_indefinite_length = length == 0x80 # indefinite length
      number = first_byte & 0x1f

      no_id_idx = if number == 0x1f
        number = 0
        count = 1
        data[1..].each_byte do |byte|
          count += 1

          number = (number << 7) | (byte & 0x7f)
          break if byte.nobits?(0x80)
        end
        length = data.getbyte(count)
        count
      else
        1
      end

      value = if is_indefinite_length
        unless is_constructed
          raise ASN1Error, "indefinite length for primitive value"
        end

        data[no_id_idx + 1..-1]
      elsif length > 0x80
        # ASN.1 says this octet can't be 0xff
        raise ASN1Error, "invalid length" if length == 0xff
        length_bytes = length & 0x7f
        length = data[no_id_idx + 1, length_bytes].unpack('C*').reduce(0) { |len, b| (len << 8) | b }
        data[no_id_idx + length_bytes + 1..-1]
      else
        data[no_id_idx + 1..-1]
      end

      hlength = no_id_idx + length_bytes

      if is_constructed
        decode_cons(tag_class, number, hlength, length, value, is_indefinite_length, depth, offset, &block)
      else
        decode_prim(tag_class, number, hlength, length, value, depth, offset, &block)
      end
    end

    # :nodoc:
    def decode_cons(tag_class, number, hlength, length, data, is_indefinite_length, depth, offset, &block)
      datalen = data.size

      if is_indefinite_length
        remaining = nil

      else
        remaining = data[length..-1]
        data = data[0, length]

        if length > datalen
          raise ASN1Error, "too long"
        end
      end

      traverse0(depth, offset, hlength, length == 0x80 ? 0 : length, true, tag_class, number, &block) if block

      offset += hlength

      objs = []
      has_eoc = false
      until data.nil? || data.empty?
        datalen = data.size

        obj, data = decode0(data, depth + 1, offset, &block)

        offset += datalen
        offset -= data.size if data

        case obj
        when EndOfContent
          has_eoc = true

          break if is_indefinite_length

          objs << obj

          break
        else
          objs << obj
        end
      end

      if is_indefinite_length && !has_eoc
        raise ASN1Error, "missing EOC"
      end

      obj = if tag_class == :UNIVERSAL
        case number
        when SEQUENCE
          Sequence.new(objs, number, nil, tag_class)
        when SET
          Set.new(objs, number, nil, tag_class)
        else
          Constructive.new(objs, number, nil, tag_class)
        end
      else
        ASN1Data.new(objs, number, tag_class)
      end
      obj.indefinite_length = is_indefinite_length

      if data && !data.empty?
        if remaining.nil?
          remaining = data
        else
          remaining << data
        end
      end

      return obj, remaining
    end

    # :nodoc:
    def decode_prim(tag_class, number, hlength, length, data, depth, offset, &block)
      remaining = data[length..-1]
      data = data[0, length]

      traverse0(depth, offset, hlength, length, false, tag_class, number, &block) if block

      offset += hlength

      obj = if tag_class == :UNIVERSAL
        case number
        when EOC
          if length != 0 || !data.empty?
            raise ASN1Error, "too long"
          end
          EndOfContent.new
        when BOOLEAN
          if length < 1
            raise ASN1Error, "invalid length for BOOLEAN"
          elsif length > 1
            raise ASN1Error, "too long"
          else
            Boolean.new(data != "\x00", number, nil, tag_class)
          end
        when INTEGER
          value = data.unpack('C*').reduce(0) { |len, b| (len << 8) | b }
          if data[0].ord[7] == 1
            value -= (1 << (8 * length))
          end
          OpenSSL::ASN1::Integer.new(value.to_bn, number, nil, tag_class)
        when BIT_STRING
          if data.empty?
            raise ASN1Error, "string too short"
          end
          unused = data.unpack1('C')
          if (unused > 7)
            raise ASN1Error, "invalid bit string bits left"
          end
          str = data.byteslice(1..-1) || ""
          BitString.new(str, number, nil, tag_class).tap do |b|
            b.unused_bits = unused
          end
        when OCTET_STRING
          OctetString.new(data, number, nil, tag_class)
        when NULL
          unless length.zero?
            raise ASN1Error, "null is wrong length"
          end

          Null.new(nil, number, nil, tag_class)
        when OBJECT
          top, *codes = data.unpack("w*")

          if top
            first = [2, top / 40].min
            second = top - first * 40
            codes = [first, second, *codes]
          else
            raise ASN1Error, "invalid object encoding"
          end

          obj = ObjectId.new(codes.join("."), number, nil, tag_class)

          if (sn = obj.sn)
            # on decoding, if there's a short name in the table, then
            # that's the value
            obj.value = sn
          end
          obj
        # when 7 # V_ASN1_OBJECT_DESCRIPTOR
        # when 8 # EXTERNAL
        # when 9 # REAL
        when ENUMERATED
          value = data.unpack('C*').reduce(0) { |len, b| (len << 8) | b }
          if data[0].ord[7] == 1
            value -= (1 << (8 * length))
          end
          OpenSSL::ASN1::Enumerated.new(value.to_bn, number, nil, tag_class)
        when UTF8STRING
          UTF8String.new(data, number, nil, tag_class)
        when NUMERICSTRING
          NumericString.new(data, number, nil, tag_class)
        when PRINTABLESTRING
          PrintableString.new(data, number, nil, tag_class)
        when T61STRING
          T61String.new(data, number, nil, tag_class)
        when VIDEOTEXSTRING
          VideotexString.new(data, number, nil, tag_class)
        when IA5STRING
          IA5String.new(data, number, nil, tag_class)
        when UTCTIME
          unless (c = /\A(?<year>\d{2})(?<month>\d{2})(?<day>\d{2})(?<hour>\d{2})(?<min>\d{2})(?<sec>\d{2})Z\z/.match(data))
            raise ASN1Error, "too long"
          end
          year = c[:year].to_i
          year = year > 49 ? 1900 + year : 2000 + year
          time = Time.utc(year, c[:month], c[:day], c[:hour], c[:min], c[:sec])
          UTCTime.new(time, number, nil, tag_class)
        when GENERALIZEDTIME
          unless (c = /\A(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})(?<hour>\d{2})(?<min>\d{2})(?<sec>\d{2})Z\z/.match(data))
            raise ASN1Error, "too long"
          end
          time = Time.utc(c[:year], c[:month], c[:day], c[:hour], c[:min], c[:sec])
          GeneralizedTime.new(time, number, nil, tag_class)
        when GRAPHICSTRING
          GraphicString.new(data, number, nil, tag_class)
        when ISO64STRING
          ISO64String.new(data, number, nil, tag_class)
        when GENERALSTRING
          GeneralString.new(data, number, nil, tag_class)
        when UNIVERSALSTRING
          UniversalString.new(data, number, nil, tag_class)
        when BMPSTRING
          BMPString.new(data, number, nil, tag_class)
        else
          ASN1Data.new(data, number, tag_class)
        end
      else
        ASN1Data.new(data, number, tag_class)
      end

      return obj, remaining
    end

    def traverse0(depth, offset, hlength, length, is_constructed, tag_class, number, &block)
      elems = [
        depth, offset,
        hlength, length,
        is_constructed,
        tag_class,
        number
      ]

      arity = block.arity
      if arity == 1
        block.call(elems)
      else
        if arity < elems.size
          elems = elems[0, arity]
        end

        yield elems
      end
    end
  end
end
