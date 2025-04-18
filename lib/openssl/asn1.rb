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
  module ASN1
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
      # call-seq:
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
        elsif @indefinite_length
          raise ASN1Error, "indefinite length form cannot be used " \
		        "with primitive encoding"
        else
          to_der_internal(der_value)
        end
      end

      def der_value
        raise TypeError, "no implicit conversion of #{self.class} into String" unless @value.respond_to?(:to_str)

        @value.to_str.b
      end

      private

      def cons_to_der
        ary = @value.to_a
        str = "".b

        @value.each_with_index do |item, idx|
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
        to_der_internal(der_value)
      end

      def to_der_internal(body, constructed = false)
        default_tag = ASN1.take_default_tag(self.class)
        body.force_encoding(Encoding::BINARY)
        body_len = body.size

        if @tagging == :EXPLICIT
          raise ASN1Error, "explicit tagging of unknown tag" unless default_tag

          inner_obj = ASN1.put_object(constructed, @indefinite_length, body_len, default_tag, :UNIVERSAL)

          inner_len = body_len + inner_obj.size


          # Put explicit tag
          str = ASN1.put_object(true, @indefinite_length, inner_len, @tag, @tag_class) << inner_obj
                # Append inner object


          str << body
          if @indefinite_length
            str << "\x00\x00\x00\x00".b
          end
        else
          str = ASN1.put_object(constructed, @indefinite_length, body_len, @tag, @tag_class)
          str << body
          if @indefinite_length
            str << "\x00\x00".b
          end
        end

        str
      end
    end

    module TaggedASN1Data
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
        tag ||= ASN1.take_default_tag(self.class)

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

    class Primitive < ASN1Data
      include TaggedASN1Data

      undef_method :indefinite_length=
      undef_method :infinite_length=


      def to_der
        prim_to_der
      end
    end

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
      def der_value
        "".b
      end
    end

    class Boolean < Primitive
      def der_value
        raise TypeError, "Can't convert nil into Boolean" if @value.nil?

        @value ? "\xff".b : "\x00".b
      end
    end

    class Integer < Primitive
      def der_value
        ASN1.put_integer(@value)
      end
    end

    class Enumerated < Primitive
      def der_value
        ASN1.put_integer(@value)
      end
    end

    class BitString < Primitive
      attr_accessor :unused_bits

      def initialize(*)
        super

        @unused_bits = 0
      end

      def der_value
        if @unused_bits < 0 || @unused_bits > 7
          raise ASN1Error,  "unused_bits for a bitstring value must be in " \
		        "the range 0 to 7"
        end

        return "\x00".b if @value.empty?

        @unused_bits.chr << super
      end
    end

    class OctetString < Primitive
    end

    class UTF8String < Primitive
    end

    class NumericString < Primitive
    end

    class PrintableString < Primitive
    end

    class T61String < Primitive
    end

    class VideotexString < Primitive
    end

    class IA5String < Primitive
    end

    class GraphicString < Primitive
    end

    class ISO64String < Primitive
    end

    class GeneralString < Primitive
    end

    class UniversalString < Primitive
    end

    class BMPString < Primitive
    end

    class ObjectId < Primitive
      def der_value
        value = oid.split(".").map(&:to_i)

        return (40 * value[0]).chr if value.length == 1

        [value[0] * 40 + value[1], *value[2..]].pack("w*")
      end
    end

    class UTCTime < Primitive
      FORMAT = "%y%m%d%H%M%SZ".b.freeze

      def der_value
        value = if @value.is_a?(Time)
          @value
        else
          Time.at(Integer(@value))
        end

        value.utc.strftime(FORMAT)
      end
    end

    class GeneralizedTime < Primitive
      FORMAT = "%Y%m%d%H%M%SZ".b.freeze
      def der_value
        value = if @value.is_a?(Time)
          @value
        else
          Time.at(Integer(@value))
        end

        value.utc.strftime(FORMAT)
      end
    end

    class EndOfContent < ASN1Data
      def initialize
        super("", 0, :UNIVERSAL)
      end

      def to_der
        "\x00\x00".b
      end
    end

    class Set < Constructive
    end

    class Sequence < Constructive

    end

    module_function

    # ruby port of openssl ASN1_put_object
    def put_object(constructed, indefinite_length, length, tag, tag_class)
      str = "".b
      xclass = take_asn1_tag_class(tag_class)

      i = constructed ? 0x20 : 0
      i |= (xclass & 0xc0) # PRIVATE

      if tag < 31
        str << (i | tag).chr

      else
        str << [i | 0x1f, tag].pack("Cw")
      end

      if constructed && indefinite_length
        str << 0x80.chr
      else
        str << put_length(length)
      end
      str
    end


    def put_length(length)
      if length < 0x80
        length.chr
      else
        data = integer_to_octets(length)
        (data.size | 0x80).chr << data
      end
    end

    def put_integer(value)
      raise TypeError, "Can't convert nil into OpenSSL::BN" if value.nil?

      value = value.to_bn
      if value >= 0
        data = value.to_s(2)
        data.prepend("\x00".b) if data.empty? || data.getbyte(0) >= 0x80
      else
        value = (1.to_bn << (value.num_bits + 7) / 8 * 8) + value
        data = value.to_s(2)
        data.prepend("\xff".b) if data.empty? || data.getbyte(0) < 0x80
      end

      data
    end

    def integer_to_octets(i)
      if i >= 0
        done = 0
      else
        done = -1
      end
      octets = "".b
      begin
        octets = (i & 0xff).chr << octets
        i = i >> 8
      end until i == done
      octets
    end

    # :nodoc:
    def take_default_tag(klass)
      tag = CLASS_TAG_MAP[klass]

      return tag if tag

      sklass = klass.superclass

      return unless sklass

      take_default_tag(sklass)
    end

    # from ossl_asn1.c : ossl_asn1_tag_class
    def take_asn1_tag_class(tag_class)
      case tag_class
      when :UNIVERSAL, nil then 0x00
      when :APPLICATION then 0x40
      when :CONTEXT_SPECIFIC then 0x80
      when :PRIVATE then 0xc0
      else
        raise ASN1Error,  "invalid tag class"
      end
    end
  end
end
