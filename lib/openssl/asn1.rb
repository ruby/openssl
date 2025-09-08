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
        default_tag = ASN1.take_default_tag(self.class)
        body_len = body ? body.size : 0

        if @tagging == :EXPLICIT
          raise ASN1Error, "explicit tagging of unknown tag" unless default_tag

          inner_obj = ASN1.put_object(constructed, @indefinite_length, body_len, default_tag, :UNIVERSAL)

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
      private

      # :nodoc:
      def der_value
        raise ASN1Error, "nil expected" unless @value == nil
      end
    end

    class Boolean < Primitive
      private

      # :nodoc:
      def der_value
        raise TypeError, "Can't convert nil into Boolean" if @value.nil?

        @value ? "\xff" : "\x00"
      end
    end

    class Integer < Primitive
      private

      # :nodoc:
      def der_value
        ASN1.put_integer(@value)
      end
    end

    class Enumerated < Primitive
      private

      # :nodoc:
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
      def initialize
        super("", 0, :UNIVERSAL)
      end

      def to_der
        "\x00\x00"
      end
    end

    class Set < Constructive
    end

    class Sequence < Constructive

    end

    module_function

    # ruby port of openssl ASN1_put_object
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


    def put_length(length)
      if length < 0x80
        length.chr.force_encoding(Encoding::BINARY)
      else
        data = length.to_bn.to_s(2)
        [data.size | 0x80].pack("C") << data
      end
    end

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

    # :nodoc:
    def take_default_tag(klass)
      tag = CLASS_TAG_MAP[klass]

      return tag if tag

      sklass = klass.superclass

      return unless sklass

      take_default_tag(sklass)
    end

    # :nodoc:
    TAG_CLASS_TYPES = {
      UNIVERSAL: 0x00,
      APPLICATION: 0x40,
      CONTEXT_SPECIFIC: 0x80,
      PRIVATE: 0xc0
    }
    private_constant :TAG_CLASS_TYPES

    # from ossl_asn1.c : ossl_asn1_tag_class
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

    def traverse(der, &blk)
      raise LocalJumpError unless blk

      _, remaining = decode0(der, &blk)

      unless remaining.nil? || remaining.empty?
        total_read = der.size - remaining.size
        raise ASN1Error, "Type mismatch. Total bytes read: #{total_read} Bytes available: #{remaining.size} Offset: #{total_read}"
      end

      nil
    end

    def decode(data)
      decode0(data).first
    end

    def decode0(data, depth = 0, offset = 0, &block)
      data = data.to_der if data.respond_to?(:to_der)

      first_byte, length = data.unpack('CC')
      length_bytes = 1
      tag_class = TAG_CLASS_TYPES.key(first_byte & 0xc0) || :UNIVERSAL
      is_constructed = first_byte.anybits?(0x20)
      is_indefinite_length = length == 0x80 # indefinite length
      id = first_byte & 0x1f

      no_id_idx = if id == 0x1f
        id = 0
        count = 1
        data[1..].each_byte do |byte|
          count += 1

          id = (id << 7) | (byte & 0x7f)
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
        decode_cons(tag_class, id, hlength, length, value, is_indefinite_length, depth, offset, &block)
      else
        decode_prim(tag_class, id, hlength, length, value, depth, offset, &block)
      end
    end

    def decode_cons(tag_class, id, hlength, length, data, is_indefinite_length, depth, offset, &block)
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

      traverse0(depth, offset, hlength, length == 0x80 ? 0 : length, true, tag_class, id, &block) if block

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
        case id
        when 16 # Sequence
          Sequence.new(objs, id, nil, tag_class)
        when 17 # Set
          Set.new(objs, id, nil, tag_class)
        else
          Constructive.new(objs, id, nil, tag_class)
        end
      else
        ASN1Data.new(objs, id, tag_class)
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

    def decode_prim(tag_class, id, hlength, length, data, depth, offset, &block)
      remaining = data[length..-1]
      data = data[0, length]

      traverse0(depth, offset, hlength, length, false, tag_class, id, &block) if block

      offset += hlength

      obj = if tag_class == :UNIVERSAL
        case id
        when 0 # EOC
          if length != 0 || !data.empty?
            raise ASN1Error, "too long"
          end
          EndOfContent.new
        when 1 # BOOLEAN
          if length < 1
            raise ASN1Error, "invalid length for BOOLEAN"
          elsif length > 1
            raise ASN1Error, "too long"
          else
            Boolean.new(data != "\x00", id, nil, tag_class)
          end
        when 2 # INTEGER
          number = data.unpack('C*').reduce(0) { |len, b| (len << 8) | b }
          if data[0].ord[7] == 1
            number -= (1 << (8 * length))
          end
          OpenSSL::ASN1::Integer.new(number.to_bn, id, nil, tag_class)
        when 3 # BIT_STRING
          if data.empty?
            raise ASN1Error, "string too short"
          end
          unused = data.unpack1('C')
          if (unused > 7)
            raise ASN1Error, "invalid bit string bits left"
          end
          str = data.byteslice(1..-1) || ""
          BitString.new(str, id, nil, tag_class).tap do |b|
            b.unused_bits = unused
          end
        when 4 # OCTET_STRING
          OctetString.new(data, id, nil, tag_class)
        when 5 # NULL
          unless length.zero?
            raise ASN1Error, "null is wrong length"
          end

          Null.new(nil, id, nil, tag_class)
        when 6 # OBJECT
          top, *codes = data.unpack("w*")

          if top
            first = [2, top / 40].min
            second = top - first * 40
            codes = [first, second, *codes]
          else
            raise ASN1Error, "invalid object encoding"
          end

          obj = ObjectId.new(codes.join("."), id, nil, tag_class)

          if (sn = obj.sn)
            # on decoding, if there's a short name in the table, then
            # that's the value
            obj.value = sn
          end
          obj
        # when 7 # V_ASN1_OBJECT_DESCRIPTOR
        # when 8 # EXTERNAL
        # when 9 # REAL
        when 10 # ENUMERATED
          number = data.unpack('C*').reduce(0) { |len, b| (len << 8) | b }
          if data[0].ord[7] == 1
            number -= (1 << (8 * length))
          end
          OpenSSL::ASN1::Enumerated.new(number.to_bn, id, nil, tag_class)
        when 12 # UTF8String
          UTF8String.new(data, id, nil, tag_class)
        when 18
          NumericString.new(data, id, nil, tag_class)
        when 19
          PrintableString.new(data, id, nil, tag_class)
        when 20
          T61String.new(data, id, nil, tag_class)
        when 21
          VideotexString.new(data, id, nil, tag_class)
        when 22
          IA5String.new(data, id, nil, tag_class)
        when 23
          unless (c = /\A(?<year>\d{2})(?<month>\d{2})(?<day>\d{2})(?<hour>\d{2})(?<min>\d{2})(?<sec>\d{2})Z\z/.match(data))
            raise ASN1Error, "too long"
          end
          year = c[:year].to_i
          year = year > 49 ? 1900 + year : 2000 + year
          time = Time.utc(year, c[:month], c[:day], c[:hour], c[:min], c[:sec])
          UTCTime.new(time, id, nil, tag_class)
        when 24
          unless (c = /\A(?<year>\d{4})(?<month>\d{2})(?<day>\d{2})(?<hour>\d{2})(?<min>\d{2})(?<sec>\d{2})Z\z/.match(data))
            raise ASN1Error, "too long"
          end
          time = Time.utc(c[:year], c[:month], c[:day], c[:hour], c[:min], c[:sec])
          GeneralizedTime.new(time, id, nil, tag_class)
        when 25
          GraphicString.new(data, id, nil, tag_class)
        when 26
          ISO64String.new(data, id, nil, tag_class)
        when 27
          GeneralString.new(data, id, nil, tag_class)
        when 28
          UniversalString.new(data, id, nil, tag_class)
        when 30
          BMPString.new(data, id, nil, tag_class)
        else
          ASN1Data.new(data, id, tag_class)
        end
      else
        ASN1Data.new(data, id, tag_class)
      end

      return obj, remaining
    end

    def traverse0(depth, offset, hlength, length, is_constructed, tag_class, id, &block)
      elems = [
        depth, offset,
        hlength, length,
        is_constructed,
        tag_class,
        id
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
