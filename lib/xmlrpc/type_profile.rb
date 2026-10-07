# frozen_string_literal: false
#
# Type profiles for XML-RPC for Ruby.
#
# A XMLRPC::TypeProfile describes, per client or server instance, which
# XML-RPC types and extensions the encoder (XMLRPC::Create) and the parser
# (XMLRPC::XMLParser) accept. Encoder and parser of one instance share the
# same profile object, so nothing depends on mutating XMLRPC::Config
# globals.
#

module XMLRPC # :nodoc:

  # Controlled representation of an XML-RPC value whose tag is not
  # understood by the current type profile.
  #
  # When a profile keeps unknown extensions
  # (TypeProfile.new(unknown_extension: :keep)), an unknown tag is
  # returned as an instance of this class instead of raising, and never
  # as an instance of an arbitrary Ruby class derived from the tag name.
  class UnknownValue
    attr_reader :tag, :content

    def initialize(tag, content)
      @tag = tag.to_s
      @content = content
    end

    def ==(other)
      other.instance_of?(self.class) &&
        other.tag == @tag && other.content == @content
    end
    alias eql? ==

    def hash
      [self.class, @tag, @content].hash
    end

    def inspect
      "#<XMLRPC::UnknownValue tag=#{@tag.inspect} content=#{@content.inspect}>"
    end
  end

  # Describes which XML-RPC types and extensions one client or server
  # instance accepts when encoding and decoding values.
  #
  # Two ready-made profiles are provided:
  #
  # * XMLRPC::TypeProfile::STANDARD - only the standard XML-RPC types
  #   (32-bit i4/int, boolean, string, double, dateTime.iso8601, base64,
  #   array, struct). Unknown tags are rejected.
  # * XMLRPC::TypeProfile::EXTENDED - additionally accepts i8 (64-bit
  #   integers), nil and decimal (exact XMLRPC::Decimal), and keeps
  #   unknown tags as XMLRPC::UnknownValue.
  #
  # Custom profiles can be built with TypeProfile.new, e.g.
  #
  #   profile = XMLRPC::TypeProfile.new(i8: true, nil_value: true)
  #   client.set_type_profile(profile)
  class TypeProfile

    INT4_MIN = -(2**31)
    INT4_MAX = 2**31 - 1
    INT8_MIN = -(2**63)
    INT8_MAX = 2**63 - 1

    # Optional name of the profile (e.g. "standard"), only informational.
    attr_reader :name

    # Creates a new type profile.
    #
    # * +i8+: allow the <code><i8></code> tag for 64-bit integers.
    # * +nil_value+: allow the <code><nil/></code> extension tag.
    # * +decimal+: allow the <code><decimal></code> extension tag for
    #   exact decimal numbers (XMLRPC::Decimal), which are never
    #   converted through Float.
    # * +unknown_extension+: either +:reject+ (raise on unknown tags) or
    #   +:keep+ (return them as XMLRPC::UnknownValue).
    def initialize(name=nil, i8: false, nil_value: false, decimal: false,
                   unknown_extension: :reject)
      unless [:reject, :keep].include?(unknown_extension)
        raise ArgumentError,
              "unknown_extension must be :reject or :keep, got #{unknown_extension.inspect}"
      end
      @name = name
      @i8 = i8 ? true : false
      @nil_value = nil_value ? true : false
      @decimal = decimal ? true : false
      @unknown_extension = unknown_extension
    end

    def allow_i8?
      @i8
    end

    def allow_nil?
      @nil_value
    end

    def allow_decimal?
      @decimal
    end

    def keep_unknown_extension?
      @unknown_extension == :keep
    end

    # Returns the XML-RPC tag to use for the Integer +value+ according to
    # its range and this profile's capabilities ("i4" or "i8"), or +nil+
    # when +value+ cannot be represented.
    def integer_tag(value)
      if value >= INT4_MIN && value <= INT4_MAX
        "i4"
      elsif @i8 && value >= INT8_MIN && value <= INT8_MAX
        "i8"
      else
        nil
      end
    end

    # Standard XML-RPC types only.
    STANDARD = new("standard")

    # Standard types plus i8, nil and decimal; unknown tags are kept as
    # XMLRPC::UnknownValue.
    EXTENDED = new("extended", i8: true, nil_value: true, decimal: true,
                   unknown_extension: :keep)

    [STANDARD, EXTENDED].each(&:freeze)
  end

end
