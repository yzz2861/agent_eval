# frozen_string_literal: false
#
# Instance-level type profiles for XML-RPC for Ruby.
#
# A XMLRPC::TypeProfile describes, for one client or server instance, which
# XML-RPC value types its encoder and parser accept. The same profile object
# is shared by the encoder (XMLRPC::Create) and the parser of an instance, so
# both directions obey one explicit configuration instead of the global
# XMLRPC::Config constants.
#

module XMLRPC # :nodoc:

  # Controlled representation of a XML-RPC value whose tag is not supported
  # by the active XMLRPC::TypeProfile.
  #
  # Instances of this class are only created by the parser when the profile's
  # unknown-extension policy is XMLRPC::TypeProfile::PRESERVE_UNKNOWN. The
  # tag name is never resolved to a Ruby class; the value is kept as opaque
  # data (tag name plus text content).
  class UnknownValue
    # The XML-RPC tag name of the unhandled value, e.g. "i8".
    attr_reader :tag

    # The text content of the unhandled value, as a String (or +nil+).
    attr_reader :content

    def initialize(tag, content) # :nodoc:
      @tag = tag.to_s
      @content = content
    end

    def ==(other)
      other.kind_of?(UnknownValue) and tag == other.tag and content == other.content
    end
    alias eql? ==

    def hash
      [self.class, @tag, @content].hash
    end

    def inspect
      "#<XMLRPC::UnknownValue: <#{@tag}>#{@content.inspect}>"
    end
  end

  # Describes which XML-RPC value types one client or server instance may
  # encode and parse.
  #
  # Two ready-made profiles are provided:
  #
  # * XMLRPC::TypeProfile.standard - standard XML-RPC types only
  #   (i4/int, boolean, string, double, dateTime.iso8601, base64, array,
  #   struct). Integers must fit into a signed 32-bit integer.
  # * XMLRPC::TypeProfile.extended - standard types plus the extension types
  #   <code><nil/></code>, <code><i8></code> (signed 64-bit integers) and
  #   <code><bigdecimal></code> (exact decimals, mapped to BigDecimal).
  #
  # Custom profiles can be built with XMLRPC::TypeProfile.new.
  #
  # Assign a profile to a client or server instance (both encoder and parser
  # of that instance then share it):
  #
  #   client = XMLRPC::Client.new("example.org", "/RPC2", 80,
  #                               type_profile: XMLRPC::TypeProfile.extended)
  #   server = XMLRPC::Server.new(8080, type_profile: XMLRPC::TypeProfile.standard)
  #
  # or later via the accessor:
  #
  #   client.type_profile = XMLRPC::TypeProfile.extended
  class TypeProfile

    # Policy: reject unknown extension tags with an error.
    REJECT_UNKNOWN   = :reject

    # Policy: keep unknown extension tags as XMLRPC::UnknownValue.
    PRESERVE_UNKNOWN = :preserve

    # Name of the profile, e.g. :standard or :extended.
    attr_reader :name

    # The unknown-extension policy, either REJECT_UNKNOWN or PRESERVE_UNKNOWN.
    attr_reader :unknown_extension

    # Creates a new type profile.
    #
    # * +nil_value+: allow the <code><nil/></code> extension.
    # * +big_integer+: allow the <code><i8></code> extension for signed
    #   64-bit integers.
    # * +decimal+: allow the <code><bigdecimal></code> extension for exact
    #   decimals (BigDecimal).
    # * +unknown_extension+: how the parser treats tags not covered by this
    #   profile; either XMLRPC::TypeProfile::REJECT_UNKNOWN (default) or
    #   XMLRPC::TypeProfile::PRESERVE_UNKNOWN.
    def initialize(name=:custom, nil_value: false, big_integer: false, decimal: false,
                   unknown_extension: REJECT_UNKNOWN)
      unless [REJECT_UNKNOWN, PRESERVE_UNKNOWN].include?(unknown_extension)
        raise ArgumentError, "unknown_extension must be :reject or :preserve"
      end

      @name              = name
      @nil_value         = nil_value ? true : false
      @big_integer       = big_integer ? true : false
      @decimal           = decimal ? true : false
      @unknown_extension = unknown_extension
    end

    # Whether the <code><nil/></code> extension is allowed.
    def nil_value?
      @nil_value
    end

    # Whether the <code><i8></code> extension (signed 64-bit integers) is
    # allowed.
    def big_integer?
      @big_integer
    end

    # Whether the <code><bigdecimal></code> extension (exact decimals) is
    # allowed.
    def decimal?
      @decimal
    end

    # Whether unknown extension tags are rejected with an error.
    def reject_unknown_extensions?
      @unknown_extension == REJECT_UNKNOWN
    end

    # Whether unknown extension tags are kept as XMLRPC::UnknownValue.
    def preserve_unknown_extensions?
      @unknown_extension == PRESERVE_UNKNOWN
    end

    # Profile allowing only the standard XML-RPC types.
    def self.standard
      new(:standard)
    end

    # Profile allowing the standard types plus the <code><nil/></code>,
    # <code><i8></code> and <code><bigdecimal></code> extensions.
    def self.extended
      new(:extended, nil_value: true, big_integer: true, decimal: true)
    end

  end # class TypeProfile

end # module XMLRPC
