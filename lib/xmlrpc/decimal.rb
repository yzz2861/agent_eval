# frozen_string_literal: false
#
# Exact decimal value for XML-RPC for Ruby.
#

module XMLRPC # :nodoc:

  # Controlled representation of an exact decimal number, used for the
  # <code><decimal></code> extension tag (see XMLRPC::TypeProfile).
  #
  # The value is kept as its exact string representation and is never
  # converted through Float, so no precision is lost. When the
  # +bigdecimal+ library is available, XMLRPC::Decimal#to_d converts the
  # value to a BigDecimal.
  class Decimal

    FORMAT = /\A[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?\z/

    # The exact decimal string, e.g. "1.2300".
    attr_reader :value

    # Creates a new XMLRPC::Decimal from a String (or anything
    # responding to +to_s+) holding an exact decimal number.
    #
    # Raises ArgumentError when the string is not a valid decimal
    # literal.
    def initialize(value)
      str = value.to_s
      unless str =~ FORMAT
        raise ArgumentError, "not an exact decimal literal: #{str.inspect}"
      end
      @value = str
    end

    # The exact decimal string.
    def to_s
      @value
    end

    # Converts the value to a BigDecimal. Requires the +bigdecimal+
    # library.
    def to_d
      require "bigdecimal"
      BigDecimal(@value)
    end

    def ==(other)
      other.instance_of?(self.class) && other.value == @value
    end
    alias eql? ==

    def hash
      [self.class, @value].hash
    end

    def inspect
      "#<XMLRPC::Decimal #{@value}>"
    end
  end

end
