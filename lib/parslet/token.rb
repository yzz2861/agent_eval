module Parslet
  # A lexical token. The range is a byte range into the original source.
  class Token
    attr_reader :type, :value, :range, :lexeme

    def self.from(token)
      return token.dup if token.kind_of?(Token)

      if token.respond_to?(:type) && token.respond_to?(:value) && token.respond_to?(:range)
        return new(token.type, token.value, token.range)
      end

      type = token.fetch(:type)
      value = token.fetch(:value)
      range = token.fetch(:range)

      new(type, value, range)
    end

    def initialize(type, value, range, lexeme=nil)
      @type = type
      @value = value
      @range = range
      @lexeme = lexeme
    end

    def with_lexeme(lexeme)
      self.class.new(type, value, range, lexeme)
    end
  end
end
