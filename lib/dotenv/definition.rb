module Dotenv
  # A variable definition as it appeared in a source file.
  class Definition
    attr_reader :key, :raw_value, :quote, :source, :line

    def initialize(key:, raw_value:, quote:, source:, line:)
      @key = key
      @raw_value = raw_value
      @quote = quote
      @source = source
      @line = line
    end

    def filename
      source.filename
    end

    def assignment?
      !raw_value.nil?
    end

    def single_quoted?
      quote == "'"
    end
  end
end
