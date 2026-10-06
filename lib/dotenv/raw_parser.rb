require "dotenv/parser"
require "dotenv/definition"

module Dotenv
  # Parses .env syntax into Definitions without performing variable or command substitution.
  class RawParser
    def self.call(...)
      new(...).call
    end

    def initialize(string, filename: nil, source_id: nil, external: {}, overwrite: false)
      @string = string.gsub(/\r\n?/, "\n")
      @filename = filename
      @source_id = source_id
      @external = external
      @overwrite = overwrite
      @definitions = []
      @called = false
    end

    def call
      parse unless @called
      to_h
    end

    def definitions
      parse unless @called
      @definitions
    end

    private

    def parse
      @string.scan(Parser::LINE) do
        match = $LAST_MATCH_INFO
        key = match[:key]

        if match[:export] && !match[:value]
          next if exported_external?(key)

          unless @definitions.any? { |definition| definition.key == key }
            raise FormatError, "Line #{match.to_s.inspect} has an unset variable"
          end
        else
          @definitions << build_definition(key, match)
        end
      end
      @called = true
    end

    def build_definition(key, match)
      raw_value = match[:value] || ""
      value = raw_value.strip
      quote = value[Parser::QUOTED_STRING, 1]

      Definition.new(
        key: key,
        value: value.sub(Parser::QUOTED_STRING, '\\2'),
        quote: quote,
        filename: @filename,
        source_id: @source_id,
        line: match.pre_match.count("\n") + 1
      )
    end

    def to_h
      @definitions.to_h { |definition| [definition.key, definition] }
    end

    def exported_external?(key)
      @overwrite != true && key != "DOTENV_LINEBREAK_MODE" && @external.key?(key)
    end
  end
end
