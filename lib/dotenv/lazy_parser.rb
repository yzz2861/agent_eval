module Dotenv
  # Parses a source into definitions without variable or command substitution.
  class LazyParser
    def self.call(...)
      new(...).call
    end

    def initialize(source)
      @source = source
      @string = source.content.gsub(/\r\n?/, "\n")
    end

    def call
      definitions = []

      @string.scan(Parser::LINE) do
        match = $LAST_MATCH_INFO
        value = match[:value]
        export_without_value = match[:export] && match[:value].nil?
        raw_value, quote = export_without_value ? [nil, nil] : parse_value(value || "")

        definitions << Definition.new(
          key: match[:key],
          raw_value: raw_value,
          quote: quote,
          source: @source,
          line: line_number(match)
        )
      end

      definitions
    end

    private

    def parse_value(value)
      value = value.strip
      match = value.match(Parser::QUOTED_STRING)

      if match
        [match[2], match[1]]
      else
        [value, nil]
      end
    end

    def line_number(match)
      @string.byteslice(0...match.begin(0)).count("\n") + 1
    end
  end
end
