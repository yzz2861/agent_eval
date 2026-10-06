module Dotenv
  # Identifies where a command substitution originated inside a `.env` file.
  class SourceLocation
    attr_reader :filename, :line, :key

    def initialize(filename: nil, line: nil, key: nil)
      @filename = filename
      @line = line
      @key = key
    end

    def to_s
      parts = []
      parts << (filename || "(eval)")
      parts << ":#{line}" if line
      parts << " in #{key}" if key
      parts.join
    end
  end
end
