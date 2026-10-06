require "dotenv/substitutions/variable"
require "dotenv/substitutions/command"
require "dotenv/command_policy"

module Dotenv
  # Error raised when encountering a syntax error while parsing a .env file.
  class FormatError < SyntaxError; end

  # Parses the `.env` file format into key/value pairs.
  # It allows for variable substitutions, command substitutions, and exporting of variables.
  class Parser
    @substitutions = [
      Dotenv::Substitutions::Command,
      Dotenv::Substitutions::Variable
    ]

    LINE = /
      (?:^|\A)                # beginning of line
      \s*                     # leading whitespace
      (?<export>export\s+)?   # optional export
      (?<key>[\w.]+)          # key
      (?:                     # optional separator and value
        (?:\s*=\s*?|:\s+?)    #   separator
        (?<value>             #   optional value begin
          \s*'(?:\\'|[^'])*'  #     single quoted value
          |                   #     or
          \s*"(?:\\"|[^"])*"  #     double quoted value
          |                   #     or
          [^\#\n]+            #     unquoted value
        )?                    #   value end
      )?                      # separator and value end
      \s*                     # trailing whitespace
      (?:\#.*)?               # optional comment
      (?:$|\z)                # end of line
    /x

    QUOTED_STRING = /\A(['"])(.*)\1\z/m

    class << self
      attr_reader :substitutions

      def call(...)
        new(...).call
      end
    end

    def initialize(string, overwrite: false, command_policy: nil, filename: nil, staged: nil)
      # Convert line breaks to same format
      @string = string.gsub(/\r\n?/, "\n")
      @hash = {}
      @overwrite = overwrite
      @command_policy = CommandPolicy.coerce(command_policy)
      @filename = filename
      @staged = staged
    end

    def call
      # Offsets where each line starts, used to report command locations.
      line_starts = [0]
      @string.enum_for(:scan, /\n/).each { line_starts << $LAST_MATCH_INFO.end(0) }

      @string.scan(LINE) do
        match = $LAST_MATCH_INFO
        offset = match.begin(:key)
        line_number = (line_starts.bsearch_index { |position| position > offset } || line_starts.length)

        if existing?(match[:key])
          # Use value from already defined variable
          @hash[match[:key]] = existing_value(match[:key])
        elsif match[:export] && !match[:value]
          # Check for exported variable with no value
          if !@hash.member?(match[:key])
            raise FormatError, "Line #{match.to_s.inspect} has an unset variable"
          end
        else
          @hash[match[:key]] = parse_value(match[:value] || "", line_number)
        end
      end

      @hash
    end

    private

    # Determine if a variable is already defined and should not be overwritten.
    def existing?(key)
      return false if @overwrite
      key != "DOTENV_LINEBREAK_MODE" &&
        (ENV.key?(key) || (@staged && @staged.key?(key)))
    end

    # Value carried by a variable already present in `ENV` or staged by an
    # earlier file in the same load.
    def existing_value(key)
      return ENV[key] if ENV.key?(key)
      @staged&.[](key)
    end

    def parse_value(value, line_number = nil)
      # Remove surrounding quotes
      value = value.strip.sub(QUOTED_STRING, '\2')
      maybe_quote = Regexp.last_match(1)

      # Expand new lines in double quoted values
      value = expand_newlines(value) if maybe_quote == '"'

      # Unescape characters and performs substitutions unless value is single quoted
      if maybe_quote != "'"
        # Keep escaped parens intact until command substitution resolves them.
        value = Substitutions::Command.protect_escaped_parens(value)
        value = unescape_characters(value)

        location = CommandLocation.new(filename: @filename, line: line_number)
        view = ENV.to_h.merge(@staged || {}).merge(@hash).freeze

        self.class.substitutions.each do |proc|
          value =
            if proc == Substitutions::Command
              proc.call(value, view, policy: @command_policy, location: location, view: view)
            else
              proc.call(value, view)
            end
        end
      end

      value
    end

    def unescape_characters(value)
      value.gsub(/\\([^$])/, '\1')
    end

    def expand_newlines(value)
      if (@hash["DOTENV_LINEBREAK_MODE"] || ENV["DOTENV_LINEBREAK_MODE"]) == "legacy"
        value.gsub('\n', "\n").gsub('\r', "\r")
      else
        value.gsub('\n', "\\\\\\n").gsub('\r', "\\\\\\r")
      end
    end
  end
end
