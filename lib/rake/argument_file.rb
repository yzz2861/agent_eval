# frozen_string_literal: true

module Rake
  class ArgumentFileError < StandardError
  end

  # Expands UTF-8 command-line argument files referenced with @path.
  class ArgumentFileExpander
    MAX_NESTING = 8
    MAX_TOTAL_BYTES = 1 << 20

    Location = Struct.new(:path, :line, :column)
    Part = Struct.new(
      :character, :location, :protected_character, :escaped, :response_quote
    ) do
      def protected_character?
        protected_character
      end
    end

    Token = Struct.new(:parts, :reference, :reference_location, :quote_location)

    def self.expand(argv)
      expander = new
      expander.expand_argv(argv, Dir.pwd, 0)
    end

    def expand_argv(argv, base_directory, depth)
      argv.flat_map do |argument|
        argument = argument.to_s
        if argument.start_with?("@") && argument.length > 1
          path = File.expand_path(argument[1..-1], base_directory)
          read_and_expand(path, depth, nil, nil)
        else
          argument
        end
      end
    end

    private

    def initialize
      @total_bytes = 0
    end

    def read_and_expand(path, depth, referrer, location)
      if depth > MAX_NESTING
        raise_file_error(
          "parameter file nesting exceeds #{MAX_NESTING} levels",
          referrer, location
        )
      end

      content = read_file(path, referrer, location)
      @total_bytes += content.bytesize
      unless content.force_encoding(Encoding::UTF_8).valid_encoding?
        raise ArgumentFileError, "parameter file #{path} is not valid UTF-8"
      end
      if @total_bytes > MAX_TOTAL_BYTES
        raise ArgumentFileError,
          "total parameter file size exceeds #{MAX_TOTAL_BYTES} bytes"
      end

      tokens = Tokenizer.new.tokenize(content, path)
      directory = File.dirname(path)

      tokens.flat_map do |token|
        if token.reference
          reference_path = token.parts.reject(&:response_quote).
            map(&:character).join
          if reference_path.empty?
            raise_file_error(
              "missing parameter file name after @",
              path, token.reference_location
            )
          end

          reference_path = File.expand_path(reference_path, directory)
          read_and_expand(reference_path, depth + 1, path,
            token.reference_location)
        else
          normalize_token(token)
        end
      end
    end

    def read_file(path, referrer, location)
      File.binread(path)
    rescue SystemCallError => error
      raise_file_error(
        "cannot read parameter file #{path}: #{error.message}",
        referrer, location
      )
    end

    def raise_file_error(message, path, location)
      prefix = if path
        "#{path}:#{location.line}:#{location.column}: "
      else
        ""
      end
      raise ArgumentFileError, "#{prefix}#{message}"
    end

    def normalize_token(token)
      return token.parts.map(&:character).join if token.reference

      value = logical_value(token)
      return value unless task_token?(value)

      opening = token.parts.index { |part| part.character == "[" }
      closing = opening && token.parts.each_index.
        select { |index| token.parts[index].character == "]" }.last
      result = String.new
      source_map = []
      task_quote = nil
      return normalize_plain_token(token) if opening.nil? || closing.nil?

      token.parts.each_with_index do |part, index|
        character = part.character
        structural_bracket = index == opening || index == closing
        inside_arguments = opening && index > opening && index < closing

        if part.response_quote
          next unless inside_arguments

          append(result, source_map, character, part.location)
          task_quote = toggle_quote(task_quote, character)
        elsif structural_bracket || !inside_arguments
          append(result, source_map, character, part.location)
          task_quote = nil if structural_bracket
        elsif task_quote
          append(result, source_map, character, part.location)
        elsif part.escaped && quote_character?(character)
          append(result, source_map, "\\", part.location)
          append(result, source_map, character, part.location)
        elsif quote_character?(character)
          append(result, source_map, character, part.location)
          task_quote = toggle_quote(task_quote, character)
        elsif part.protected_character? && protected_task_character?(character)
          append(result, source_map, "\\", part.location)
          append(result, source_map, character, part.location)
        elsif part.escaped && character == "\\"
          append(result, source_map, "\\", part.location)
          append(result, source_map, character, part.location)
        else
          append(result, source_map, character, part.location)
        end
      end

      ArgumentString.new(result, source_map)
    end

    def append(result, source_map, character, location)
      result << character
      source_map << location
    end

    def normalize_plain_token(token)
      result = String.new
      source_map = []
      token.parts.each do |part|
        next if part.response_quote

        append(result, source_map, part.character, part.location)
      end
      ArgumentString.new(result, source_map)
    end

    def logical_value(token)
      token.parts.reject(&:response_quote).map(&:character).join
    end

    def task_token?(value)
      value !~ /\A-/ && value !~ /\A\w+=/ && value.include?("[")
    end

    def protected_task_character?(character)
      character =~ /\A\s\z/ || character == ","
    end

    def quote_character?(character)
      character == "'" || character == '"'
    end

    def toggle_quote(current_quote, character)
      return character if current_quote.nil?
      return nil if current_quote == character

      current_quote
    end

    class Tokenizer
      def tokenize(content, path)
        @path = path
        @tokens = []
        @token = nil
        @outer_quote = nil
        scan(content)
        finalize_token
        @tokens
      end

      private

      def scan(content)
        line = 1
        column = 1
        escaped = false

        content.each_char do |character|
          location = Location.new(@path, line, column)

          if escaped
            if character == "\n"
              line += 1
              column = 1
            else
              append_character(
                character,
                Location.new(@path, line, column),
                true
              )
              column += 1
            end
            escaped = false
            next
          end

          if character == "\\" && @outer_quote != "'"
            escaped = true
            column += 1
            next
          end

          if @outer_quote.nil? && character =~ /\A\s\z/
            finalize_token
          else
            quoted_token = @outer_quote != nil
            start_token(character, location, quoted_token)

            if character == "@"
              append_character(character, location) unless @token.reference
            elsif character == "'" || character == '"'
              handle_quote(character, location)
            else
              append_character(character, location)
            end
          end

          if character == "\n"
            line += 1
            column = 1
          else
            column += 1
          end
        end

        if escaped
          raise_file_error(
            Location.new(@path, line, [column, 1].max),
            "unterminated escape"
          )
        end

        return unless @outer_quote

        message = "unterminated quote"
        argument_number = task_argument_number
        message += " in task argument #{argument_number}" if argument_number
        raise_file_error(@token.quote_location, message)
      end

      def start_token(character, location, quoted)
        return if @token

        @token = Token.new([], false, nil, nil)
        if character == "@" && !quoted && @outer_quote.nil?
          @token.reference = true
          @token.reference_location = location
        end
      end

      def handle_quote(character, location)
        if @outer_quote.nil?
          @outer_quote = character
          @token.quote_location ||= location
          append_character(character, location, false, true)
          return
        end

        if @outer_quote == character
          @outer_quote = nil
          append_character(character, location, false, true)
          return
        end

        append_character(character, location)
      end

      def append_character(
        character, location, escaped = false, response_quote = false
      )
        protected_character = @outer_quote != nil || escaped
        @token.parts << Part.new(
          character, location, protected_character, escaped, response_quote
        )
      end

      def finalize_token
        return unless @token

        @tokens << @token
        @token = nil
        @outer_quote = nil
      end

      def raise_file_error(location, message)
        raise ArgumentFileError,
          "#{location.path}:#{location.line}:#{location.column}: #{message}"
      end

      def task_argument_number
        opening = @token.parts.index { |part| part.character == "[" }
        return unless opening

        quoted_before_bracket = @token.parts[0...opening].any?(
          &:response_quote
        )

        1 + @token.parts.each_with_index.count do |part, index|
          next false unless index > opening && part.character == ","

          quoted_before_bracket || !part.protected_character?
        end
      end
    end

    ArgumentString = Class.new(String) do
      attr_accessor :source_map

      def initialize(value, source_map)
        super(value)
        @source_map = source_map
      end
    end
  end
end
