module Dotenv
  # A `.env` file that will be read and parsed into a Hash
  class Environment < Hash
    attr_reader :filename, :overwrite

    # Create a new Environment
    #
    # @param filename [String] the path to the file to read
    # @param overwrite [Boolean] whether the parser should assume existing values will be overwritten
    # @param command_substitution [:shell, :disabled, :literal, #call] policy for `$(...)` substitutions
    def initialize(filename, overwrite: false, command_substitution: :shell)
      super()
      @filename = filename
      @overwrite = overwrite
      @command_substitution = command_substitution
      load
    end

    def load
      update Parser.call(
        read,
        overwrite: overwrite,
        source: filename,
        command_substitution: @command_substitution
      )
    end

    def read
      File.open(@filename, "rb:bom|utf-8", &:read)
    end
  end
end
