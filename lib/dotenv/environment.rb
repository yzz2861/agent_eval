module Dotenv
  # A `.env` file that will be read and parsed into a Hash
  class Environment < Hash
    attr_reader :filename, :overwrite, :command_policy

    # Create a new Environment
    #
    # @param filename [String] the path to the file to read
    # @param overwrite [Boolean] whether the parser should assume existing values will be overwritten
    # @param command_policy [Symbol, #call, CommandPolicy] how `$(...)` substitutions are handled
    # @param staged [Hash] variables already staged from earlier files in the same load
    def initialize(filename, overwrite: false, command_policy: nil, staged: nil)
      super()
      @filename = filename
      @overwrite = overwrite
      @command_policy = CommandPolicy.coerce(command_policy)
      @staged = staged
      load
    end

    def load
      update Parser.call(
        read,
        overwrite: overwrite,
        command_policy: command_policy,
        filename: filename,
        staged: @staged
      )
    end

    def read
      File.open(@filename, "rb:bom|utf-8", &:read)
    end
  end
end
