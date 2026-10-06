module Dotenv
  # A `.env` file that will be read and parsed into a Hash
  class Environment < Hash
    attr_reader :filename, :overwrite

    # Create a new Environment
    #
    # @param filename [String] the path to the file to read
    # @param overwrite [Boolean] whether the parser should assume existing values will be overwritten
    def initialize(filename, overwrite: false, env: ENV)
      super()
      @filename = filename
      @overwrite = overwrite
      @env = env
      load
    end

    def load
      update Parser.call(read, overwrite: overwrite, env: @env)
    end

    def read
      File.open(@filename, "rb:bom|utf-8", &:read)
    end
  end
end
