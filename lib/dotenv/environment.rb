module Dotenv
  # A `.env` file that will be read and parsed into a Hash
  class Environment < Hash
    attr_reader :filename, :overwrite

    def self.resolved(values, filename: nil)
      allocate.tap do |environment|
        environment.send(:initialize_resolved, values, filename)
      end
    end

    # Create a new Environment
    #
    # @param filename [String] the path to the file to read
    # @param overwrite [Boolean] whether the parser should assume existing values will be overwritten
    def initialize(filename, overwrite: false)
      super()
      @filename = filename
      @overwrite = overwrite
      load
    end

    def load
      update Parser.call(read, overwrite: overwrite)
    end

    def read
      File.open(@filename, "rb:bom|utf-8", &:read)
    end

    private

    def initialize_resolved(values, filename = nil)
      Hash.instance_method(:initialize).bind_call(self)
      @filename = filename
      @overwrite = false
      merge!(values)
    end
  end
end
