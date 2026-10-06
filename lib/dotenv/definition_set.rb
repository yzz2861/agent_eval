require "dotenv/raw_parser"

module Dotenv
  # All variable definitions collected from one or more files.
  class DefinitionSet
    attr_reader :definitions, :overrides, :external

    def initialize(overwrite: false, external: ENV.to_h)
      @overwrite = overwrite
      @external = external
      @definitions = {}
      @overrides = Hash.new { |hash, key| hash[key] = [] }
    end

    def add_source(source)
      parser = RawParser.new(
        source.content,
        filename: source.filename,
        source_id: source.object_id,
        external: @external,
        overwrite: @overwrite
      )
      parser.definitions.each { |definition| add_definition(definition) }
    end

    def add_definition(definition)
      key = definition.key

      if @definitions.key?(key)
        current = @definitions.fetch(key)
        if current.source_id == definition.source_id
          @overrides[key] << current
          @definitions[key] = definition
        else
          @overrides[key] << definition
        end
      elsif !file_overwrites? && @external.key?(key) && !linebreak_mode?(key)
        @overrides[key] << definition
      else
        @definitions[key] = definition
      end
    end

    def each(&block)
      @definitions.each_value(&block)
    end

    def keys
      @definitions.keys | @overrides.keys
    end

    def external?(key)
      !file_overwrites? && !linebreak_mode?(key) && @external.key?(key)
    end

    def external_value(key)
      @external.fetch(key) if external?(key)
    end

    def overridden(key)
      @overrides.fetch(key, [])
    end

    private

    def file_overwrites?
      @overwrite == true
    end

    def linebreak_mode?(key)
      key == "DOTENV_LINEBREAK_MODE"
    end
  end
end
