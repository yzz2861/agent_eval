require "dotenv/definition"
require "dotenv/environment"
require "dotenv/definition_set"
require "dotenv/resolver"

module Dotenv
  # Reads files, collects final definitions, then resolves and applies them.
  class LazyLoader
    attr_reader :sources, :definition_set, :environment

    def initialize(filenames, overwrite: false, ignore: true)
      @filenames = filenames
      @overwrite = overwrite
      @ignore = ignore
    end

    def read
      @sources = @filenames.map do |filename|
        path = File.expand_path(filename)
        begin
          Source.new(filename: path, content: File.open(path, "rb:bom|utf-8", &:read))
        rescue Errno::ENOENT, Errno::EISDIR
          raise unless @ignore

          nil
        end
      end.compact
    end

    def parse
      read unless @sources
      @definition_set = DefinitionSet.new(overwrite: @overwrite)
      @sources.each { |source| @definition_set.add_source(source) }
      @definition_set
    end

    def resolve
      parse unless @definition_set
      @environment = Environment.resolved(Resolver.call(@definition_set))
    end

    def apply
      resolve unless @environment
      Dotenv.update(@environment, overwrite: @overwrite)
    end
  end
end
