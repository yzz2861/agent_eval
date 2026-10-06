module Dotenv
  # Reads, collects, resolves, and applies .env files in separate stages.
  class LazyLoader
    attr_reader :sources, :definitions, :resolved, :applied

    def initialize(filenames, overwrite: false, ignore: true, instrumenter: nil)
      @filenames = filenames
      @overwrite = overwrite
      @ignore = ignore
      @instrumenter = instrumenter
    end

    def read
      @sources ||= @filenames.map do |filename|
        path = File.expand_path(filename)
        Source.new(path, File.open(path, "rb:bom|utf-8", &:read))
      rescue Errno::ENOENT, Errno::EISDIR
        raise unless @ignore

        nil
      end.compact

      self
    end

    def parse
      read
      @environment ||= ENV.to_h
      @definitions ||= DefinitionSet.new(
        sources,
        overwrite: @overwrite,
        environment: @environment
      )
      self
    end

    def resolve
      parse
      @resolved ||= LazyResolver.call(
        definitions,
        overwrite: @overwrite,
        environment: @environment
      )
      self
    end

    def apply
      resolve
      @applied = instrument_apply do
        sources.each do |source|
          instrument(:load, env: source)
        end

        Dotenv.update(resolved, overwrite: @overwrite)
      end
      self
    end

    def to_h
      resolve
      resolved
    end

    private

    def instrument_apply(&block)
      return yield unless @instrumenter

      @instrumenter.call(:update, &block)
    end

    def instrument(name, payload = {})
      return unless @instrumenter

      @instrumenter.call(name, payload) do |event_payload|
        yield(event_payload) if block_given?
      end
    end
  end
end
