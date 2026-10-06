module Dotenv
  # The final definition selected after applying source order and overrides.
  class DefinitionSet < Hash
    attr_reader :sources, :entries, :overrides

    def initialize(sources, overwrite: false, environment: ENV.to_h)
      super()
      @sources = sources
      @overwrite = overwrite
      @environment = environment
      @entries = sources.flat_map { |source| LazyParser.call(source) }
      @overrides = assignments.group_by(&:key)

      collect!
      validate_exports!
    end

    def assignments
      entries.select(&:assignment?)
    end

    def exports
      entries.reject(&:assignment?)
    end

    def definition_for(key)
      self[key]
    end

    def overridden?(key)
      @overrides.fetch(key, []).any? { |definition| definition != self[key] }
    end

    private

    def collect!
      sources.each { |source| assignments_for(source).each { |definition| self[definition.key] = definition } }
    end

    def assignments_for(source)
      assignments.select { |definition| definition.source == source }
    end

    def validate_exports!
      exports.each do |export|
        next if key?(export.key)
        next if @overwrite != true && @environment.key?(export.key)

        line = export.source.content.each_line.to_a[export.line - 1]&.strip
        raise FormatError, "Line #{line.inspect} has an unset variable"
      end
    end
  end
end
