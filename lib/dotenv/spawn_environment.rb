module Dotenv
  # An environment mapping suitable for passing directly to Process.spawn.
  class SpawnEnvironment < Hash
    attr_reader :summary

    def initialize(summary)
      super()
      @summary = summary.freeze
    end
  end

  # Builds an isolated child-process environment without mutating ENV.
  class SpawnEnvironmentBuilder
    def initialize(
      *filenames,
      inherit: :all,
      overrides: {},
      source: ENV,
      case_sensitive: :platform,
      ignore: true
    )
      @filenames = filenames
      @filenames = [".env"] if @filenames.empty?
      @inherit = inherit
      @overrides = overrides
      @source = source.to_h
      @ignore = ignore
      @case_sensitive = resolve_case_sensitive(case_sensitive)
      @values = {}
      @canonical_keys = {}
      @case_conflicts = Hash.new { |hash, key| hash[key] = [] }
      @deleted = []
    end

    def build
      selected = selected_parent_environment
      selected.each { |key, value| apply(key, value) }

      @filenames.each do |filename|
        parse_file(filename)
      end

      @overrides.each do |key, value|
        normalized_key = key.to_s
        normalized_value = value.nil? ? nil : value.to_s
        record_deleted_key(normalized_key) if value.nil?
        apply(normalized_key, normalized_value)
      end

      mapping = spawn_mapping(selected)
      summary = change_summary(selected, mapping)
      result = SpawnEnvironment.new(summary)
      result.update(mapping)
      result.freeze
    end

    private

    def resolve_case_sensitive(value)
      case value
      when true, false
        value
      when :platform
        !Gem.win_platform?
      else
        raise ArgumentError, "Invalid value for case_sensitive: #{value.inspect}"
      end
    end

    def selected_parent_environment
      case @inherit
      when :all
        @source
      when :none
        {}
      when Array, String
        selected_keys = Array(@inherit).map(&:to_s).map { |key| canonical_key(key) }
        @source.each_with_object({}) do |(key, value), selected|
          next unless selected_keys.include?(canonical_key(key))

          selected[key] = value
        end
      else
        raise ArgumentError, "Invalid value for inherit: #{@inherit.inspect}"
      end
    end

    def parse_file(filename)
      path = File.expand_path(filename)
      contents = File.open(path, "rb:bom|utf-8", &:read)
      parsed = Parser.call(contents, overwrite: true, env: @values)
      parsed.each { |key, value| apply(key, value) }
    rescue Errno::ENOENT, Errno::EISDIR
      raise unless @ignore
    end

    def apply(key, value)
      canonical = canonical_key(key)

      if value.nil?
        existing_key = @canonical_keys.delete(canonical)
        @values.delete(existing_key || key)
        return
      end

      existing_key = @canonical_keys[canonical]
      if existing_key && existing_key != key
        record_case_conflict(canonical, existing_key, key)
        @values.delete(existing_key)
      end

      @values[key] = value
      @canonical_keys[canonical] = key
    end

    def canonical_key(key)
      @case_sensitive ? key : key.downcase
    end

    def spawn_mapping(selected)
      mapping = @values.dup

      if @inherit != :all
        @source.each_key do |key|
          canonical = canonical_key(key)
          final_key = @canonical_keys[canonical]
          mapping[key] = nil unless final_key == key
        end
      end

      apply_deletions(mapping, @deleted)

      mapping
    end

    def change_summary(selected, mapping)
      final = mapping.reject { |_key, value| value.nil? }
      source_normalized = normalize_environment(@source)
      selected_normalized = normalize_environment(selected)
      final_normalized = normalize_environment(final)

      shared_keys = source_normalized.keys & final_normalized.keys
      changed = shared_keys.reject { |key| source_normalized[key] == final_normalized[key] }
      removed = source_normalized.keys - final_normalized.keys

      {
        case_sensitive: @case_sensitive,
        inherited: selected.keys.sort,
        added: (final_normalized.keys - selected_normalized.keys).sort,
        changed: changed.sort,
        unchanged: (shared_keys - changed).sort,
        removed: removed.sort,
        deleted: @deleted.sort,
        empty: final.keys.select { |key| final[key] == "" }.sort,
        case_conflicts: @case_conflicts.to_h.freeze
      }
    end

    def normalize_environment(env)
      return env if @case_sensitive

      env.each_with_object({}) do |(key, value), normalized|
        canonical = key.downcase
        normalized[canonical] = value unless normalized.key?(canonical)
      end
    end

    def record_case_conflict(canonical, *keys)
      keys.each do |conflicting_key|
        next if @case_conflicts[canonical].include?(conflicting_key)

        @case_conflicts[canonical] << conflicting_key
      end
    end

    def apply_deletions(mapping, keys)
      keys.each do |key|
        canonical = canonical_key(key)
        final_key = @canonical_keys[canonical]

        if final_key
          mapping.delete(key) if key != final_key
        else
          parent_key = parent_key_for(canonical, key)
          mapping[parent_key] = nil if parent_key && mapping[parent_key].nil?
        end
      end
    end

    def parent_key_for(canonical, fallback_key)
      @source.keys.find { |key| canonical_key(key) == canonical } || fallback_key
    end

    def record_deleted_key(key)
      canonical = canonical_key(key)
      normalized_key = @case_sensitive ? key : canonical
      @deleted << normalized_key unless @deleted.include?(normalized_key)
    end
  end
end
