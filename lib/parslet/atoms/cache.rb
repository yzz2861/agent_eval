module Parslet::Atoms
  class Cache
    class UnknownSourceFrame
      def observed_eof
        true
      end

      def maximum
        nil
      end

      def close
      end
    end

    Stats = Struct.new(:hits, :misses, :invalidated, :entries) do
      def hit_rate
        return 0 if hits + misses == 0
        Rational(hits, hits + misses)
      end
    end

    def initialize
      @entries = {}
      @stats = Stats.new(0, 0, 0, 0)
    end

    attr_reader :stats

    def reset_stats
      @stats.hits = 0
      @stats.misses = 0
      @stats.invalidated = 0
    end

    def get(obj, source, pos, consume_all, captures, reporter, frame)
      key = [obj.object_id, pos, consume_all, captures.cache_key]
      entry = @entries[key]
      unless entry
        @stats.misses += 1
        return nil
      end

      if entry[:failure] && entry[:reporter_id] != reporter.object_id
        @stats.misses += 1
        return nil
      end

      @stats.hits += 1
      frame.observe(entry[:observed]) if frame.respond_to?(:observe)
      [
        self.class.remap(
          entry[:result], source, entry[:delta], {}, true),
        entry[:advance]
      ]
    end

    def set(obj, pos, consume_all, captures, reporter, result, advance, frame)
      success, value = result
      return if !success && reporter.nil?

      key = [obj.object_id, pos, consume_all, captures.cache_key]
      existing = @entries.key?(key)
      @entries[key] = {
        result: result,
        advance: advance,
        observed: frame.observed_eof ? nil : frame.maximum || pos,
        delta: 0,
        failure: !success,
        reporter_id: reporter.nil? ? nil : reporter.object_id
      }
      @stats.entries += 1 unless existing
    end

    def replace(start_pos, old_length, replacement)
      new_length = replacement.bytesize
      old_end = start_pos + old_length
      surviving = {}

      @entries.each do |key, entry|
        entry_pos = key[1]
        observed = entry[:observed]

        if observed.nil?
          invalidate(entry)
          next
        end

        overlaps_edit = if old_length.zero?
          entry_pos <= start_pos
        else
          entry_pos < old_end
        end
        zero_width_at_start = observed == start_pos && entry_pos == start_pos

        if (observed > start_pos && overlaps_edit) || zero_width_at_start
          invalidate(entry)
          next
        end

        if entry_pos >= old_end && !zero_width_at_start
          entry_pos += new_length - old_length
          observed += new_length - old_length
          entry[:delta] += new_length - old_length
        end

        key = key.dup
        key[1] = entry_pos
        entry[:observed] = observed
        surviving[key] = entry
      end

      @entries = surviving
    end

    def self.remap(value, source, delta, seen={}, force=true)
      return value unless force

      case value
      when Parslet::Slice
        force && delta.zero? ? duplicate_slice(value, source) :
          remap_slice(value, source, delta)
      when Parslet::Cause
        value.remap(source, delta, seen)
      when Parslet::Position
        Parslet::Position.new(source.string, value.bytepos + delta)
      when Array
        value.map { |item| remap(item, source, delta, seen, force) }
      when Hash
        value.each_with_object({}) do |(key, item), result|
          result[key] = remap(item, source, delta, seen, force)
        end
      else
        return remap(value.to_slice, source, delta, seen, force) if
          value.respond_to?(:to_slice)
        value
      end
    end

    def self.remap_slice(slice, source, delta)
      return duplicate_slice(slice, source) if delta.zero?
      position = Parslet::Position.new(
        source.string,
        slice.position.bytepos + delta)
      string = source.string.byteslice(
        position.bytepos,
        slice.str.bytesize)
      Parslet::Slice.new(position, string, source.line_cache)
    end

    def self.duplicate_slice(slice, source)
      Parslet::Slice.new(
        Parslet::Position.new(source.string, slice.position.bytepos),
        slice.str.dup,
        source.line_cache)
    end

  private

    def invalidate(entry)
      @stats.invalidated += 1
      @stats.entries -= 1
    end

  end
end
