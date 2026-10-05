require 'zlib'
require 'flipper/errors'

module Flipper
  class Layer
    BUCKET_COUNT = 1_000
    private_constant :BUCKET_COUNT

    attr_reader :name, :allocations

    def initialize(name, allocations)
      @name = name.to_sym
      @allocations = normalize_allocations(allocations)
      validate!
      @allocations.freeze
      @feature_names = @allocations.keys.freeze
      freeze
    end

    def feature_names
      @feature_names.dup
    end

    def feature?(feature_name)
      @allocations.key?(feature_name.to_sym)
    end

    def matches?(feature_name, actors)
      allocation = @allocations[feature_name.to_sym]
      return false if allocation.nil? || actors.nil? || actors.empty?

      allocation.cover?(bucket_for(actors))
    end

    def bucket_for(actors)
      actors = Array(actors)
      values = actors.map do |actor|
        actor.respond_to?(:flipper_id) ? actor.flipper_id.to_s : actor.value
      end
      identifier = values.size == 1 ? values.first : values.sort.join('|')
      Zlib.crc32("flipper.layer:#{name}:#{identifier}") % BUCKET_COUNT
    end

    private

    def normalize_allocations(allocations)
      unless allocations.is_a?(Hash)
        raise InvalidLayer, "layer #{name.inspect} allocations must be a Hash"
      end

      allocations.each_with_object({}) do |(feature_name, range), normalized|
        normalized_feature_name = feature_name.to_sym
        normalized[normalized_feature_name] = normalize_range(normalized_feature_name, range)
      end
    end

    def normalize_range(feature_name, range)
      unless range.is_a?(Range) &&
             range.begin.is_a?(Integer) &&
             range.end.is_a?(Integer)
        raise InvalidLayer,
              "allocation for #{feature_name.inspect} in layer #{name.inspect} must be an integer bucket Range"
      end

      finish = range.exclude_end? ? range.end : range.end + 1
      range.begin...finish
    end

    def validate!
      if name.to_s.strip.empty?
        raise InvalidLayer, 'layer name cannot be blank'
      end

      @allocations.each do |feature_name, range|
        if feature_name.to_s.strip.empty?
          raise InvalidLayer, "feature names in layer #{name.inspect} cannot be blank"
        end

        if range.begin < 0 || range.begin >= range.end
          raise InvalidLayer,
                "allocation for #{feature_name.inspect} in layer #{name.inspect} " \
                "must be within buckets 0...#{BUCKET_COUNT}"
        end
      end

      sorted_allocations = @allocations.sort_by { |_, range| [range.begin, range.end] }
      sorted_allocations.each_cons(2) do |(_, first), (second_feature, second)|
        if first.end > second.begin
          raise InvalidLayer,
                "allocation for #{second_feature.inspect} in layer #{name.inspect} overlaps another allocation"
        end
      end

      allocated_buckets = @allocations.sum { |_, range| range.end - range.begin }
      if allocated_buckets > BUCKET_COUNT
        raise InvalidLayer,
              "layer #{name.inspect} allocates #{allocated_buckets} buckets, but only #{BUCKET_COUNT} are available"
      end

      @allocations.each do |feature_name, range|
        if range.end > BUCKET_COUNT
          raise InvalidLayer,
                "allocation for #{feature_name.inspect} in layer #{name.inspect} " \
                "must be within buckets 0...#{BUCKET_COUNT}"
        end
      end
    end
  end
end
