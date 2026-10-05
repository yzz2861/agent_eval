require 'thread'
require 'zlib'

module Flipper
  # Public: A Layer splits a shared audience into fixed, non-overlapping
  # bucket ranges so that experiments (features) running in the same layer
  # never affect the same actor at the same time.
  #
  # Each feature in the layer is explicitly assigned a fixed range of
  # buckets. An actor is hashed into exactly one bucket for the layer, so at
  # most one feature in the layer can claim the actor; features that do not
  # claim the actor report disabled before their own gates are even
  # consulted (see Feature#enabled?).
  #
  # Because ranges are fixed and assigned explicitly, removing a feature
  # from the layer never re-buckets the actors of the remaining features.
  #
  #   layer = Flipper.register_layer(:checkout) do |l|
  #     l.assign :new_checkout, 0...50
  #     l.assign :checkout_v2, 50...75
  #     # 75...100 is intentionally unassigned headroom
  #   end
  #
  # The layer hash ("layer:<layer name><actor id>") intentionally uses a
  # different domain than the percentage of actors gate
  # ("<feature name><actor id>") so layer assignment and a feature's own
  # percentage rollout stay statistically independent.
  class Layer
    # Private: Supports the same 3 decimal places of percentage precision
    # as the percentage of actors gate.
    SCALING_FACTOR = 1_000
    private_constant :SCALING_FACTOR

    # Private: Total number of buckets actors are hashed into.
    BUCKET_COUNT = 100 * SCALING_FACTOR
    private_constant :BUCKET_COUNT

    # Private: Hash domain prefix keeping layer bucketing independent from
    # the per-feature percentage of actors bucketing.
    HASH_DOMAIN = "layer:".freeze
    private_constant :HASH_DOMAIN

    # Public: The name of the layer.
    attr_reader :name

    def initialize(name)
      @name = name.to_sym
      @allocations = {}
      @mutex = Mutex.new
    end

    # Public: Assign a fixed percentage range of this layer to a feature.
    #
    # feature_name - The Symbol or String name of the feature.
    # range - An exclusive-end Range of percentages (0...100), supporting up
    #         to 3 decimal places, e.g. 0...25 or 25...37.5.
    #
    # Returns self.
    # Raises ArgumentError if the range is malformed, out of bounds, or the
    #   feature is already assigned.
    # Raises Flipper::LayerOverlap if the range overlaps a range already
    #   assigned to another feature (which is also how over-allocation
    #   beyond 100% is rejected).
    def assign(feature_name, range)
      feature_name = feature_name.to_sym
      buckets = buckets_for(range)

      @mutex.synchronize do
        if @allocations.key?(feature_name)
          raise ArgumentError,
                "#{feature_name.inspect} is already assigned in layer #{name.inspect}; unassign it before re-assigning"
        end

        overlapping = @allocations.find do |_name, allocated|
          allocated.begin < buckets.end && buckets.begin < allocated.end
        end

        if overlapping
          raise LayerOverlap,
                "#{range.inspect} overlaps #{percent_range(overlapping.last).inspect} " +                "already assigned to #{overlapping.first.inspect} in layer #{name.inspect}"
        end

        @allocations[feature_name] = buckets
      end

      self
    end

    # Public: Remove a feature from this layer. Actors of every other
    # feature keep their existing assignment; only the removed feature's
    # range is freed.
    #
    # Returns self.
    def unassign(feature_name)
      @mutex.synchronize { @allocations.delete(feature_name.to_sym) }
      self
    end

    # Public: Is the feature assigned a range in this layer.
    #
    # Returns true or false.
    def include?(feature_name)
      @mutex.synchronize { @allocations.key?(feature_name.to_sym) }
    end

    # Public: The names of all features assigned in this layer.
    #
    # Returns an Array of Symbols.
    def feature_names
      @mutex.synchronize { @allocations.keys }
    end

    # Public: The percentage range assigned to a feature, or nil.
    #
    # Returns an exclusive-end Range of percentages.
    def range_for(feature_name)
      allocated = @mutex.synchronize { @allocations[feature_name.to_sym] }
      allocated && percent_range(allocated)
    end

    # Public: The feature claiming the given actor in this layer, or nil if
    # the actor's bucket falls in an unassigned range.
    #
    # thing - Anything Flipper::Types::Actor.wrap accepts.
    #
    # Returns a Symbol feature name or nil.
    def feature_for(thing)
      bucket = bucket_for(thing)
      @mutex.synchronize { @allocations.dup }.each do |feature_name, allocated|
        return feature_name if allocated.cover?(bucket)
      end
      nil
    end

    # Public: Is the actor claimed by the given feature in this layer.
    #
    # Returns true or false.
    def assigned?(feature_name, thing)
      allocated = @mutex.synchronize { @allocations[feature_name.to_sym] }
      !allocated.nil? && allocated.cover?(bucket_for(thing))
    end

    # Public: The bucket (0...100_000) the actor hashes into for this layer.
    # Stable for a given layer name and actor, independent of any feature.
    #
    # Returns an Integer.
    def bucket_for(thing)
      actor = Types::Actor.wrap(thing)
      Zlib.crc32("#{HASH_DOMAIN}#{name}#{actor.value}") % BUCKET_COUNT
    end

    private

    def buckets_for(range)
      unless range.is_a?(Range) && range.begin.is_a?(Numeric) && range.end.is_a?(Numeric)
        raise ArgumentError,
              "range must be a Range of percentages, but was #{range.inspect}"
      end

      unless range.exclude_end?
        raise ArgumentError,
              "range must exclude its end (use ...), but was #{range.inspect}"
      end

      if range.begin < 0 || range.end > 100 || range.begin >= range.end
        raise ArgumentError,
              "range must be within 0...100 with begin < end, but was #{range.inspect}"
      end

      (range.begin * SCALING_FACTOR).round...(range.end * SCALING_FACTOR).round
    end

    def percent_range(buckets)
      (buckets.begin.to_f / SCALING_FACTOR)...(buckets.end.to_f / SCALING_FACTOR)
    end
  end
end
