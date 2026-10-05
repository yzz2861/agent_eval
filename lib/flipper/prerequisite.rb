module Flipper
  # Public: Value object declaring that one feature depends on another
  # feature being on (or off) before its own gates are consulted.
  #
  # Prerequisites are combined with the regular gates using AND semantics:
  # a feature is only enabled for an actor when ALL of its prerequisites are
  # satisfied AND at least one of its gates is open for that actor. A feature
  # with unsatisfied prerequisites is disabled no matter what its gates say,
  # and satisfied prerequisites alone do not enable a feature with no open
  # gate.
  class Prerequisite
    # Public: The name of the feature that is required.
    attr_reader :feature_name

    # Public: Initializes a new prerequisite.
    #
    # feature_name - The Symbol or String name of the required feature.
    # on - When true (default) the required feature must be enabled for the
    #      actor; when false it must be disabled for the actor. A required
    #      feature that does not exist in the adapter never satisfies the
    #      prerequisite, regardless of this flag.
    def initialize(feature_name, on: true)
      @feature_name = feature_name.to_sym
      @on = on ? true : false
    end

    # Public: True when the required feature must be enabled.
    def on?
      @on
    end

    # Public: True when the required feature must be disabled.
    def off?
      !@on
    end

    def ==(other)
      other.is_a?(Prerequisite) &&
        other.feature_name == feature_name &&
        other.on? == on?
    end
    alias_method :eql?, :==

    def hash
      [feature_name, on?].hash
    end

    def inspect
      "#<#{self.class.name}:#{object_id} feature_name=#{feature_name.inspect} on=#{on?.inspect}>"
    end
  end
end
