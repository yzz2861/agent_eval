# frozen_string_literal: true

module Psych
  # A safely loaded value whose YAML tag does not map to a permitted Ruby
  # class. The wrapped +value+ contains the ordinary scalar, sequence, or
  # mapping represented by the tagged node, while +tag+ is emitted unchanged.
  class UnknownTag
    # The original YAML tag.
    attr_reader :tag, :value, :type

    # Create a tagged value containing an ordinary scalar, Array, or Hash.
    def initialize tag, value
      @tag = tag
      self.value = value
    end

    # Replace the represented scalar, Array, or Hash and update +type+.
    def value= value
      @type = case value
              when Hash then :map
              when Array then :seq
              else :scalar
              end
      @value = value
    end

    def scalar?;   @type == :scalar; end
    def sequence?; @type == :seq; end
    def map?;      @type == :map; end
    alias mapping? map?

    def == other
      other.is_a?(UnknownTag) && tag == other.tag && value == other.value
    end
    alias eql? ==

    def hash
      [tag, value].hash
    end

    def inspect
      "#<#{self.class} #{tag.inspect} #{value.inspect}>"
    end
  end
end
