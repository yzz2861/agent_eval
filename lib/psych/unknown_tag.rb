# frozen_string_literal: true

module Psych
  ###
  # Psych::UnknownTag is a value object that holds the content of a YAML
  # node whose tag is not recognized (or names a class that is not
  # permitted) when loading with <tt>preserve_unknown_tags: true</tt>.
  #
  # The tag is never resolved to a Ruby class: no constant lookup is
  # performed and no user constructor is called.  Instead the object
  # lazily keeps the original tag together with the plain Ruby
  # representation of the node content:
  #
  # * a String for scalar nodes (the raw, untokenized scalar text)
  # * an Array for sequence nodes
  # * a Hash for mapping nodes
  #
  # The contained value can be inspected and replaced by the application,
  # and dumping the object with Psych emits the original tag again, so
  # documents carrying foreign tags (for example tags defined by other
  # languages) can round-trip through a service that only relays YAML:
  #
  #   yaml = "--- !python/tuple [1, 2]\n"
  #   obj = Psych.safe_load yaml, preserve_unknown_tags: true
  #   obj.tag      # => "!python/tuple"
  #   obj.value    # => [1, 2]
  #
  #   obj.value = [3, 4]
  #   Psych.dump obj  # => "--- !python/tuple\n- 3\n- 4\n"
  class UnknownTag
    # The original YAML tag of the preserved node.
    attr_reader :tag

    # The plain Ruby content of the preserved node: a String (scalar),
    # an Array (sequence) or a Hash (mapping).  Applications may replace
    # it with another plain value before dumping.
    attr_accessor :value

    def initialize tag, value
      @tag   = tag
      @value = value
    end

    def == other
      UnknownTag === other && tag == other.tag && value == other.value
    end
    alias eql? ==

    def hash
      [self.class, tag, value].hash
    end

    def inspect
      "#<#{self.class.name} tag=#{tag.inspect} value=#{value.inspect}>"
    end
  end
end
