# frozen_string_literal: true

module MessagePack
  # Ordered map representation used when +preserve_maps: true+ is set on an
  # unpacker or factory. Each map is stored as an ordered sequence of
  # +[key, value]+ pairs so duplicate, compound and numerically distinct keys
  # are retained from the MessagePack wire format.
  class Map
    # Create a map from an enumerable of +[key, value]+ pairs.
    def self.from_pairs(pairs)
    end

    # Convert to a Hash using an explicit duplicate-key strategy.
    # Supported strategies are +:raise+, +:first+, +:last+ or a callable
    # receiving +(key, old_value, new_value)+.
    def to_h(strategy)
    end
  end
end
