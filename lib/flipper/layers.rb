require 'flipper/errors'
require 'flipper/layer'

module Flipper
  class Layers
    attr_reader :layers

    def initialize(config = {})
      unless config.is_a?(Hash)
        raise InvalidLayer, 'layers configuration must be a Hash'
      end

      @layers = {}
      feature_layers = {}

      config.each do |name, allocations|
        layer = if allocations.is_a?(Layer)
          allocations
        else
          layer_name = name.nil? ? '' : name
          Layer.new(layer_name, allocations)
        end

        expected_name = name.to_sym
        if layer.name != expected_name
          raise InvalidLayer,
                "layer is named #{layer.name.inspect}, but was configured as #{expected_name.inspect}"
        end

        layer.feature_names.each do |feature_name|
          if feature_layers.key?(feature_name)
            previous_layer = feature_layers[feature_name]
            raise InvalidLayer,
                  "feature #{feature_name.inspect} cannot be in both " \
                  "layer #{previous_layer.inspect} and layer #{name.inspect}"
          end

          feature_layers[feature_name] = expected_name
        end

        @layers[expected_name] = layer
      end

      @layers.freeze
      @feature_layers = feature_layers.freeze
      freeze
    end

    def layer_for(feature_name)
      layer_name = @feature_layers[feature_name.to_sym]
      @layers[layer_name]
    end

    def feature?(feature_name)
      @feature_layers.key?(feature_name.to_sym)
    end
  end
end

Flipper::Layers::EMPTY = Flipper::Layers.new.freeze
