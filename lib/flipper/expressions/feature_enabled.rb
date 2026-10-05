module Flipper
  module Expressions
    class FeatureEnabled
      def self.call(feature_name, context:)
        feature_name = feature_name.to_s
        evaluation = context[:evaluation]
        feature_provider = context[:feature_provider]

        if evaluation && feature_provider
          evaluation.enabled?(feature_provider.call(feature_name))
        else
          actors = Array(context[:original_actors] || context[:actors])
          actors.empty? ? Flipper.enabled?(feature_name) : Flipper.enabled?(feature_name, *actors)
        end
      end
    end
  end
end
