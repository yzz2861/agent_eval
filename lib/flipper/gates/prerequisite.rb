module Flipper
  module Gates
    class Prerequisite < Gate
      def name
        :prerequisite
      end

      def key
        :prerequisites
      end

      def data_type
        :set
      end

      def enabled?(value)
        !value.empty?
      end

      def open?(context)
        context.values.prerequisites.all? do |value|
          prerequisite = Types::Prerequisite.wrap(value)
          feature = context.feature(prerequisite.name)
          prerequisite.matches?(context.evaluation.enabled?(feature))
        end
      end

      def wrap(thing)
        Types::Prerequisite.wrap(thing)
      end

      def protects?(thing)
        thing.is_a?(Types::Prerequisite)
      end
    end
  end
end
