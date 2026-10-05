module Flipper
  module Adapters
    class Failsafe
      include ::Flipper::Adapter

      attr_reader :adapter

      # Public: Build a new Failsafe instance.
      #
      # adapter   - Flipper adapter to guard.
      # options   - Hash of options:
      #             :errors - Array of exception types for which to fail safe

      def initialize(adapter, options = {})
        @adapter = adapter
        @errors = options.fetch(:errors, [StandardError])
      end

      def features
        @adapter.features
      rescue *@errors
        Set.new
      end

      def add(feature)
        @adapter.add(feature)
      rescue *@errors
        false
      end

      def remove(feature)
        @adapter.remove(feature)
      rescue *@errors
        false
      end

      def clear(feature)
        @adapter.clear(feature)
      rescue *@errors
        false
      end

      def get(feature)
        @adapter.get(feature)
      rescue *@errors
        {}
      end

      def get_multi(features)
        @adapter.get_multi(features)
      rescue *@errors
        {}
      end

      def get_all(**kwargs)
        @adapter.get_all(**kwargs)
      rescue *@errors
        {}
      end

      def enable(feature, gate, thing)
        @adapter.enable(feature, gate, thing)
      rescue *@errors
        false
      end

      def disable(feature, gate, thing)
        @adapter.disable(feature, gate, thing)
      rescue *@errors
        false
      end

      if RUBY_VERSION >= '3.0'
        def evaluation_snapshot(consistency: :strong)
          @adapter.evaluation_snapshot(consistency: consistency)
        end
      else
        def evaluation_snapshot(consistency = :strong)
          @adapter.evaluation_snapshot(consistency)
        end
      end

      def supports_evaluation_snapshots?
        @adapter.supports_evaluation_snapshots?
      end

      if RUBY_VERSION >= '3.0'
        def with_evaluation_snapshot(consistency: :strong, &block)
          @adapter.with_evaluation_snapshot(consistency: consistency, &block)
        end
      else
        def with_evaluation_snapshot(consistency = :strong, &block)
          @adapter.with_evaluation_snapshot(consistency, &block)
        end
      end

      def current_evaluation_snapshot
        @adapter.current_evaluation_snapshot
      rescue StandardError
        nil
      end
    end
  end
end
