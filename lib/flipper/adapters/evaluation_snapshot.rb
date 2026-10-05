module Flipper
  module Adapters
    # Internal: Routes reads to a consistent feature snapshot and writes to the
    # live adapter. Writes remain visible to later scopes but never mutate the
    # configuration used by the snapshot that is active when they occur.
    class EvaluationSnapshot < Wrapper
      READ_METHODS = %i[features get get_multi get_all export].freeze

      attr_reader :snapshot_adapter

      def initialize(adapter, snapshot_adapter)
        super(adapter)
        @snapshot_adapter = snapshot_adapter
      end

      READ_METHODS.each do |method|
        if RUBY_VERSION >= '3.0'
          define_method(method) do |*args, **kwargs, &block|
            @snapshot_adapter.public_send(method, *args, **kwargs, &block)
          end
        else
          define_method(method) do |*args, &block|
            @snapshot_adapter.public_send(method, *args, &block)
          end
        end
      end

      def read_only?
        false
      end

      def supports_snapshot?
        @adapter.supports_snapshot?
      end

      def snapshot
        @adapter.snapshot
      end

      def adapter_stack
        "evaluation_snapshot(#{@snapshot_adapter.adapter_stack}) -> #{@adapter.adapter_stack}"
      end
    end
  end
end
