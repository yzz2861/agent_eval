# frozen-string-literal: true

class Roda
  module RodaPlugins
    # The server_timing plugin adds a Server-Timing response header with the
    # durations of named blocks in the routing tree:
    #
    #   plugin :server_timing
    #
    #   route do |r|
    #     timed("db", "Load user") do
    #       # database work
    #     end
    #
    #     timed("view", "Render response") do
    #       # template work
    #     end
    #   end
    #
    # +r.server_timing+ and +r.timed+ are equivalent to the routing-scope
    # methods.
    #
    # Each call records the total wall-clock duration of the block.  When
    # blocks are nested, the parent also records a self duration with its total
    # duration minus the total durations of intervals started inside the same
    # Fiber.  The self duration is emitted as a separate metric using the
    # +.self+ suffix:
    #
    #   server_timing("view") do
    #     server_timing("db") { }
    #   end
    #   # view;dur=20;desc="Render", view.self;dur=15;desc="Render (self)", db;dur=5
    #
    # Multiple calls with the same name are aggregated.  Total durations are
    # summed, self durations are summed, and the description from the first
    # call with a non-nil description is used.  Metrics are emitted in the
    # order in which their names were first started, with a metric's total and
    # self values kept adjacent.
    #
    # Intervals started in different Fibers are independent.  A child Fiber
    # never becomes a child of an interval that is open in the parent Fiber.
    #
    # A block that raises an exception still records all intervals that were
    # started in the block before the exception.
    #
    # The clock is a callable returning a monotonic time in seconds.  By
    # default, Process.clock_gettime(Process::CLOCK_MONOTONIC) is used:
    #
    #   clock = Class.new do
    #     def initialize(times)
    #       @times = times
    #     end
    #
    #     def call
    #       @times.shift.to_r
    #     end
    #   end.new([0, 1, 1, 2])
    #   plugin :server_timing, clock: clock
    #
    # The +:max_header_bytes+ option limits the generated Server-Timing field
    # value to the given number of bytes (1024 by default).  Metrics are kept
    # in first-started order; a nested metric is kept as a total/self pair or
    # not at all.  An existing Server-Timing header is preserved before the
    # generated metrics and is never truncated by this plugin.
    module ServerTiming
      SCOPE_INSTANCE_VARIABLES = [:@_server_timing].freeze

      HEADER_NAME = (defined?(Rack::Headers) && Rack::Headers.is_a?(Class) ?
        "server-timing" : "Server-Timing").freeze
      DEFAULT_MAX_HEADER_BYTES = 1024
      METRIC_TOKEN_RE = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/

      # Per-request timing state.  This is not intended for direct use.
      class Recorder
        Metric = Struct.new(:name, :description, :total, :self, :nested)

        def initialize(clock)
          @clock = clock
          @metrics = {}
          @metric_order = []
          @stacks = {}
        end

        # Time the required block and return its return value.
        def time(name, description)
          metric = metric(name, description)
          stack << [metric, @clock.call, 0, false]

          begin
            yield
          ensure
            close_interval
          end
        end

        # Return the metrics serialized in deterministic order.
        def metrics
          @metric_order.map do |metric_name|
            metric = @metrics[metric_name]
            values = [serialize(metric)]
            values << serialize_self(metric) if metric.nested
            values.join(", ")
          end
        end

        private

        def metric(name, description)
          name = name.to_s
          unless METRIC_TOKEN_RE.match?(name)
            raise RodaError, "invalid Server-Timing metric name: #{name.inspect}"
          end

          metric = @metrics[name]
          unless metric
            metric = Metric.new(name, nil, 0, 0, false)
            @metrics[name] = metric
            @metric_order << name
          end
          metric.description = description.to_s if metric.description.nil? && !description.nil?
          metric
        end

        def stack
          @stacks[Fiber.current] ||= []
        end

        def close_interval
          metric, start_time, child_duration, nested = stack.pop
          duration = @clock.call - start_time
          metric.total += duration
          metric.self += duration - child_duration
          metric.nested = true if nested

          if parent = stack[-1]
            parent[2] += duration
            parent[3] = true
          end
        end

        def serialize(metric)
          "#{metric.name};dur=#{duration(metric.total)}#{description(metric.description)}"
        end

        def serialize_self(metric)
          description = if metric.description
            "#{metric.description} (self)"
          end
          "#{metric.name}.self;dur=#{duration(metric.self)}#{description(description)}"
        end

        def description(value)
          return String.new unless value

          value = value.to_s.dup
          value.gsub!(/[\r\n]+/, " ")
          value.gsub!(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/, String.new)
          value.gsub!("\\".freeze) { "\\\\".freeze }
          value.gsub!('"'.freeze, '\\"'.freeze)
          ";desc=\"#{value}\""
        end

        def duration(seconds)
          value = sprintf("%.6f", (seconds * 1000).to_r)
          value.sub(/\.?0+\z/, String.new)
        end
      end

      def self.configure(app, opts=RodaPlugins::OPTS)
        clock = opts[:clock] || app.opts[:server_timing_clock] || default_clock
        unless clock.respond_to?(:call)
          raise RodaError, "server_timing plugin :clock option must respond to call"
        end

        max_header_bytes = if opts.key?(:max_header_bytes) && !opts[:max_header_bytes].nil?
          opts[:max_header_bytes]
        elsif app.opts[:server_timing_max_header_bytes]
          app.opts[:server_timing_max_header_bytes]
        else
          DEFAULT_MAX_HEADER_BYTES
        end
        max_header_bytes = Integer(max_header_bytes)
        if max_header_bytes < 0
          raise RodaError, "server_timing plugin :max_header_bytes option cannot be negative"
        end

        app.opts[:server_timing_clock] = clock
        app.opts[:server_timing_max_header_bytes] = max_header_bytes
      end

      if RUBY_VERSION >= "2.1"
        def self.default_clock
          proc { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
        end
      else
        # simplecov:disable
        def self.default_clock
          proc { Time.now.to_f }
        end
        # simplecov:enable
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :server_timing_clock)
        RodaPlugins.opt_attr_reader(self, :server_timing_max_header_bytes)
      end

      module InstanceMethods
        # Time the given block and include it in the Server-Timing response
        # header under the given metric name.  The optional description is
        # escaped when serialized and included as the metric description.
        def server_timing(name, description=nil)
          @_server_timing ||= Recorder.new(opts[:server_timing_clock])
          @_server_timing.time(name, description) { yield }
        end
        alias timed server_timing

        private

        # Add recorded metrics after response processing, while preserving any
        # existing Server-Timing header.
        def _roda_after_89__server_timing(res)
          return unless res && @_server_timing

          metrics = @_server_timing.metrics
          return if metrics.empty?

          headers = res[1]
          key = headers.each_key.find { |header_key| header_key.to_s.downcase == HEADER_NAME.downcase }
          existing = Array(key && headers[key]).map(&:to_s).reject(&:empty?)
          value = existing.join(", ".freeze)

          metrics.each do |metric|
            if value.empty?
              candidate = metric
            else
              candidate = "#{value}, #{metric}"
            end

            if candidate.bytesize <= opts[:server_timing_max_header_bytes]
              value = candidate
            else
              break
            end
          end

          headers[key || HEADER_NAME] = value unless value.empty?
        end
      end

      module RequestMethods
        # Time the given block through the related Roda instance.
        def server_timing(name, description=nil, &block)
          @scope.server_timing(name, description, &block)
        end
        alias timed server_timing
      end
    end

    register_plugin(:server_timing, ServerTiming)
  end
end
