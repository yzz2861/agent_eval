# frozen_string_literal: true

#
class Roda
  module RodaPlugins
    # The server_timing plugin adds a +Server-Timing+ response header that
    # reports how long named parts of a request took (database queries,
    # template rendering, and so on).
    #
    # Timings are recorded inside the route block using #server_timing:
    #
    #   plugin :server_timing
    #
    #   route do |r|
    #     users = server_timing("db.users") { User.all }
    #     server_timing("view.render", "users index") { view(:users) }
    #   end
    #
    # Timing intervals may be nested.  Each named metric is reported using
    # two entries when nesting is involved:
    #
    # * +name+ aggregates the wall-clock duration of every interval with
    #   that name, including child intervals (the total time).
    # * +name.self+ aggregates the exclusive duration, which is the total
    #   duration minus the duration of intervals directly nested inside it.
    #   The +.self+ entry is omitted when total and exclusive durations are
    #   equal.
    #
    # Aggregation rules for multiple calls with the same name:
    #
    # * The +dur+ value is the sum of all matching intervals (in
    #   milliseconds), preserving the total/exclusive split described above.
    # * A +count+ extension parameter reports how many intervals were
    #   aggregated, but only when there is more than one call.
    # * If every call provides the same non-nil description, it is kept in
    #   +desc+.  If descriptions differ, no +desc+ is emitted (the count is
    #   still reported).
    # * Metrics are emitted in first-seen order (the order in which the
    #   first interval of each name started).
    #
    # For cases where a block is inconvenient, #server_timing_start and
    # #server_timing_finish can be used without a block:
    #
    #   timer = server_timing_start("db.users")
    #   users = User.all
    #   server_timing_finish(timer)
    #
    # Intervals started in one Fiber are tracked independently of intervals
    # started in another Fiber of the same request, so an interval finishing
    # inside a different Fiber is never treated as a child of an interval
    # that happens to be open in the requesting Fiber.
    #
    # Intervals are settled even if the timed block raises an exception, so
    # partially completed work is still accounted for.
    #
    # The clock used to measure durations is injectable, which makes
    # assertions deterministic in specs.  It must be a callable object
    # returning monotonically increasing values in seconds; durations are
    # converted to milliseconds in the header.  The default clock is
    # Process.clock_gettime(Process::CLOCK_MONOTONIC).
    #
    #   plugin :server_timing, clock: -> { @elapsed += 0.001; @elapsed }
    #
    # The generated header is merged with an existing +Server-Timing+
    # response header: existing entries are preserved verbatim and emitted
    # first, followed by the metrics collected by the plugin.
    #
    # The total byte size of the +Server-Timing+ header is limited using the
    # +header_limit+ option (4096 bytes by default).  Existing entries take
    # precedence and are never truncated by the plugin.  Plugin metrics are
    # then added in first-seen order; a metric that does not fit is skipped
    # (including its +.self+ entry) and later metrics are still considered.
    # Metric entries are never cut off mid-value.
    #
    # === Options
    #
    # :clock :: Callable returning the current monotonic time in seconds
    #           (defaults to +Process.clock_gettime(Process::CLOCK_MONOTONIC)+).
    # :header_limit :: Maximum byte size of the generated Server-Timing
    #                  header (defaults to 4096).
    module ServerTiming
      HEADER_NAME = "Server-Timing".freeze

      # Default upper bound for the size of the Server-Timing header, bytes.
      DEFAULT_HEADER_LIMIT = 4096

      # Characters allowed in an RFC 7230 token.
      TOKEN_CHAR = "A-Za-z0-9!#$%&'*+-.^_`|~".freeze
      TOKEN_START_RE = /\A[#{TOKEN_CHAR}]/n.freeze
      TOKEN_SCAN_RE = /[^#{TOKEN_CHAR}]/n.freeze
      QESCAPE_RE = /([\\"])/
      CONTROL_CHAR_RE = /[\x00-\x08\x0a-\x1f\x7f]/

      # Represents an interval started with #server_timing_start that has not
      # yet been finished.
      class Timer
        attr_reader :name, :description, :fiber, :start_time
        attr_accessor :child_duration

        def initialize(recorder, name, description, fiber, start_time)
          @recorder = recorder
          @name = name
          @description = description
          @fiber = fiber
          @start_time = start_time
          @child_duration = 0.0
          @finished = false
        end

        # Finish the interval and aggregate it.  Calling this more than once
        # has no effect.  Returns nil.
        def finish
          return if @finished
          @finished = true
          @recorder.send(:finish_timer, self)
          nil
        end

        # Whether the interval has already been finished.
        def finished?
          @finished
        end
      end

      # Per-request recorder owning the per-Fiber interval stacks and the
      # aggregated metrics.
      class Recorder
        def initialize(clock, mutex = Mutex.new)
          @clock = clock
          @mutex = mutex
          @stacks = Hash.new { |h, fiber| h[fiber] = [] }
          @metrics = {}
          @order = []
        end

        # Start a named interval and return its Timer.
        def start(name, description)
          timer = Timer.new(self, name, description, Fiber.current, @clock.call)
          @mutex.synchronize do
            metric_for(name)
            @stacks[timer.fiber] << timer
          end
          timer
        end

        # Time the given block, settling the interval even when the block
        # raises.  Returns the block's return value.
        def measure(name, description)
          timer = start(name, description)
          begin
            yield
          ensure
            timer.finish
          end
        end

        # Settle every interval still open on any Fiber, using the current
        # clock value.  Child intervals are settled before their parents.
        def settle_all(time = @clock.call)
          @mutex.synchronize do
            @stacks.each_value do |stack|
              record(stack.pop, time) while stack.last
            end
          end
          nil
        end

        # Build the Server-Timing header value, merging it with +existing+ and
        # bounding the result to +limit+ bytes.  Returns nil when there is
        # nothing to emit.
        def header_value(existing, limit)
          parts = []
          used = 0

          if existing && !existing.empty?
            parts << existing
            used = existing.bytesize
            return existing if used + 2 > limit
            used += 2
          end

          each_entry do |entry|
            size = entry.bytesize
            size += 2 unless parts.empty?
            next if used + size > limit
            parts << entry
            used += size
          end

          return nil if parts.empty?
          parts.join(", ")
        end

        private

        def finish_timer(timer)
          @mutex.synchronize do
            stack = @stacks[timer.fiber]
            if (index = stack.rindex(timer))
              stack.delete_at(index)
              record(timer, @clock.call)
            end
          end
          nil
        end

        # Record one finished interval against its metric and attribute its
        # duration to the exclusive time of the nearest still-open ancestor
        # on the same Fiber.
        def record(timer, end_time)
          duration = end_time - timer.start_time
          duration = 0.0 if duration < 0
          exclusive = duration - timer.child_duration
          exclusive = 0.0 if exclusive < 0

          metric = metric_for(timer.name)
          metric[:total] += duration
          metric[:exclusive] += exclusive
          metric[:count] += 1
          if metric[:description_set]
            metric[:mixed_descriptions] = true if metric[:first_description] != timer.description
          else
            metric[:description_set] = true
            metric[:first_description] = timer.description
          end

          if (parent = @stacks[timer.fiber].last)
            parent.child_duration += duration
          end
        end

        def metric_for(name)
          @metrics.fetch(name) do
            metric = {
              total: 0.0,
              exclusive: 0.0,
              count: 0,
              first_description: nil,
              description_set: false,
              mixed_descriptions: false,
            }
            @metrics[name] = metric
            @order << name
            metric
          end
        end

        # Yield the serialized total entry for each metric in first-seen
        # order, followed by its self entry when the values differ.
        def each_entry
          @order.each do |name|
            metric = @metrics.fetch(name)
            total = metric[:total] * 1000
            exclusive = metric[:exclusive] * 1000
            description = metric[:first_description] if metric[:description_set] && !metric[:mixed_descriptions]
            count = metric[:count]

            yield format_entry(
              ServerTiming.metric_name(name),
              total,
              description,
              count > 1 ? count : nil
            )
            if (total - exclusive).abs > 1e-6
              yield format_entry("#{name}.self", exclusive, nil, nil)
            end
          end
        end

        def format_entry(name, duration, description, count)
          entry = +"#{ServerTiming.metric_name(name)};dur=#{ServerTiming.format_duration(duration)}"
          entry << ";desc=#{ServerTiming.quote(description)}" if description
          entry << ";count=#{count}" if count
          entry
        end
      end

      class << self
        # Turn an arbitrary metric name into a valid RFC 7230 token by
        # replacing every character that is not a token character with +_+.
        def metric_name(name)
          str = name.to_s.dup.force_encoding(Encoding::UTF_8)
          str.gsub!(TOKEN_SCAN_RE, "_")
          str[0] = "_" unless str.empty? || str[0] =~ TOKEN_START_RE
          str
        end

        # Escape a description for use inside a quoted-string: backslashes
        # and double quotes get a backslash prefix, and header control
        # characters (other than tab) are removed.
        def quote(value)
          str = value.to_s.gsub(CONTROL_CHAR_RE, "")
          "\"#{str.gsub(QESCAPE_RE, '\\\\\\1')}\""
        end

        # Format a millisecond duration without floating point noise.
        def format_duration(duration)
          rounded = duration.round(6)
          rounded == rounded.to_i ? rounded.to_i.to_s : rounded.to_s
        end

        # Name of the response header (lower case on Rack 3).
        def header_name
          if defined?(Rack::Headers) && Rack::Headers.is_a?(Class)
            HEADER_NAME.downcase
          else
            HEADER_NAME
          end
        end
      end

      def self.configure(app, opts = RodaPlugins::OPTS)
        if opts.key?(:clock)
          clock = opts[:clock]
          raise Roda::RodaError, "server_timing :clock option must respond to #call" unless clock.respond_to?(:call)
          app.opts[:server_timing_clock] = clock
        end
        if opts.key?(:header_limit)
          limit = opts[:header_limit]
          raise Roda::RodaError, "server_timing :header_limit option must be an Integer" unless limit.is_a?(Integer)
          app.opts[:server_timing_header_limit] = limit
        end
      end

      def self.load_dependencies(app, *_args, &_block)
        # Loaded first so that server_timing's dispatcher wraps the
        # error_handler dispatcher: when a rescued exception rebuilds the
        # response, server_timing's outer +ensure+ block can still attach the
        # settled timings to it.  No error handler is installed by default,
        # so this only changes the dispatch wrapping.
        app.plugin :error_handler
      end

      module ClassMethods
        # Callable returning the current monotonic clock value in seconds.
        def server_timing_clock
          opts[:server_timing_clock] ||
            -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
        end

        # Maximum byte size of the generated Server-Timing header.
        def server_timing_header_limit
          opts[:server_timing_header_limit] || DEFAULT_HEADER_LIMIT
        end
      end

      module InstanceMethods
        # Time the given block and associate it with +name+.  The block's
        # return value is returned.  The optional +description+ is reported
        # in the +desc+ parameter of the header.
        def server_timing(name, description = nil)
          _server_timing_recorder!.measure(name, description) { yield }
        end

        # Start a named interval without a block.  Finish it with
        # #server_timing_finish.
        def server_timing_start(name, description = nil)
          _server_timing_recorder!.start(name, description)
        end

        # Finish an interval returned by #server_timing_start.  Returns nil.
        def server_timing_finish(timer)
          timer.finish
        end

        # The per-request ServerTiming::Recorder.
        def server_timing_recorder
          @_server_timing_recorder
        end

        # Run the main route with a recorder available, settle every open
        # interval in an +ensure+ block (so an exception still closes them),
        # and append the Server-Timing header to the finished response.
        def _roda_handle_main_route
          @_server_timing_recorder ||=
            ServerTiming::Recorder.new(self.class.server_timing_clock)
          begin
            res = super
          ensure
            @_server_timing_recorder.settle_all
            _server_timing_write_header(res[1]) if res
          end
          res
        end

        private

        def _server_timing_recorder!
          @_server_timing_recorder ||=
            ServerTiming::Recorder.new(self.class.server_timing_clock)
        end

        # Merge the recorded metrics into any existing Server-Timing header in
        # the given headers hash, respecting the configured header limit.
        def _server_timing_write_header(headers)
          canonical = ServerTiming.header_name
          existing = headers.delete(canonical)
          existing ||= headers.delete(ServerTiming::HEADER_NAME)

          value = @_server_timing_recorder.header_value(
            existing,
            self.class.server_timing_header_limit
          )
          headers[canonical] = value if value
        end
      end
    end

    register_plugin(:server_timing, ServerTiming)
  end
end
