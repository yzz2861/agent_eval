require_relative "../spec_helper"
require_relative "../../lib/roda/plugins/server_timing"

describe "server_timing plugin" do
  # Deterministic monotonic clock measured in seconds, mirroring the default
  # Process::CLOCK_MONOTONIC clock.
  clock_class = Class.new do
    attr_accessor :now

    def initialize
      @now = 0.0
    end

    def call
      @now
    end

    def advance(seconds)
      @now += seconds
    end
  end

  def timing_header
    req("/", "rack.input" => rack_input)[1][@header_key]
  end

  before do
    @clock = clock_class.new
    @header_key = Roda::RodaPlugins::ServerTiming.header_name
  end

  it "emits a Server-Timing header with exact durations from the injected clock" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        clock.advance(0.010)
        server_timing("db") { clock.advance(0.025) }
        "ok"
      end
    end

    timing_header.must_equal "db;dur=25"
  end

  it "returns the block's return value" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        result = server_timing("db") do
          clock.advance(0.001)
          42
        end
        result.to_s
      end
    end

    body.must_equal "42"
    timing_header.must_equal "db;dur=1"
  end

  it "reports descriptions escaped for quoted strings and strips control characters" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("db", %(user "quote" \\ slash\nline)) { clock.advance(0.001) }
        ""
      end
    end

    timing_header.must_equal %(db;dur=1;desc="user \\"quote\\" \\\\ slashline")
  end

  it "escapes invalid metric name characters to underscores" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing(:"db/users 1") { clock.advance(0.002) }
        ""
      end
    end

    timing_header.must_equal "db_users_1;dur=2"
  end

  it "preserves non-ASCII descriptions in the quoted string" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("db", "用户 查询") { clock.advance(0.001) }
        ""
      end
    end

    timing_header.must_equal "db;dur=1;desc=\"用户 查询\""
  end

  it "reports total and exclusive durations for nested intervals" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("total") do
          clock.advance(0.020)
          server_timing("db") { clock.advance(0.030) }
          clock.advance(0.005)
          server_timing("view") { clock.advance(0.002) }
          clock.advance(0.003)
        end
        ""
      end
    end

    timing_header.must_equal(
      "total;dur=60, total.self;dur=28, db;dur=30, view;dur=2"
    )
  end

  it "sums same-named calls, appends the count, and aggregates self time" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("db", "users query") { clock.advance(0.030) }
        server_timing("db", "users query") do
          clock.advance(0.010)
          server_timing("sub") { clock.advance(0.004) }
        end
        ""
      end
    end

    timing_header.must_equal(
      %(db;dur=44;desc="users query";count=2, db.self;dur=40, sub;dur=4)
    )
  end

  it "omits descriptions when calls with the same name use different descriptions" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("db", "one") { clock.advance(0.001) }
        server_timing("db", "two") { clock.advance(0.001) }
        ""
      end
    end

    timing_header.must_equal "db;dur=2;count=2"
  end

  it "keeps a shared description when other calls omit theirs" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("db", "one") { clock.advance(0.001) }
        server_timing("db") { clock.advance(0.001) }
        ""
      end
    end

    timing_header.must_equal "db;dur=2;count=2"
  end

  it "emits metrics in the order the metric name is first seen" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("alpha") do
          clock.advance(0.001)
          server_timing("beta") { clock.advance(0.001) }
        end
        server_timing("alpha") { clock.advance(0.001) }
        server_timing("gamma") { clock.advance(0.001) }
        ""
      end
    end

    timing_header.must_equal(
      "alpha;dur=3;count=2, alpha.self;dur=2, beta;dur=1, gamma;dur=1"
    )
  end

  it "settles intervals whose block raises and re-raises the exception" do
    clock = @clock
    raised = false
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        begin
          server_timing("outer") do
            clock.advance(0.010)
            server_timing("inner") do
              clock.advance(0.020)
              raise StandardError, "boom"
            end
          end
        rescue StandardError
          raised = true
        end
        "ok"
      end
    end

    body.must_equal "ok"
    raised.must_equal true
    timing_header.must_equal(
      "outer;dur=30, outer.self;dur=10, inner;dur=20"
    )
  end

  it "settles intervals still open when the route raises, using the error handler response" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      plugin :error_handler do |e|
        "handled"
      end
      route do |r|
        server_timing_start("open")
        clock.advance(0.015)
        raise StandardError, "boom"
      end
    end

    response = req("/", "rack.input" => rack_input)
    response[0].must_equal 500
    response[1][@header_key].must_equal "open;dur=15"
  end

  it "does not treat intervals in other Fibers as children of open intervals" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("outer") do
          clock.advance(0.010)
          fiber = Fiber.new do
            server_timing("fiber_work") { clock.advance(0.020) }
          end
          fiber.resume
          clock.advance(0.005)
        end
        ""
      end
    end

    timing_header.must_equal(
      "outer;dur=35, fiber_work;dur=20"
    )
  end

  it "tracks independent nested stacks per Fiber" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("outer") do
          clock.advance(0.010)
          fiber = Fiber.new do
            server_timing("fparent") do
              clock.advance(0.004)
              server_timing("fchild") { clock.advance(0.006) }
            end
          end
          fiber.resume
          clock.advance(0.001)
        end
        ""
      end
    end

    timing_header.must_equal(
      "outer;dur=21, fparent;dur=10, fparent.self;dur=4, fchild;dur=6"
    )
  end

  it "aggregates concurrent thread intervals without cross-attribution" do
    clock = @clock
    mutex = Mutex.new
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("request") do
          threads = 4.times.map do |i|
            Thread.new(i) do
              server_timing("work", "thread") do
                mutex.synchronize { clock.advance(0.002) }
              end
            end
          end
          threads.each(&:join)
          clock.advance(0.001)
        end
        ""
      end
    end

    timing_header.must_equal(
      %(request;dur=9, work;dur=8;desc="thread";count=4)
    )
  end

  it "supports start/finish without a block" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        timer = server_timing_start("db", "manual")
        clock.advance(0.012)
        server_timing_finish(timer)
        clock.advance(0.001)
        ""
      end
    end

    timing_header.must_equal %(db;dur=12;desc="manual")
  end

  it "makes finishing a timer a no-op when called twice" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        timer = server_timing_start("db")
        clock.advance(0.010)
        server_timing_finish(timer)
        clock.advance(0.020)
        server_timing_finish(timer)
        ""
      end
    end

    timing_header.must_equal "db;dur=10"
  end

  it "merges with an existing Server-Timing header, keeping existing entries first" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        response.headers["server-timing"] = %q(cache;dur=3;desc="hit")
        server_timing("db") { clock.advance(0.007) }
        ""
      end
    end

    timing_header.must_equal %(cache;dur=3;desc="hit", db;dur=7)
  end

  it "finds an existing header regardless of the key casing used" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        response.headers["Server-Timing"] = "cache;dur=3"
        server_timing("db") { clock.advance(0.007) }
        ""
      end
    end

    value = timing_header
    value.must_include "db;dur=7"
    value.must_include "cache;dur=3"
  end

  it "limits header size, keeping existing entries and later fitting metrics" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock, header_limit: 32
      route do |r|
        response.headers["server-timing"] = "existing;dur=1"
        server_timing("long_metric_name") { clock.advance(0.001) }
        server_timing("x") { clock.advance(0.002) }
        ""
      end
    end

    value = timing_header
    value.bytesize.must_be :<=, 52
    value.must_equal "existing;dur=1, x;dur=2"
  end

  it "keeps the existing header unchanged when it alone reaches the limit" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock, header_limit: 10
      route do |r|
        response.headers["server-timing"] = "existing;dur=1"
        server_timing("db") { clock.advance(0.001) }
        ""
      end
    end

    timing_header.must_equal "existing;dur=1"
  end

  it "emits no plugin metrics when the header limit is zero" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock, header_limit: 0
      route do |r|
        server_timing("db") { clock.advance(0.001) }
        ""
      end
    end

    req("/", "rack.input" => rack_input)[1].wont_include @header_key
  end

  it "pairs self entries with their total entry when truncating" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock, header_limit: 10
      route do |r|
        server_timing("very_long_name") do
          clock.advance(0.001)
          server_timing("child") { clock.advance(0.001) }
        end
        server_timing("x") do
          clock.advance(0.001)
        end
        ""
      end
    end

    value = timing_header
    value.bytesize.must_be :<=, 30
    value.must_equal "x;dur=1"
  end

  it "uses sub-millisecond precision" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("db") { clock.advance(0.00025) }
        ""
      end
    end

    timing_header.must_equal "db;dur=0.25"
  end

  it "emits the header for responses finished early with r.halt" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        r.get "halted" do
          server_timing("db") { clock.advance(0.005) }
          response.status = 201
          r.halt response.finish_with_body([])
        end
        ""
      end
    end

    response = req("/halted", "rack.input" => rack_input)
    response[0].must_equal 201
    response[1][@header_key].must_equal "db;dur=5"
  end

  it "settles intervals left open in non-resumed Fibers at request end" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        fiber = Fiber.new do
          server_timing("never_resumed") do
            clock.advance(0.002)
            Fiber.yield
            clock.advance(0.003)
          end
        end
        server_timing("main") do
          clock.advance(0.004)
          fiber.resume
          clock.advance(0.001)
        end
        ""
      end
    end

    # The yielded Fiber leaves its interval open; settle_all at request end
    # closes it at the final clock time (3ms after it started).  Because the
    # Fiber interval is on a different stack, it is not counted as a child
    # of the main interval.
    timing_header.must_equal(
      "main;dur=7, never_resumed;dur=3"
    )
  end

  it "works with a frozen Roda class" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        server_timing("db") { clock.advance(0.001) }
        ""
      end
      freeze
    end

    timing_header.must_equal "db;dur=1"
  end

  it "inherits options in subclasses" do
    clock = @clock
    parent = Class.new(Roda)
    parent.plugin :server_timing, clock: clock, header_limit: 1000
    @app = Class.new(parent)
    @app.route do |r|
      server_timing("db") { clock.advance(0.001) }
      ""
    end

    timing_header.must_equal "db;dur=1"
    app.server_timing_header_limit.must_equal 1000
  end

  it "does not emit a header when no intervals were recorded and none existed" do
    clock = @clock
    app(:bare) do
      plugin :server_timing, clock: clock
      route do |r|
        ""
      end
    end

    req("/", "rack.input" => rack_input)[1].wont_include @header_key
  end

  it "accepts the default monotonic clock and emits millisecond durations" do
    app(:bare) do
      plugin :server_timing
      route do |r|
        server_timing("db") { sleep 0.001 }
        ""
      end
    end

    value = timing_header
    match = /\Adb;dur=(\d+(?:\.\d+)?)\z/.match(value)
    match.wont_be_nil
    Float(match[1]).must_be :>=, 0.5
  end

  it "raises for a non-callable clock and a non-integer header limit" do
    proc do
      Class.new(Roda) { plugin :server_timing, clock: 1 }
    end.must_raise Roda::RodaError

    proc do
      Class.new(Roda) { plugin :server_timing, header_limit: "10" }
    end.must_raise Roda::RodaError
  end
end
