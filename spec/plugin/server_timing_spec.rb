require_relative "../spec_helper"

describe "server_timing plugin" do
  def clock_app(max_header_bytes=nil, &block)
    clock = FixedClock.new
    options = {:clock => clock}
    options[:max_header_bytes] = max_header_bytes unless max_header_bytes.nil?

    app(:bare) do
      plugin :server_timing, options
      route(&block)
    end
    clock
  end

  def timing_header(response)
    response[1].fetch("server-timing") do
      response[1]["Server-Timing"]
    end
  end

  class FixedClock
    attr_reader :now

    def initialize
      @now = 1000
    end

    def call
      @now
    end

    def advance(seconds)
      @now += seconds
    end
  end

  it "emits exact durations from an injected clock" do
    clock = clock_app do |r|
      timed("db", "Load user") do
        clock.advance(1)
      end
      r.server_timing("view") do
        clock.advance(Rational(1, 2))
      end
      "ok"
    end

    timing_header(req).must_equal \
      %(db;dur=1000;desc="Load user", view;dur=500)
  end

  it "records total and self durations for nested intervals" do
    clock = clock_app do |r|
      server_timing("view", "Render") do
        clock.advance(4)
        server_timing("db", "Query") do
          clock.advance(3)
        end
        clock.advance(1)
      end
      "ok"
    end

    timing_header(req).must_equal \
      %(view;dur=8000;desc="Render", view.self;dur=5000;desc="Render (self)", db;dur=3000;desc="Query")
  end

  it "aggregates repeated names by summing total and self times and keeping the first description" do
    clock = clock_app do |r|
      server_timing("db", "Queries") do
        clock.advance(5)
        server_timing("template", "Layout") do
          clock.advance(2)
        end
      end

      server_timing("db") do
        clock.advance(3)
      end

      server_timing("db") do
        clock.advance(1)
        server_timing("template", "Ignored") do
          clock.advance(1)
        end
      end

      "ok"
    end

    timing_header(req).must_equal \
      %(db;dur=12000;desc="Queries", db.self;dur=9000;desc="Queries (self)", template;dur=3000;desc="Layout")
  end

  it "settles intervals when an exception exits the block" do
    clock = clock_app do |r|
      server_timing("outer", "Outer") do
        clock.advance(5)
        server_timing("inner", "Inner") do
          clock.advance(2)
          raise ArgumentError, "boom"
        end
      end
    end

    begin
      req
    rescue ArgumentError => e
      e.message.must_equal "boom"
    else
      flunk "expected the route exception to be raised"
    end

  end

  it "settles caught exceptions for the error response" do
    clock = FixedClock.new
    app(:bare) do
      plugin :server_timing, :clock => clock
      plugin :error_handler do |e|
        e.message
      end

      route do |r|
        server_timing("work", "Work") do
          clock.advance(3)
          raise StandardError, "failure"
        end
      end
    end

    response = req
    response[0].must_equal 500
    timing_header(response).must_equal %(work;dur=3000;desc="Work")
    body.must_equal "failure"
  end

  it "does not treat intervals in child Fibers as parent intervals" do
    clock = clock_app do |r|
      result = nil

      server_timing("outer", "Outer") do
        clock.advance(1)

        fiber = Fiber.new do
          server_timing("child", "Child") do
            clock.advance(2)
          end
        end

        fiber.resume
        result = fiber
        clock.advance(3)
      end

      result.inspect
    end

    timing_header(req).must_equal \
      %(outer;dur=6000;desc="Outer", child;dur=2000;desc="Child")
  end

  it "escapes descriptions" do
    clock_app do |r|
      server_timing("x", "hello \"world\" \\\r\n \u0000") do
      end
      "ok"
    end

    timing_header(req).must_equal %(x;dur=0;desc="hello \\"world\\" \\\\  ")
  end

  it "rejects metric names that are not header tokens" do
    clock_app do |r|
      server_timing("bad name") { }
    end

    proc { req }.must_raise Roda::RodaError
  end

  it "merges an existing Server-Timing string before generated metrics" do
    clock = clock_app do |r|
      response["server-timing"] = %(existing;dur=12;desc="Already present")
      server_timing("db", "Query") do
        clock.advance(2)
      end
      "ok"
    end

    timing_header(req).must_equal \
      %(existing;dur=12;desc="Already present", db;dur=2000;desc="Query")
  end

  it "merges an existing Server-Timing array before generated metrics" do
    clock = clock_app do |r|
      response["server-timing"] = [%(one;dur=1), %(two;dur=2)]
      server_timing("db") do
        clock.advance(2)
      end
      "ok"
    end

    timing_header(req).must_equal "one;dur=1, two;dur=2, db;dur=2000"
  end

  it "keeps metrics in deterministic first-started order when truncated" do
    clock = clock_app(35) do |r|
      server_timing("one", "one") do
        clock.advance(1)
      end
      server_timing("two", "two") do
        clock.advance(2)
      end
      "ok"
    end

    timing_header(req).must_equal %(one;dur=1000;desc="one")
  end

  it "keeps nested total and self metrics together when truncated" do
    clock = clock_app(63) do |r|
      server_timing("one", "one") do
        clock.advance(1)
        server_timing("inner", "inner") do
          clock.advance(1)
        end
      end
      server_timing("two", "two") do
        clock.advance(2)
      end
      "ok"
    end

    timing_header(req).must_equal \
      %(one;dur=2000;desc="one", one.self;dur=1000;desc="one (self)")
  end

  it "preserves an existing header that exceeds the configured limit" do
    clock = clock_app(20) do |r|
      response["server-timing"] = %(existing;desc="This is a long existing metric")
      server_timing("db") do
        clock.advance(1)
      end
      "ok"
    end

    timing_header(req).must_equal %(existing;desc="This is a long existing metric")
  end

  it "supports a zero header limit" do
    clock = clock_app(0) do |r|
      server_timing("db") do
        clock.advance(1)
      end
      "ok"
    end

    req[1].wont_include "server-timing"
    req[1].wont_include "Server-Timing"
  end

  it "does not set a header when no intervals are recorded" do
    clock_app do |r|
      "ok"
    end

    req[1].wont_include "server-timing"
    req[1].wont_include "Server-Timing"
  end

  it "supports shape-friendly instances" do
    clock = FixedClock.new
    app(:bare) do
      plugin :shape_friendly
      plugin :server_timing, :clock => clock
      route do |r|
        server_timing("db") do
          clock.advance(1)
        end
        "ok"
      end
    end

    timing_header(req).must_equal "db;dur=1000"
  end

  it "works when the application is frozen" do
    clock = FixedClock.new
    app(:bare) do
      plugin :server_timing, :clock => clock
      route do |r|
        timed("db") do
          clock.advance(1)
        end
        "ok"
      end
    end
    app.freeze

    timing_header(req).must_equal "db;dur=1000"
  end

  it "works with the deprecated dispatch API" do
    clock = FixedClock.new
    app = Class.new(Roda)
    app.plugin :server_timing, :clock => clock
    app.route do |r|
      server_timing("db") do
        clock.advance(1)
      end
      "ok"
    end

    env = req_env({})
    response = app.new(env).call(&app.route_block)
    timing_header(response).must_equal "db;dur=1000"
  end
end
