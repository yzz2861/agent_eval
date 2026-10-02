# frozen_string_literal: true

require_relative "spec_helper"

describe "Rack::Attack throttle reservations" do
  before do
    Rack::Attack.cache.store = Rack::Attack::MemoryStore.new
    @app = ->(_env) { [200, {}, ["ok"]] }
  end

  def app
    Rack::Attack.new(@app)
  end

  def counter_value(discriminator = "1.2.3.4")
    key = "rack::attack:#{Time.now.to_i / 60}:login:#{discriminator}"
    Rack::Attack.cache.store.read(key)
  end

  def counter_named(name, discriminator = "1.2.3.4")
    key = "rack::attack:#{Time.now.to_i / 60}:#{name}:#{discriminator}"
    Rack::Attack.cache.store.read(key)
  end

  def configure_throttle(**options)
    Rack::Attack.throttle("login", limit: 1, period: 60, **options) do |request|
      request.ip
    end
  end

  it "keeps a reservation when the response is a failed attempt" do
    configure_throttle(reserve: true)
    @app = ->(_env) { [401, {}, ["unauthorized"]] }

    get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

    assert_equal 401, last_response.status
    assert_equal 1, counter_value
  end

  it "returns a reservation for a successful response after the body closes" do
    configure_throttle(reserve: true)

    get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

    assert_equal 200, last_response.status
    assert_nil counter_value
  end

  it "keeps a reservation when the application raises an exception" do
    configure_throttle(reserve: true)
    @app = ->(_env) { raise RuntimeError, "boom" }

    assert_raises(RuntimeError) do
      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    end

    assert_equal 1, counter_value
  end

  it "keeps a reservation when a deferred body raises after the response status" do
    configure_throttle(reserve: true)
    delayed_error_body = Object.new
    def delayed_error_body.each
      raise RuntimeError, "body boom"
    end
    @app = ->(_env) { [200, {}, delayed_error_body] }

    assert_raises(RuntimeError) do
      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    end

    assert_equal 1, counter_value
  end

  it "returns a reservation when the client closes early" do
    configure_throttle(reserve: true)
    @app = ->(_env) { raise Errno::ECONNRESET }

    assert_raises(Errno::ECONNRESET) do
      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    end

    assert_nil counter_value
  end

  it "returns a reservation when a deferred body reports client disconnection" do
    configure_throttle(reserve: true)
    delayed_error_body = Object.new
    def delayed_error_body.each
      raise Errno::EPIPE
    end
    @app = ->(_env) { [200, {}, delayed_error_body] }

    assert_raises(Errno::EPIPE) do
      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
    end

    assert_nil counter_value
  end

  it "supports a custom failure policy based on status and error" do
    configure_throttle(
      reserve: true,
      failed_if: ->(status, error) { error.nil? && status == 422 }
    )

    unauthorized = Rack::Attack.new(->(_env) { [401, {}, ["unauthorized"]] })
    invalid = Rack::Attack.new(->(_env) { [422, {}, ["invalid"]] })
    Rack::MockRequest.new(unauthorized).get("/", "REMOTE_ADDR" => "1.2.3.5")
    assert_nil counter_value("1.2.3.5")

    response = Rack::MockRequest.new(invalid).get("/", "REMOTE_ADDR" => "1.2.3.4")
    assert_equal 422, response.status
    assert_equal 1, counter_value
  end

  it "settles mixed response-time and body-time policies independently" do
    Rack::Attack.throttle("status", limit: 1, period: 60, reserve: true,
                                       failed_if: ->(status, _error) { status == 422 }) do |request|
      request.ip
    end
    Rack::Attack.throttle("exception", limit: 1, period: 60, reserve: true,
                                          failed_if: ->(_status, error) { !error.nil? }) do |request|
      request.ip
    end

    body = Object.new
    def body.each; yield "invalid"; end
    def body.close; end
    middleware = Rack::Attack.new(->(_env) { [422, {}, body] })
    _status, _headers, wrapped_body = middleware.call(
      Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "1.2.3.4")
    )

    assert_equal 1, counter_named("status")

    wrapped_body.close
    assert_equal 1, counter_named("status")
    assert_nil counter_named("exception")
  end

  it "rejects concurrent requests before the first response is known" do
    configure_throttle(reserve: true)
    entered = Queue.new
    outcome = Queue.new
    @app = lambda do |_env|
      entered << :ready
      result = outcome.pop
      raise(result) if result.is_a?(Exception)
      result
    end
    middleware = app
    env = Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "1.2.3.4")

    first = Thread.new { middleware.call(env) }.tap { |thread| thread.report_on_exception = false }
    entered.pop

    status, _headers, _body = middleware.call(
      Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "1.2.3.4")
    )
    assert_equal 429, status
    assert_equal 1, counter_value

    outcome << [200, {}, ["ok"]]
    _status, _headers, first_body = first.value
    first_body.close
    assert_nil counter_value
  end

  it "retains the failed reservation for a blocked concurrent request" do
    configure_throttle(reserve: true)
    entered = Queue.new
    outcome = Queue.new
    @app = lambda do |_env|
      entered << :ready
      result = outcome.pop
      raise(result) if result.is_a?(Exception)
      result
    end
    middleware = app
    env = Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "1.2.3.4")

    first = Thread.new { middleware.call(env) }.tap { |thread| thread.report_on_exception = false }
    entered.pop
    _status, _headers, _body = middleware.call(
      Rack::MockRequest.env_for("/", "REMOTE_ADDR" => "1.2.3.4")
    )

    outcome << RuntimeError.new("boom")
    assert_raises(RuntimeError) { first.value }
    assert_equal 1, counter_value
  end
end

describe "Rack::Attack::MemoryStore reservations" do
  before do
    Rack::Attack.cache.store = Rack::Attack::MemoryStore.new
  end

  it "issues independent credentials and settles each only once" do
    first = Rack::Attack.cache.reserve("login", 60, 2)
    second = Rack::Attack.cache.reserve("login", 60, 2)
    third = Rack::Attack.cache.reserve("login", 60, 2)

    assert first.accepted?
    assert second.accepted?
    refute third.accepted?
    refute_equal first.token, second.token

    assert Rack::Attack.cache.settle(first, false)
    assert_equal 1, Rack::Attack.cache.store.read("rack::attack:#{Time.now.to_i / 60}:login")
    refute Rack::Attack.cache.settle(first, false)
    assert_equal 1, Rack::Attack.cache.store.read("rack::attack:#{Time.now.to_i / 60}:login")

    assert Rack::Attack.cache.settle(second, true)
    assert_equal 1, Rack::Attack.cache.store.read("rack::attack:#{Time.now.to_i / 60}:login")
    refute Rack::Attack.cache.settle(second, false)
    assert_equal 1, Rack::Attack.cache.store.read("rack::attack:#{Time.now.to_i / 60}:login")
  end

  it "never produces a negative counter when returning a reservation" do
    store = Rack::Attack::MemoryStore.new
    _accepted, _count, _epoch = store.reserve("counter", 1, 1, 10, "token", 0)
    store.write("counter", 0)

    assert store.settle("token", false)
    assert_nil store.read("counter")
    refute store.settle("token", false)
    assert_nil store.read("counter")
  end

  it "keeps counts non-negative across controlled interleaving" do
    store = Rack::Attack::MemoryStore.new
    accepted_results = Queue.new
    observations = []
    reservations_accepted = Queue.new

    workers = 2.times.map do |index|
      Thread.new do
        accepted, _count, _epoch = store.reserve(
          "counter",
          1,
          2,
          10,
          "reservation-#{index}",
          0
        )
        accepted_results << accepted
        reservations_accepted.pop
      end
    end

    2.times do
      assert accepted_results.pop
      reservations_accepted << :continue
    end
    workers.each(&:join)

    ["reservation-1", "reservation-0"].each do |token|
      assert store.settle(token, false)
      observations << store.read("counter").to_i
    end

    accepted, _count, _epoch = store.reserve("counter", 1, 2, 10, "third", 0)

    assert accepted
    assert_equal [1, 0], observations
    assert_equal 1, store.read("counter")
  end

  it "does not refund a reservation into a newer window" do
    store = Rack::Attack::MemoryStore.new
    store.reserve("rack::attack:0:login", 1, 1, 1, "old", 59)
    store.write("rack::attack:1:login", 5)

    assert store.settle("old", false)
    assert_equal 5, store.read("rack::attack:1:login")
    assert_nil store.read("rack::attack:0:login")
  end
end
