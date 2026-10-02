# frozen_string_literal: true

require_relative "../spec_helper"
require_relative "../support/freeze_time_helper"

describe "shadow_throttle" do
  before do
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  let(:events) { [] }

  def app_calls
    @app_calls ||= []
  end

  def app
    calls = app_calls

    Rack::Builder.new do
      use Rack::Lint
      use Rack::Attack
      run lambda { |_env|
        calls << 1
        [200, {}, ['Hello World']]
      }
    end.to_app
  end

  def subscribe_events
    {
      "throttle.rack_attack" => :throttle,
      "shadow_throttle.rack_attack" => :shadow_throttle,
      "shadow_throttle_error.rack_attack" => :shadow_throttle_error
    }.each do |event_name, tag|
      ActiveSupport::Notifications.subscribe(event_name) do |_name, _start, _finish, _id, payload|
        events.push([tag, payload])
      end
    end
  end

  def counter_value(name, discriminator, period)
    key = "rack::attack:#{Time.now.to_i / period}:#{name}:#{discriminator}"
    Rack::Attack.cache.store.read(key)
  end

  it "runs both groups over the same batch with isolated counts, app calls and event order" do
    Rack::Attack.throttle("req/ip", limit: 2, period: 60) { |req| req.ip }
    Rack::Attack.shadow_throttle("req/ip", limit: 3, period: 60) { |req| req.ip }
    Rack::Attack.shadow_throttle_on_reject = true
    subscribe_events

    statuses = within_same_period do
      6.times.map { get "/", {}, "REMOTE_ADDR" => "1.2.3.4"; last_response.status }
    end

    # The shadow group never changes the response: only the real group decides.
    _(statuses).must_equal [200, 200, 429, 429, 429, 429]
    _(app_calls.size).must_equal 2

    # Counters are fully isolated even though both rules share a name and
    # discriminator: each group counted all 6 requests on its own.
    _(counter_value("req/ip", "1.2.3.4", 60)).must_equal 6
    _(counter_value("shadow:req/ip", "1.2.3.4", 60)).must_equal 6

    # Real hits and hypothetical hits are distinct events, in request order:
    # req3-6 hit the real throttle, req4-6 would have hit the shadow throttle.
    _(events.map(&:first)).must_equal [
      :throttle,
      :throttle, :shadow_throttle,
      :throttle, :shadow_throttle,
      :throttle, :shadow_throttle
    ]

    real_event = events.find { |name, _| name == :throttle }.last
    _(real_event[:request].env["rack.attack.matched"]).must_equal "req/ip"

    shadow_events = events.select { |name, _| name == :shadow_throttle }
    _(shadow_events.size).must_equal 3

    shadow_payload = shadow_events.first.last
    _(shadow_payload[:matched]).must_equal "req/ip"
    _(shadow_payload[:match_data][:count]).must_equal 4
    _(shadow_payload[:match_data][:limit]).must_equal 3

    # Shadow events only carry a limited view of the request, not the full env.
    _(shadow_payload[:request]).must_equal(ip: "1.2.3.4", method: "GET", path: "/")
  end

  it "does not consume the real rules' counts nor change their verdict" do
    Rack::Attack.throttle("real/ip", limit: 3, period: 60) { |req| req.ip }
    Rack::Attack.shadow_throttle("eager/ip", limit: 1, period: 60) { |req| req.ip }
    subscribe_events

    statuses = within_same_period do
      3.times.map { get "/", {}, "REMOTE_ADDR" => "1.2.3.4"; last_response.status }
    end

    # The shadow limit was exceeded on requests 2 and 3, yet everything passes.
    _(statuses).must_equal [200, 200, 200]
    _(app_calls.size).must_equal 3

    # Shadow evaluations never incremented the real counter.
    _(counter_value("real/ip", "1.2.3.4", 60)).must_equal 3
    _(counter_value("shadow:eager/ip", "1.2.3.4", 60)).must_equal 3

    _(events.map(&:first)).must_equal [:shadow_throttle, :shadow_throttle]

    # Hypothetical hits are annotated separately from real match data.
    _(last_request.env["rack.attack.matched"]).must_be_nil
    _(last_request.env["rack.attack.throttle_data"].keys).must_equal ["real/ip"]
    _(last_request.env["rack.attack.shadow_throttle_data"]["eager/ip"][:count]).must_equal 3
    _(last_request.env["rack.attack.shadow_matches"]["eager/ip"][:count]).must_equal 3
  end

  it "skips shadow evaluation on rejected requests by default" do
    Rack::Attack.throttle("real/ip", limit: 1, period: 60) { |req| req.ip }
    Rack::Attack.shadow_throttle("shadow/ip", limit: 100, period: 60) { |req| req.ip }

    within_same_period do
      3.times { get "/", {}, "REMOTE_ADDR" => "1.2.3.4" }
    end

    _(last_response.status).must_equal 429
    _(app_calls.size).must_equal 1
    _(counter_value("real/ip", "1.2.3.4", 60)).must_equal 3
    _(counter_value("shadow:shadow/ip", "1.2.3.4", 60)).must_equal 1
  end

  it "records shadow results on rejected requests when configured" do
    Rack::Attack.throttle("real/ip", limit: 1, period: 60) { |req| req.ip }
    Rack::Attack.shadow_throttle("shadow/ip", limit: 100, period: 60) { |req| req.ip }
    Rack::Attack.shadow_throttle_on_reject = true

    within_same_period do
      3.times { get "/", {}, "REMOTE_ADDR" => "1.2.3.4" }
    end

    _(last_response.status).must_equal 429
    _(app_calls.size).must_equal 1
    _(counter_value("real/ip", "1.2.3.4", 60)).must_equal 3
    _(counter_value("shadow:shadow/ip", "1.2.3.4", 60)).must_equal 3
    _(last_request.env["rack.attack.shadow_throttle_data"]["shadow/ip"][:count]).must_equal 3
  end

  it "keeps the real verdict when a shadow rule raises" do
    Rack::Attack.throttle("real/ip", limit: 5, period: 60) { |req| req.ip }
    Rack::Attack.shadow_throttle("broken/ip", limit: 1, period: 60) { |_req| raise "boom" }
    Rack::Attack.shadow_throttle("healthy/ip", limit: 1, period: 60) { |req| req.ip }
    subscribe_events

    within_same_period do
      2.times { get "/", {}, "REMOTE_ADDR" => "1.2.3.4" }
    end

    # The response and the real counts are untouched by the shadow failure,
    # and the remaining shadow rules still ran.
    _(last_response.status).must_equal 200
    _(app_calls.size).must_equal 2
    _(counter_value("real/ip", "1.2.3.4", 60)).must_equal 2
    _(counter_value("shadow:healthy/ip", "1.2.3.4", 60)).must_equal 2

    error_events = events.select { |name, _| name == :shadow_throttle_error }
    _(error_events.size).must_equal 2

    error_payload = error_events.first.last
    _(error_payload[:matched]).must_equal "broken/ip"
    _(error_payload[:error][:class]).must_equal "RuntimeError"
    _(error_payload[:error][:message]).must_equal "boom"
    _(error_payload[:request]).must_equal(ip: "1.2.3.4", method: "GET", path: "/")
  end

  it "keeps the rejection when a shadow rule raises on a rejected request" do
    Rack::Attack.throttle("real/ip", limit: 1, period: 60) { |req| req.ip }
    Rack::Attack.shadow_throttle("broken/ip", limit: 1, period: 60) { |_req| raise "boom" }
    Rack::Attack.shadow_throttle_on_reject = true
    subscribe_events

    within_same_period do
      2.times { get "/", {}, "REMOTE_ADDR" => "1.2.3.4" }
    end

    _(last_response.status).must_equal 429
    _(app_calls.size).must_equal 1
    _(events.map(&:first)).must_equal [:shadow_throttle_error, :throttle, :shadow_throttle_error]
  end
end
