# frozen_string_literal: true

require_relative "spec_helper"
require "timecop"

describe "Rack::Attack.shadow_throttle" do
  let(:events) { [] }

  before do
    @period = 60
    @application_calls = 0
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    @application = ->(_env) do
      @application_calls += 1
      [200, {}, ["ok"]]
    end

    Rack::Attack.throttle("formal", limit: 1, period: @period) { |request| request.ip }
    Rack::Attack.shadow_throttle("shadow lenient", limit: 2, period: @period) { |request| request.ip }
    Rack::Attack.shadow_throttle("shadow strict", limit: 0, period: @period) { |request| request.ip }

    event_pattern = /(throttle|shadow_throttle)\.rack_attack/
    @subscriber = ActiveSupport::Notifications.subscribe(event_pattern) do |name, _start, _finish, _id, payload|
      events << [name, payload]
    end
  end

  after do
    ActiveSupport::Notifications.unsubscribe(@subscriber)
  end

  def app
    application = @application

    Rack::Builder.new do
      use Rack::Attack
      run application
    end.to_app
  end

  it "keeps counters isolated, does not change the response, and reports hypothetical matches" do
    Timecop.freeze(Time.at(0))
    3.times { get "/", {}, "REMOTE_ADDR" => "1.2.3.4" }

    _(last_response.status).must_equal 429
    _(@application_calls).must_equal 1

    counter = lambda do |name|
      key = "rack::attack:0:#{name}:1.2.3.4"
      Rack::Attack.cache.store.read(key)
    end

    _(counter.call("formal")).must_equal 3
    _(counter.call("shadow:shadow lenient")).must_equal 3
    _(counter.call("shadow:shadow strict")).must_equal 3

    _(events.map(&:first)).must_equal [
      "shadow_throttle.rack_attack",
      "throttle.rack_attack",
      "shadow_throttle.rack_attack",
      "throttle.rack_attack",
      "shadow_throttle.rack_attack",
      "shadow_throttle.rack_attack"
    ]

    formal_events = events.select { |name, _payload| name == "throttle.rack_attack" }
    _(formal_events.size).must_equal 2
    _(last_request.env["rack.attack.matched"]).must_equal "formal"
    _(last_request.env["rack.attack.match_type"]).must_equal :throttle

    shadow_events = events.map(&:last).select { |payload| payload[:match_type] == :shadow_throttle }
    _(shadow_events.size).must_equal 4
    _(shadow_events.map { |payload| payload[:matched] }.tally).must_equal(
      "shadow strict" => 3,
      "shadow lenient" => 1
    )

    shadow_events.each do |payload|
      _(payload[:hypothetical]).must_equal true
      _(payload[:request_summary]).must_equal(
        ip: "1.2.3.4",
        path: "/",
        request_method: "GET"
      )
      _(payload).wont_include :request
    end
  ensure
    Timecop.return
  end

  it "isolates errors from one shadow rule without changing the formal decision" do
    Rack::Attack.clear_configuration
    Rack::Attack.throttle("formal", limit: 1, period: @period) { |request| request.ip }
    Rack::Attack.shadow_throttle("broken shadow", limit: 0, period: @period) { raise "shadow failure" }
    Rack::Attack.shadow_throttle("working shadow", limit: 0, period: @period) { |request| request.ip }

    Timecop.freeze(Time.at(0))
    2.times { get "/", {}, "REMOTE_ADDR" => "1.2.3.4" }

    _(last_response.status).must_equal 429
    _(events.map(&:first)).must_equal [
      "shadow_throttle.rack_attack",
      "throttle.rack_attack",
      "shadow_throttle.rack_attack"
    ]
    matched_names = events.map do |_name, payload|
      payload[:request] ? payload[:request].env["rack.attack.matched"] : payload[:matched]
    end
    _(matched_names).must_equal [
      "working shadow",
      "formal",
      "working shadow"
    ]
    _(last_request.env["rack.attack.matched"]).must_equal "formal"
  ensure
    Timecop.return
  end

  it "records a hypothetical match after a formal blocklist decision" do
    Rack::Attack.clear_configuration
    Rack::Attack.blocklist("formal blocklist") { |request| request.ip == "1.2.3.4" }
    Rack::Attack.shadow_throttle("shadow strict", limit: 0, period: @period) { |request| request.ip }
    @application_calls = 0

    Timecop.freeze(Time.at(0))
    get "/", {}, "REMOTE_ADDR" => "1.2.3.4"

    _(last_response.status).must_equal 403
    _(@application_calls).must_equal 0
    _(events.map(&:first)).must_equal ["shadow_throttle.rack_attack"]
    _(events.last.last[:matched]).must_equal "shadow strict"
    _(last_request.env["rack.attack.matched"]).must_equal "formal blocklist"
    _(last_request.env["rack.attack.match_type"]).must_equal :blocklist
  ensure
    Timecop.return
  end
end
