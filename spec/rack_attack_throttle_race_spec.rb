# frozen_string_literal: true

require_relative 'spec_helper'

describe 'Rack::Attack throttle window race' do
  # Controllable per-thread clock: when a fake epoch is set for the current
  # thread, Time.now reports it; other threads keep their own value.
  module FakeClock
    CURRENT_KEY = :rack_attack_spec_fake_now

    def now
      fake_now = Thread.current[CURRENT_KEY]
      fake_now ? Time.at(fake_now) : super
    end
  end

  # Parks exactly one arriving thread until released from the driver thread.
  class Barrier
    def initialize
      @mutex = Mutex.new
      @condition = ConditionVariable.new
      @arrived = false
      @open = false
    end

    def arrive
      @mutex.synchronize do
        @arrived = true
        @condition.broadcast
        @condition.wait(@mutex) until @open
      end
    end

    def wait_until_arrived
      @mutex.synchronize do
        @condition.wait(@mutex) until @arrived
      end
    end

    def release
      @mutex.synchronize do
        @open = true
        @condition.broadcast
      end
    end
  end

  # MemoryStore keeps counting thread-safe; this only adds a per-key barrier.
  class GatedStore < ActiveSupport::Cache::MemoryStore
    def initialize(barriers)
      super()
      @barriers = barriers
    end

    def increment(name, amount = 1, **options)
      barrier = @barriers[name]
      barrier.arrive if barrier
      super
    end
  end

  before do
    @period = 60
    Time.singleton_class.prepend(FakeClock) unless Time.singleton_class.include?(FakeClock)
  end

  after do
    Thread.current[FakeClock::CURRENT_KEY] = nil
  end

  def build_cache(barriers)
    cache = Rack::Attack::Cache.new(store: GatedStore.new(barriers))
    Rack::Attack.instance_variable_set(:@cache, cache)
    cache
  end

  def request_for(ip)
    Rack::Attack::Request.new(Rack::MockRequest.env_for('/', 'REMOTE_ADDR' => ip))
  end

  def with_fake_time(epoch)
    previous = Thread.current[FakeClock::CURRENT_KEY]
    Thread.current[FakeClock::CURRENT_KEY] = epoch
    yield
  ensure
    Thread.current[FakeClock::CURRENT_KEY] = previous
  end

  # Evaluates a single rule in a worker thread with its own clock and returns
  # once the worker is parked inside Cache#count for the given counter key.
  def start_parked_rule(request, rule_name, epoch, barriers, key)
    Thread.new do
      Thread.current[FakeClock::CURRENT_KEY] = epoch
      Rack::Attack.configuration.throttles[rule_name].matched_by?(request)
    end.tap { barriers[key].wait_until_arrived }
  end

  it 'ties throttle_data and match_data to the window that produced the count' do
    # A counts in window 0; B starts later and counts in window 1. Both are
    # parked inside the store before either reads the window epoch back.
    epoch_a = 0
    epoch_b = @period

    barriers = {}
    cache = build_cache(barriers)

    # Limit 0 throttles on the first hit so match_data is populated too.
    Rack::Attack.throttle('ip/sec', limit: 0, period: @period) { |req| req.ip }

    request_a = request_for('1.0.0.1')
    request_b = request_for('1.0.0.2')
    key_a = "#{cache.prefix}:#{epoch_a / @period}:ip/sec:1.0.0.1"
    key_b = "#{cache.prefix}:#{epoch_b / @period}:ip/sec:1.0.0.2"
    barriers[key_a] = Barrier.new
    barriers[key_b] = Barrier.new

    result_a = nil
    thread_a = Thread.new do
      Thread.current[FakeClock::CURRENT_KEY] = epoch_a
      result_a = Rack::Attack.configuration.throttled?(request_a)
    end
    barriers[key_a].wait_until_arrived

    result_b = nil
    thread_b = Thread.new do
      Thread.current[FakeClock::CURRENT_KEY] = epoch_b
      result_b = Rack::Attack.configuration.throttled?(request_b)
    end
    barriers[key_b].wait_until_arrived

    barriers[key_a].release
    barriers[key_b].release
    thread_a.join
    thread_b.join

    _(result_a).must_equal true
    _(result_b).must_equal true

    data_a = request_a.env['rack.attack.throttle_data']['ip/sec']
    data_b = request_b.env['rack.attack.throttle_data']['ip/sec']

    _(data_a[:count]).must_equal 1
    _(data_b[:count]).must_equal 1
    _(data_a[:epoch_time]).must_equal epoch_a
    _(data_b[:epoch_time]).must_equal epoch_b
    _(request_a.env['rack.attack.match_data'][:epoch_time]).must_equal epoch_a
    _(request_b.env['rack.attack.match_data'][:epoch_time]).must_equal epoch_b
  end

  it 'keeps per-rule window data consistent when multiple rules interleave' do
    # Every request runs both rules. The four count calls run in a strict
    # interleaving (A/rule-a@t0, B/rule-a@t1, A/rule-b@t0, B/rule-b@t1), each
    # parked while the next overwrites the shared epoch.
    t0 = 0
    t1 = @period

    barriers = {}
    cache = build_cache(barriers)
    Rack::Attack.throttle('rule-a', limit: 100, period: @period) { |req| req.ip }
    Rack::Attack.throttle('rule-b', limit: 100, period: @period) { |req| req.ip }

    request_a = request_for('2.0.0.1')
    request_b = request_for('2.0.0.2')

    keys = [
      ["#{cache.prefix}:0:rule-a:2.0.0.1", request_a, t0],
      ["#{cache.prefix}:1:rule-a:2.0.0.2", request_b, t1],
      ["#{cache.prefix}:0:rule-b:2.0.0.1", request_a, t0],
      ["#{cache.prefix}:1:rule-b:2.0.0.2", request_b, t1]
    ]
    keys.each { |key, _, _| barriers[key] = Barrier.new }

    threads = keys.map do |key, request, epoch|
      rule_name = key.split(':')[4]
      start_parked_rule(request, rule_name, epoch, barriers, key)
    end

    keys.each { |key, _, _| barriers[key].release }
    threads.each(&:join)

    a_data = request_a.env['rack.attack.throttle_data']
    b_data = request_b.env['rack.attack.throttle_data']

    _(a_data['rule-a'][:epoch_time]).must_equal t0
    _(a_data['rule-b'][:epoch_time]).must_equal t0
    _(b_data['rule-a'][:epoch_time]).must_equal t1
    _(b_data['rule-b'][:epoch_time]).must_equal t1
    _(a_data['rule-a'][:count]).must_equal 1
    _(a_data['rule-b'][:count]).must_equal 1
    _(b_data['rule-a'][:count]).must_equal 1
    _(b_data['rule-b'][:count]).must_equal 1
  end

  it 'does not let reset_count hand a concurrent count a stale window time' do
    # A count is parked in window 0 while reset_count is evaluated in window
    # 1. The count request must keep the epoch of its own window, and only the
    # window-1 counter key may be deleted.
    t0 = 0
    t1 = @period

    barriers = {}
    cache = build_cache(barriers)
    Rack::Attack.throttle('ip/sec', limit: 100, period: @period) { |req| req.ip }

    request = request_for('3.0.0.1')
    key0 = "#{cache.prefix}:0:ip/sec:3.0.0.1"
    key1 = "#{cache.prefix}:1:ip/sec:3.0.0.1"
    barriers[key0] = Barrier.new
    cache.store.write(key0, 7, expires_in: 60)
    cache.store.write(key1, 9, expires_in: 60)

    count_thread = Thread.new do
      Thread.current[FakeClock::CURRENT_KEY] = t0
      Rack::Attack.configuration.throttled?(request)
    end
    barriers[key0].wait_until_arrived

    reset_thread = Thread.new do
      Thread.current[FakeClock::CURRENT_KEY] = t1
      cache.reset_count('ip/sec:3.0.0.1', @period)
    end
    reset_thread.join

    barriers[key0].release
    count_thread.join

    data = request.env['rack.attack.throttle_data']['ip/sec']
    _(data[:epoch_time]).must_equal t0
    _(data[:count]).must_equal 8
    _(cache.store.read(key0)).must_equal 8
    _(cache.store.read(key1)).must_be_nil
  end

  it 'uses the dynamically evaluated period for both the key and the epoch' do
    cache = Rack::Attack::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    Rack::Attack.instance_variable_set(:@cache, cache)

    dynamic_period = 30
    Rack::Attack.throttle('ip/sec', limit: 100, period: ->(_req) { dynamic_period }) { |req| req.ip }

    [[30, 65], [45, 95]].each do |period, epoch|
      dynamic_period = period
      request = request_for('4.0.0.1')
      key = "#{cache.prefix}:#{epoch / period}:ip/sec:4.0.0.1"
      cache.store.write(key, 0, expires_in: period + 1)

      with_fake_time(epoch) do
        Rack::Attack.configuration.throttled?(request)
      end

      data = request.env['rack.attack.throttle_data']['ip/sec']
      _(data[:period]).must_equal period
      _(data[:epoch_time]).must_equal epoch

      _(cache.store.read(key)).must_equal 1
    end
  end

  it 'tags every evaluated rule with its own epoch and leaves unmatched requests untagged' do
    cache = Rack::Attack::Cache.new(store: ActiveSupport::Cache::MemoryStore.new)
    Rack::Attack.instance_variable_set(:@cache, cache)
    Rack::Attack.throttle('ip/sec', limit: 100, period: @period) { |_req| nil }
    Rack::Attack.throttle('other', limit: 100, period: @period) { |req| req.ip }

    counted = request_for('5.0.0.1')
    with_fake_time(@period + 1) do
      Rack::Attack.configuration.throttled?(counted)
    end

    unmatched = request_for('5.0.0.2')
    with_fake_time(@period * 5) do
      Rack::Attack.configuration.throttled?(unmatched)
    end

    data = unmatched.env['rack.attack.throttle_data']
    _(data.keys).must_equal ['other']
    _(data['other'][:epoch_time]).must_equal(@period * 5)
    _(unmatched.env['rack.attack.match_data']).must_be_nil
    _(unmatched.env['rack.attack.matched']).must_be_nil
  end
end
