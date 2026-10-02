# frozen_string_literal: true

require_relative 'spec_helper'

# Deterministic clock: time only moves when a test advances it.
class FakeClock
  attr_reader :now

  def initialize(start = 1_000.0)
    @now = start
  end

  def advance(seconds)
    @now += seconds
  end

  # Jump to an arbitrary reading (including backwards) to simulate clock
  # adjustments.
  def jump_to(seconds)
    @now = seconds
  end

  def call(_request)
    @now
  end
end

# Reusable barrier: every thread parks at #sync until all have arrived, then
# they are all released together. No sleeping or timing luck involved.
class StartBarrier
  def initialize(size)
    @size = size
    @arrived = 0
    @mutex = Mutex.new
    @condition = ConditionVariable.new
  end

  def sync
    @mutex.synchronize do
      @arrived += 1
      @condition.wait(@mutex) until @arrived == @size
      @condition.broadcast
    end
  end
end

describe 'Rack::Attack.smooth_throttle' do
  before do
    @clock = FakeClock.new
    Rack::Attack.smooth_throttle_clock = @clock
    Rack::Attack.cache.store = Rack::Attack::Store::Memory.new
  end

  def app
    Rack::Builder.new do
      use Rack::Lint
      use Rack::Attack
      use Rack::Lint

      run ->(_env) { [200, {}, ['Hello World']] }
    end.to_app
  end

  after do
    Rack::Attack.smooth_throttle_clock = nil
  end

  def configure(&block)
    Rack::Attack.smooth_throttle('exports', rate: 1, burst: 5, &block)
  end

  describe 'configuration' do
    it 'is registered separately from fixed-window throttles' do
      configure { |req| [req.ip, 1] }
      _(Rack::Attack.smooth_throttles.keys).must_equal ['exports']
      _(Rack::Attack.throttles).must_equal({})
    end

    it 'requires :rate and :burst' do
      _(-> { Rack::Attack.smooth_throttle('x', burst: 1) {} }).must_raise ArgumentError
      _(-> { Rack::Attack.smooth_throttle('x', rate: 1) {} }).must_raise ArgumentError
    end

    it 'rejects non-positive rate or negative burst' do
      _(-> { Rack::Attack.smooth_throttle('x', rate: 0, burst: 1) {} }).must_raise ArgumentError
      _(-> { Rack::Attack.smooth_throttle('x', rate: 1, burst: -1) {} }).must_raise ArgumentError
    end
  end

  describe 'weighted burst budget' do
    before do
      configure { |req| [req.ip, req.path == '/heavy' ? 3 : 1] }
    end

    it 'admits exactly burst unit costs at the same instant' do
      5.times do
        get '/', {}, 'REMOTE_ADDR' => '1.1.1.1'
        _(last_response.status).must_equal 200
      end

      get '/', {}, 'REMOTE_ADDR' => '1.1.1.1'
      _(last_response.status).must_equal 429
    end

    it 'charges the request cost against the budget' do
      get '/heavy', {}, 'REMOTE_ADDR' => '2.2.2.2'
      _(last_response.status).must_equal 200

      get '/', {}, 'REMOTE_ADDR' => '2.2.2.2'
      _(last_response.status).must_equal 200
      get '/', {}, 'REMOTE_ADDR' => '2.2.2.2'
      _(last_response.status).must_equal 200

      # 3 + 1 + 1 exhausted the burst of 5.
      get '/', {}, 'REMOTE_ADDR' => '2.2.2.2'
      _(last_response.status).must_equal 429
    end

    it 'refills continuously at the configured rate' do
      6.times { get '/', {}, 'REMOTE_ADDR' => '3.3.3.3' }
      _(last_response.status).must_equal 429

      # At rate 1/s, 0.5s is not enough to admit another unit.
      @clock.advance(0.5)
      get '/', {}, 'REMOTE_ADDR' => '3.3.3.3'
      _(last_response.status).must_equal 429

      @clock.advance(0.6)
      get '/', {}, 'REMOTE_ADDR' => '3.3.3.3'
      _(last_response.status).must_equal 200

      get '/', {}, 'REMOTE_ADDR' => '3.3.3.3'
      _(last_response.status).must_equal 429
    end

    it 'exposes the exact wait until the next request is admissible' do
      6.times { get '/', {}, 'REMOTE_ADDR' => '4.4.4.4' }

      data = last_request.env['rack.attack.match_data']
      _(data[:retry_after]).must_be_close_to 1.0, 1e-9

      # Just short of the wait is still rejected.
      @clock.advance(0.99)
      get '/', {}, 'REMOTE_ADDR' => '4.4.4.4'
      _(last_response.status).must_equal 429

      @clock.advance(0.02)
      get '/', {}, 'REMOTE_ADDR' => '4.4.4.4'
      _(last_response.status).must_equal 200
    end
  end

  describe 'zero cost' do
    before do
      configure do |req|
        cost = req.path == '/free' ? 0 : 1
        [req.ip, cost]
      end
    end

    it 'is always allowed and never consumes the budget' do
      100.times do
        get '/free', {}, 'REMOTE_ADDR' => '5.5.5.5'
        _(last_response.status).must_equal 200
      end

      5.times do
        get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'
        _(last_response.status).must_equal 200
      end

      get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'
      _(last_response.status).must_equal 429
    end

    it 'records a zero cost and no theoretical arrival time' do
      get '/free', {}, 'REMOTE_ADDR' => '5.5.5.5'
      data = last_request.env['rack.attack.throttle_data']['exports']
      _(data[:cost]).must_equal 0.0
      _(data[:theoretical_arrival_time]).must_be_nil
    end
  end

  describe 'cost larger than the burst allowance' do
    before do
      configure { |req| [req.ip, req.path == '/huge' ? 6 : 1] }
    end

    it 'is rejected with no finite wait time' do
      get '/huge', {}, 'REMOTE_ADDR' => '6.6.6.6'
      _(last_response.status).must_equal 429

      data = last_request.env['rack.attack.match_data']
      _(data[:retry_after]).must_be_nil
    end

    it 'does not go into debt or consume budget' do
      get '/huge', {}, 'REMOTE_ADDR' => '7.7.7.7'
      _(last_response.status).must_equal 429

      5.times do
        get '/', {}, 'REMOTE_ADDR' => '7.7.7.7'
        _(last_response.status).must_equal 200
      end
    end

    it 'omits the Retry-After header while enabled' do
      Rack::Attack.throttled_response_retry_after_header = true
      get '/huge', {}, 'REMOTE_ADDR' => '8.8.8.8'
      _(last_response.headers).wont_include 'retry-after'
    ensure
      Rack::Attack.throttled_response_retry_after_header = false
    end
  end

  describe 'negative or invalid cost' do
    it 'raises for a negative cost' do
      configure { |req| [req.ip, -1] }
      _(-> { get '/', {}, 'REMOTE_ADDR' => '9.9.9.9' }).must_raise ArgumentError
    end

    it 'raises for a non-numeric cost' do
      configure { |req| [req.ip, 'expensive'] }
      _(-> { get '/', {}, 'REMOTE_ADDR' => '9.9.9.9' }).must_raise ArgumentError
    end
  end

  describe 'backwards clock movement' do
    before do
      configure { |req| [req.ip, 1] }
    end

    it 'stays fail-closed: no extra budget from a rewinded clock' do
      5.times { get '/', {}, 'REMOTE_ADDR' => '10.0.0.1' }

      @clock.jump_to(5.0)
      # Nothing is admitted at the rewinded reading: the owed 5 units must
      # still be earned from elapsed time after the jump.
      6.times { get '/', {}, 'REMOTE_ADDR' => '10.0.0.1' }
      _(last_response.status).must_equal 429

      @clock.advance(995.0) # 5.0 + 995 = 1000.0, still one unit short
      get '/', {}, 'REMOTE_ADDR' => '10.0.0.1'
      _(last_response.status).must_equal 429

      @clock.advance(1.0) # now = 1001.0, exactly enough
      get '/', {}, 'REMOTE_ADDR' => '10.0.0.1'
      _(last_response.status).must_equal 200
    end
  end

  describe 'block returning a bare discriminator' do
    it 'defaults the cost to 1' do
      configure { |req| req.ip }
      5.times { get '/', {}, 'REMOTE_ADDR' => '11.0.0.1' }
      get '/', {}, 'REMOTE_ADDR' => '11.0.0.1'
      _(last_response.status).must_equal 429
    end
  end

  describe 'nil discriminator' do
    it 'is not throttled' do
      configure { |_| nil }
      10.times { get '/', {}, 'REMOTE_ADDR' => '12.0.0.1' }
      _(last_response.status).must_equal 200
      _(last_request.env['rack.attack.throttle_data']).must_be_nil
    end
  end

  describe ':cost option' do
    it 'computes cost from a dedicated callable' do
      Rack::Attack.smooth_throttle('exports', rate: 1, burst: 5,
                                             cost: ->(req) { req.path == '/heavy' ? 2 : 1 }) do |req|
        req.ip
      end

      get '/heavy', {}, 'REMOTE_ADDR' => '13.0.0.1'
      get '/heavy', {}, 'REMOTE_ADDR' => '13.0.0.1'
      get '/', {}, 'REMOTE_ADDR' => '13.0.0.1'
      _(last_response.status).must_equal 200

      get '/', {}, 'REMOTE_ADDR' => '13.0.0.1'
      _(last_response.status).must_equal 429
    end
  end

  describe ':clock option' do
    it 'uses the injected per-throttle clock over the global one' do
      global_now = 0.0
      Rack::Attack.smooth_throttle_clock = ->(_) { global_now }

      local_now = 5_000.0
      Rack::Attack.smooth_throttle('local', rate: 1, burst: 2,
                                             clock: ->(_) { local_now }) do |req|
        [req.ip, 1]
      end

      2.times do
        get '/', {}, 'REMOTE_ADDR' => '18.0.0.1'
        _(last_response.status).must_equal 200
      end

      get '/', {}, 'REMOTE_ADDR' => '18.0.0.1'
      _(last_response.status).must_equal 429

      # Advancing the global clock changes nothing.
      global_now = 9_999.0
      get '/', {}, 'REMOTE_ADDR' => '18.0.0.1'
      _(last_response.status).must_equal 429

      local_now = 5_001.0
      get '/', {}, 'REMOTE_ADDR' => '18.0.0.1'
      _(last_response.status).must_equal 200
    end
  end

  describe 'Rack::Attack.reset!' do
    it 'clears smooth throttle state' do
      Rack::Attack.smooth_throttle('resettable', rate: 1, burst: 1) do |req|
        [req.ip, 1]
      end

      get '/', {}, 'REMOTE_ADDR' => '19.0.0.1'
      get '/', {}, 'REMOTE_ADDR' => '19.0.0.1'
      _(last_response.status).must_equal 429

      Rack::Attack.reset!

      get '/', {}, 'REMOTE_ADDR' => '19.0.0.1'
      _(last_response.status).must_equal 200
    end
  end

  describe 'Retry-After header' do
    before do
      configure { |req| [req.ip, 1] }
      Rack::Attack.throttled_response_retry_after_header = true
    end

    after do
      Rack::Attack.throttled_response_retry_after_header = false
    end

    it 'rounds the fractional wait up to whole seconds' do
      5.times { get '/', {}, 'REMOTE_ADDR' => '14.0.0.1' } # tat=1005
      @clock.advance(0.8) # wait for the next unit = 0.2s
      get '/', {}, 'REMOTE_ADDR' => '14.0.0.1'
      _(last_response.status).must_equal 429
      _(last_response.headers['retry-after']).must_equal '1'
    end
  end

  describe 'store without an atomic primitive' do
    it 'raises an explicit error instead of using read/write' do
      Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
      configure { |req| [req.ip, 1] }

      error = assert_raises(Rack::Attack::AtomicStoreUnsupportedError) do
        get '/', {}, 'REMOTE_ADDR' => '15.0.0.1'
      end
      _(error.message).must_include '#update'
    end
  end

  describe 'concurrency' do
    before do
      # Every admitted request costs exactly 1; the clock is frozen, so no
      # refill can happen while threads run.
      configure { |req| [req.ip, 1] }
    end

    it 'admits no more than the burst when requests race' do
      threads_count = 32
      barrier = StartBarrier.new(threads_count)
      request = Rack::Attack::Request.new('REMOTE_ADDR' => '16.0.0.1')
      results = Array.new(threads_count)

      throttle = Rack::Attack.smooth_throttles['exports']

      workers = Array.new(threads_count) do |index|
        Thread.new do
          barrier.sync # all threads hit the limiter at the same instant
          results[index] = !throttle.matched_by?(request)
        end
      end
      workers.each(&:join)

      _(results.count(true)).must_equal 5
      _(results.count(false)).must_equal threads_count - 5
    end

    it 'counts weighted costs exactly under contention' do
      threads_count = 20
      barrier = StartBarrier.new(threads_count)
      request = Rack::Attack::Request.new('REMOTE_ADDR' => '17.0.0.1')
      results = Array.new(threads_count)

      Rack::Attack.smooth_throttle('heavy', rate: 1, burst: 5) { |_req| [request.ip, 2] }
      throttle = Rack::Attack.smooth_throttles['heavy']

      workers = Array.new(threads_count) do |index|
        Thread.new do
          barrier.sync
          results[index] = !throttle.matched_by?(request)
        end
      end
      workers.each(&:join)

      # Only floor(5 / 2) = 2 requests with cost 2 fit.
      _(results.count(true)).must_equal 2
      _(results.count(false)).must_equal 18
    end
  end
end
