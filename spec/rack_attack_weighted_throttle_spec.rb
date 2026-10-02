# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/barrier'
require_relative 'support/fake_clock'

describe 'Rack::Attack::WeightedThrottle' do
  before do
    @clock = FakeClock.new(1_000.0)
    Rack::Attack.cache.store = Rack::Attack::MemoryStore.new
  end

  def build_throttle(options = {}, &block)
    defaults = { rate: 2, per: 1, burst: 2, clock: @clock }
    Rack::Attack::WeightedThrottle.new('test', defaults.merge(options), &block)
  end

  def request_for(ip = '1.2.3.4')
    Rack::Attack::Request.new('REMOTE_ADDR' => ip)
  end

  describe 'option validation' do
    it 'requires rate, per and burst' do
      _(proc { build_throttle(rate: nil) }).must_raise ArgumentError
      _(proc { build_throttle(per: nil) }).must_raise ArgumentError
      _(proc { build_throttle(burst: nil) }).must_raise ArgumentError
    end

    it 'requires a positive rate and per, and a non-negative burst' do
      _(proc { build_throttle(rate: 0) }).must_raise ArgumentError
      _(proc { build_throttle(per: -1) }).must_raise ArgumentError
      _(proc { build_throttle(burst: -1) }).must_raise ArgumentError
      _(proc { build_throttle(rate: 'lots') }).must_raise ArgumentError
    end
  end

  describe 'burst capacity' do
    before do
      @throttle = build_throttle(burst: 2) { |req| req.ip }
    end

    it 'admits requests up to the burst capacity instantly' do
      _(@throttle.matched_by?(request_for)).must_equal false
      _(@throttle.matched_by?(request_for)).must_equal false
      _(@throttle.matched_by?(request_for)).must_equal true
    end

    it 'tracks buckets per discriminator' do
      _(@throttle.matched_by?(request_for('1.1.1.1'))).must_equal false
      _(@throttle.matched_by?(request_for('1.1.1.1'))).must_equal false
      _(@throttle.matched_by?(request_for('2.2.2.2'))).must_equal false
    end
  end

  describe 'sustained rate' do
    it 'refills capacity continuously instead of in fixed windows' do
      throttle = build_throttle(rate: 2, per: 1, burst: 1) { |req| req.ip }

      _(throttle.matched_by?(request_for)).must_equal false
      _(throttle.matched_by?(request_for)).must_equal true

      @clock.advance(0.5) # one token refilled (2 per second)
      _(throttle.matched_by?(request_for)).must_equal false
      _(throttle.matched_by?(request_for)).must_equal true

      @clock.advance(0.5)
      _(throttle.matched_by?(request_for)).must_equal false
    end
  end

  describe 'retry_after' do
    it 'reports the wait time until the next acceptable request' do
      throttle = build_throttle(rate: 2, per: 1, burst: 2) { |req| req.ip }

      throttle.matched_by?(request_for)
      throttle.matched_by?(request_for)

      rejected = request_for
      _(throttle.matched_by?(rejected)).must_equal true

      data = rejected.env['rack.attack.match_data']
      _(data[:retry_after]).must_be_within_delta 0.5, 1e-9

      @clock.advance(data[:retry_after])
      _(throttle.matched_by?(request_for)).must_equal false
    end

    it 'reports zero wait for allowed requests' do
      throttle = build_throttle { |req| req.ip }
      request = request_for

      throttle.matched_by?(request)

      _(request.env['rack.attack.throttle_data']['test'][:retry_after]).must_equal 0.0
    end
  end

  describe 'weighted cost' do
    it 'charges each request the cost computed from the request' do
      throttle = build_throttle(burst: 4, cost: ->(req) { req.env['cost'] }) { |req| req.ip }

      expensive = request_for
      expensive.env['cost'] = 3
      cheap = request_for
      cheap.env['cost'] = 1
      overflow = request_for
      overflow.env['cost'] = 1

      _(throttle.matched_by?(expensive)).must_equal false
      _(throttle.matched_by?(cheap)).must_equal false
      _(throttle.matched_by?(overflow)).must_equal true
    end

    it 'always allows zero-cost requests' do
      throttle = build_throttle(burst: 0, cost: 0) { |req| req.ip }

      10.times { _(throttle.matched_by?(request_for)).must_equal false }
    end

    it 'rejects costs above the burst capacity without poisoning the bucket' do
      throttle = build_throttle(rate: 2, per: 1, burst: 2) { |req| req.ip }
      costly = build_throttle(rate: 2, per: 1, burst: 2, cost: 100) { |req| req.ip }

      rejected = request_for
      _(costly.matched_by?(rejected)).must_equal true
      _(rejected.env['rack.attack.match_data'][:retry_after]).must_be :>, 0

      # The rejected huge cost must not consume capacity.
      _(throttle.matched_by?(request_for)).must_equal false
    end

    it 'clamps negative costs to zero' do
      throttle = build_throttle(burst: 0, cost: -5) { |req| req.ip }

      _(throttle.matched_by?(request_for)).must_equal false
    end
  end

  describe 'clock handling' do
    it 'stays conservative when the clock moves backwards' do
      throttle = build_throttle(rate: 1, per: 1, burst: 1) { |req| req.ip }

      _(throttle.matched_by?(request_for)).must_equal false

      @clock.rewind(50)

      rejected = request_for
      _(throttle.matched_by?(rejected)).must_equal true
      _(rejected.env['rack.attack.match_data'][:retry_after]).must_be :>, 0

      # Once wall time catches up with the stored arrival time, requests flow again.
      @clock.advance(50)
      @clock.advance(1)
      _(throttle.matched_by?(request_for)).must_equal false
    end
  end

  describe 'discriminator' do
    it 'ignores requests without a discriminator' do
      throttle = build_throttle { |_req| nil }

      _(throttle.matched_by?(request_for)).must_equal false
    end

    it 'applies the throttle discriminator normalizer' do
      throttle = build_throttle(burst: 1) { |req| req.env['user'] }

      upper = request_for
      upper.env['user'] = 'USER@EXAMPLE.COM'
      lower = request_for
      lower.env['user'] = 'user@example.com'

      _(throttle.matched_by?(upper)).must_equal false
      _(throttle.matched_by?(lower)).must_equal true
    end
  end

  describe 'store requirements' do
    it 'raises a clear error when the store does not support atomic updates' do
      Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
      throttle = build_throttle { |req| req.ip }

      error = _(proc { throttle.matched_by?(request_for) }).must_raise Rack::Attack::IncompatibleStoreError
      _(error.message).must_match(/atomic_update/)
    end

    it 'raises when no store is configured' do
      Rack::Attack.cache.store = nil
      throttle = build_throttle { |req| req.ip }

      _(proc { throttle.matched_by?(request_for) }).must_raise Rack::Attack::MissingStoreError
    end
  end

  describe 'concurrency' do
    it 'never admits more than the burst capacity under parallel load' do
      burst = 10
      throttle = build_throttle(rate: 1, per: 3600, burst: burst) { |_req| 'shared' }

      thread_count = 3 * burst
      barrier = Barrier.new(thread_count)
      results = Queue.new

      threads = thread_count.times.map do
        Thread.new do
          barrier.wait
          results << throttle.matched_by?(request_for)
        end
      end
      threads.each(&:join)

      throttled = thread_count.times.map { results.pop }.count(true)
      _(throttled).must_equal thread_count - burst
    end
  end
end

describe 'Rack::Attack.weighted_throttle middleware' do
  before do
    Rack::Attack.cache.store = Rack::Attack::MemoryStore.new
    Rack::Attack.weighted_throttle('api', rate: 1, per: 60, burst: 1) { |req| req.ip }
  end

  it_allows_ok_requests

  it 'throttles requests exceeding the burst capacity' do
    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
    _(last_response.status).must_equal 200

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
    _(last_response.status).must_equal 429
    _(last_request.env['rack.attack.matched']).must_equal 'api'
    _(last_request.env['rack.attack.match_type']).must_equal :throttle
  end

  it 'populates throttle data' do
    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    data = last_request.env['rack.attack.throttle_data']['api']
    _(data[:discriminator]).must_equal '1.2.3.4'
    _(data[:cost]).must_equal 1.0
    _(data[:burst]).must_equal 1.0
    _(data[:retry_after]).must_equal 0.0
  end

  describe 'with throttled_response_retry_after_header' do
    before do
      Rack::Attack.configuration.throttled_response_retry_after_header = true
    end

    it 'responds with a retry-after header' do
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 429
      retry_after = Integer(last_response.headers['retry-after'])
      _(retry_after).must_be :>, 0
      _(retry_after).must_be :<=, 60
    end
  end
end
