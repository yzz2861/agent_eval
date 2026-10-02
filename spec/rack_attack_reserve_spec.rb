# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/freeze_time_helper'

class FlakyBody
  def each
    yield 'partial'
    raise 'stream failed'
  end
end

describe 'Rack::Attack reserve-and-settle throttles' do
  before do
    @period = 60
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  def counter_value(key, period = @period)
    store_key = "rack::attack:#{Time.now.to_i / period}:#{key}"
    Rack::Attack.cache.store.read(store_key)
  end

  def call_app(app, path = '/')
    Rack::Attack.new(app).call(Rack::MockRequest.env_for(path, 'REMOTE_ADDR' => '1.2.3.4'))
  end

  describe 'with a successful app' do
    def app
      Rack::Builder.new do
        use Rack::Lint
        use Rack::Attack
        run lambda { |_env| [200, {}, ['Hello World']] }
      end.to_app
    end

    before do
      Rack::Attack.throttle('logins', limit: 1, period: @period, reserve: true) { |req| req.ip }
    end

    it 'refunds the reserved quota once the response is delivered' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        _(last_response.status).must_equal 200
        _(counter_value('logins:1.2.3.4')).must_equal 0

        # the refunded slot is available again, so the next request is allowed too
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        _(last_response.status).must_equal 200
        _(counter_value('logins:1.2.3.4')).must_equal 0
      end
    end

    it 'still populates throttle data' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        data = last_request.env['rack.attack.throttle_data']['logins']
        _(data[:count]).must_equal 1
        _(data[:limit]).must_equal 1
        _(data[:period]).must_equal @period
      end
    end
  end

  describe 'with a failing app' do
    def app
      Rack::Builder.new do
        use Rack::Lint
        use Rack::Attack
        run lambda { |_env| [401, {}, ['Unauthorized']] }
      end.to_app
    end

    before do
      Rack::Attack.throttle('logins', limit: 1, period: @period, reserve: true) { |req| req.ip }
    end

    it 'keeps the reserved quota' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        _(last_response.status).must_equal 401
        _(counter_value('logins:1.2.3.4')).must_equal 1
      end
    end

    it 'throttles at the limit and releases the rejected reservation' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        _(last_response.status).must_equal 429

        # the rejected request never reached the app, so its reservation
        # was returned: only the kept failure remains counted
        _(counter_value('logins:1.2.3.4')).must_equal 1
      end
    end
  end

  describe 'with a custom refund rule' do
    def app
      Rack::Builder.new do
        use Rack::Lint
        use Rack::Attack
        run lambda { |_env| [302, { 'location' => '/dashboard' }, ['Found']] }
      end.to_app
    end

    before do
      Rack::Attack.throttle('logins', limit: 1, period: @period, reserve: true,
                            refund_if: ->(status, _req) { status == 200 }) { |req| req.ip }
    end

    it 'keeps the quota when the rule does not refund' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        _(last_response.status).must_equal 302
        _(counter_value('logins:1.2.3.4')).must_equal 1
      end
    end
  end

  describe 'when the app raises' do
    def app
      Rack::Builder.new do
        use Rack::Lint
        use Rack::Attack
        run lambda { |_env| raise 'boom' }
      end.to_app
    end

    before do
      Rack::Attack.throttle('logins', limit: 5, period: @period, reserve: true) { |req| req.ip }
    end

    it 'keeps the reservation' do
      within_same_period do
        _(proc { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }).must_raise RuntimeError
        _(counter_value('logins:1.2.3.4')).must_equal 1
      end
    end
  end

  describe 'when the body raises while streaming' do
    def app
      Rack::Builder.new do
        use Rack::Lint
        use Rack::Attack
        run lambda { |_env| [200, {}, FlakyBody.new] }
      end.to_app
    end

    before do
      Rack::Attack.throttle('logins', limit: 5, period: @period, reserve: true) { |req| req.ip }
    end

    it 'keeps the reservation' do
      within_same_period do
        _(proc { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }).must_raise RuntimeError
        _(counter_value('logins:1.2.3.4')).must_equal 1
      end
    end
  end

  describe 'client disconnects and interleaved delivery' do
    before do
      Rack::Attack.throttle('logins', limit: 10, period: @period, reserve: true) { |req| req.ip }
    end

    it 'keeps the reservation when the client closes early' do
      within_same_period do
        _status, _headers, body = call_app(lambda { |_env| [200, {}, ['Hello']] })

        body.close # connection closed before the body was delivered

        _(counter_value('logins:1.2.3.4')).must_equal 1
      end
    end

    it 'settles exactly once even when close is called repeatedly' do
      within_same_period do
        _status, _headers, body = call_app(lambda { |_env| [200, {}, ['Hello']] })

        body.each { |chunk| chunk }
        body.close
        body.close

        _(counter_value('logins:1.2.3.4')).must_equal 0
      end
    end

    it 'settles interleaved in-flight requests independently' do
      app = lambda do |env|
        env['PATH_INFO'] == '/fail' ? [401, {}, ['no']] : [200, {}, ['ok']]
      end

      within_same_period do
        ok1 = call_app(app, '/ok')
        fail1 = call_app(app, '/fail')
        ok2 = call_app(app, '/ok')

        _(counter_value('logins:1.2.3.4')).must_equal 3

        ok1[2].each {}
        ok1[2].close
        _(counter_value('logins:1.2.3.4')).must_equal 2

        fail1[2].each {}
        fail1[2].close
        _(counter_value('logins:1.2.3.4')).must_equal 2

        ok2[2].each {}
        ok2[2].close
        _(counter_value('logins:1.2.3.4')).must_equal 1
      end
    end
  end
end

describe 'Rack::Attack::Cache reserve/settle with the memory store' do
  before do
    @period = 60
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  def cache
    Rack::Attack.cache
  end

  def counter_value(key)
    store_key = "rack::attack:#{Time.now.to_i / @period}:#{key}"
    Rack::Attack.cache.store.read(store_key)
  end

  it 'gives every reservation an independent credential' do
    within_same_period do
      r1 = cache.reserve('logins:1.2.3.4', @period)
      r2 = cache.reserve('logins:1.2.3.4', @period)

      _(r1.token).wont_equal r2.token
      _(r1.count).must_equal 1
      _(r2.count).must_equal 2
    end
  end

  it 'settles each credential at most once' do
    within_same_period do
      reservation = cache.reserve('logins:1.2.3.4', @period)

      _(reservation.settle(:refund)).must_equal true
      _(reservation.settle(:refund)).must_equal false
      _(reservation.settle(:keep)).must_equal false
      _(counter_value('logins:1.2.3.4')).must_equal 0
    end
  end

  it 'settles reservations independently' do
    within_same_period do
      r1 = cache.reserve('logins:1.2.3.4', @period)
      r2 = cache.reserve('logins:1.2.3.4', @period)

      r1.settle(:refund)
      r2.settle(:keep)

      _(counter_value('logins:1.2.3.4')).must_equal 1
    end
  end

  it 'ignores unknown tokens' do
    within_same_period do
      _(cache.settle('no-such-token', refund: true)).must_equal false
    end
  end

  it 'does not recreate or drive negative a vanished window counter' do
    within_same_period do
      reservation = cache.reserve('logins:1.2.3.4', @period)
      cache.reset_count('logins:1.2.3.4', @period)

      _(reservation.settle(:refund)).must_equal true
      _(counter_value('logins:1.2.3.4')).must_be_nil
    end
  end

  it 'refunds the window the reservation came from, never the current one' do
    t0 = Time.at(36_000) # aligned with the period boundary
    reservation = nil

    Timecop.freeze(t0) do
      reservation = cache.reserve('logins:1.2.3.4', @period)
    end

    Timecop.freeze(t0 + @period) do
      cache.reserve('logins:1.2.3.4', @period) # a reservation in the new window

      _(reservation.settle(:refund)).must_equal true

      old_key = "rack::attack:#{t0.to_i / @period}:logins:1.2.3.4"
      new_key = "rack::attack:#{(t0.to_i / @period) + 1}:logins:1.2.3.4"
      _(Rack::Attack.cache.store.read(old_key)).must_equal 0
      _(Rack::Attack.cache.store.read(new_key)).must_equal 1
    end
  end

  it 'is a no-op once the original window has expired' do
    t0 = Time.at(36_000)
    reservation = nil

    Timecop.freeze(t0) do
      reservation = cache.reserve('logins:1.2.3.4', @period)
    end

    Timecop.freeze(t0 + (5 * @period)) do
      _(reservation.settle(:refund)).must_equal false
      _(counter_value('logins:1.2.3.4')).must_be_nil
    end
  end

  it 'never drives the counter negative under concurrent interleaving' do
    within_same_period do
      cache.reserve('logins:1.2.3.4', @period).settle(:keep) # initialize the window counter

      negatives = []
      threads = 8.times.map do |t|
        Thread.new do
          25.times do |i|
            reservation = cache.reserve('logins:1.2.3.4', @period)
            reservation.settle((i + t).odd? ? :keep : :refund)

            value = counter_value('logins:1.2.3.4')
            negatives << value if value && value.to_i < 0
          end
        end
      end
      threads.each(&:join)

      _(negatives).must_be_empty
      # 1 warm-up keep + 100 keeps out of 200 interleaved reservations
      _(counter_value('logins:1.2.3.4')).must_equal 101
    end
  end
end
