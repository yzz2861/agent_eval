# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/blocking_memory_store'
require_relative 'support/freeze_time_helper'

describe 'Rack::Attack.throttle' do
  before do
    @period = 60
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.throttle('ip/sec', limit: 1, period: @period) { |req| req.ip }
  end

  it('should have a throttle') { Rack::Attack.throttles.key?('ip/sec') }

  it_allows_ok_requests

  describe 'a single request' do
    it 'should set the counter for one request' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        key = "rack::attack:#{Time.now.to_i / @period}:ip/sec:1.2.3.4"
        _(Rack::Attack.cache.store.read(key)).must_equal 1
      end
    end

    it 'should populate throttle data' do
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      data = {
        count: 1,
        limit: 1,
        period: @period,
        epoch_time: Rack::Attack.cache.last_epoch_time.to_i,
        discriminator: "1.2.3.4"
      }

      _(last_request.env['rack.attack.throttle_data']['ip/sec']).must_equal data
    end
  end

  describe "with 2 requests" do
    before do
      within_same_period do
        2.times { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }
      end
    end

    it 'should block the last request' do
      _(last_response.status).must_equal 429
    end

    it 'should tag the env' do
      _(last_request.env['rack.attack.matched']).must_equal 'ip/sec'
      _(last_request.env['rack.attack.match_type']).must_equal :throttle

      _(last_request.env['rack.attack.match_data']).must_equal(
        count: 2,
        limit: 1,
        period: @period,
        epoch_time: Rack::Attack.cache.last_epoch_time.to_i,
        discriminator: "1.2.3.4"
      )

      _(last_request.env['rack.attack.match_discriminator']).must_equal('1.2.3.4')
    end
  end
end

describe 'Rack::Attack.throttle with limit as proc' do
  before do
    @period = 60
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.throttle('ip/sec', limit: lambda { |_req| 1 }, period: @period) { |req| req.ip }
  end

  it_allows_ok_requests

  describe 'a single request' do
    it 'should set the counter for one request' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        key = "rack::attack:#{Time.now.to_i / @period}:ip/sec:1.2.3.4"
        _(Rack::Attack.cache.store.read(key)).must_equal 1
      end
    end

    it 'should populate throttle data' do
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      data = {
        count: 1,
        limit: 1,
        period: @period,
        epoch_time: Rack::Attack.cache.last_epoch_time.to_i,
        discriminator: "1.2.3.4"
      }

      _(last_request.env['rack.attack.throttle_data']['ip/sec']).must_equal data
    end
  end
end

describe 'Rack::Attack.throttle with period as proc' do
  before do
    @period = 60
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.throttle('ip/sec', limit: lambda { |_req| 1 }, period: lambda { |_req| @period }) { |req| req.ip }
  end

  it_allows_ok_requests

  describe 'a single request' do
    it 'should set the counter for one request' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        key = "rack::attack:#{Time.now.to_i / @period}:ip/sec:1.2.3.4"
        _(Rack::Attack.cache.store.read(key)).must_equal 1
      end
    end

    it 'should populate throttle data' do
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      data = {
        count: 1,
        limit: 1,
        period: @period,
        epoch_time: Rack::Attack.cache.last_epoch_time.to_i,
        discriminator: "1.2.3.4"
      }

      _(last_request.env['rack.attack.throttle_data']['ip/sec']).must_equal data
    end
  end
end

describe 'Rack::Attack.throttle with block returning nil' do
  before do
    @period = 60
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.throttle('ip/sec', limit: 1, period: @period) { |_| nil }
  end

  it_allows_ok_requests

  describe 'a single request' do
    it 'should not set the counter' do
      within_same_period do
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        key = "rack::attack:#{Time.now.to_i / @period}:ip/sec:1.2.3.4"
        assert_nil Rack::Attack.cache.store.read(key)
      end
    end

    it 'should not populate throttle data' do
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      assert_nil last_request.env['rack.attack.throttle_data']
    end
  end
end

describe 'Rack::Attack.throttle with concurrent windows' do
  it 'associates each request with the window that produced its count' do
    store = BlockingMemoryStore.new
    store.key_pattern = ':0:first'
    Rack::Attack.cache.store = store

    dynamic_period = lambda do |request|
      request.path == '/first' ? 60 : 120
    end
    Rack::Attack.throttle('first', limit: 0, period: dynamic_period) do |request|
      if request.path == '/first'
        'first'
      elsif request.path == '/second'
        'second'
      end
    end
    Rack::Attack.throttle('second', limit: 0, period: dynamic_period) do |request|
      if request.path == '/first'
        'first'
      elsif request.path == '/second'
        'second'
      end
    end

    first_request = Rack::Attack::Request.new(Rack::MockRequest.env_for('/first'))
    second_request = Rack::Attack::Request.new(Rack::MockRequest.env_for('/second'))
    first_throttle = Rack::Attack.throttles.fetch('first')
    second_throttle = Rack::Attack.throttles.fetch('second')
    first_count = nil
    second_count = nil
    second_rule_count = nil

    begin
      Timecop.freeze(Time.at(59))
      first_thread = Thread.new do
        first_throttle.matched_by?(first_request)
        second_throttle.matched_by?(first_request)
      end
      store.window_started.pop

      Timecop.freeze(Time.at(120))
      second_thread = Thread.new { second_throttle.matched_by?(second_request) }
      second_thread.join
      store.window_continue << true
      first_thread.join

      first_count = store.read('rack::attack:0:first:first')
      second_count = store.read('rack::attack:1:second:second')
      second_rule_count = store.read('rack::attack:2:second:first')
    ensure
      Timecop.return
    end

    first_data = first_request.env['rack.attack.throttle_data'].fetch('first')
    second_data = second_request.env['rack.attack.throttle_data'].fetch('second')

    _(first_data[:count]).must_equal 1
    _(first_data[:period]).must_equal 60
    _(first_data[:epoch_time]).must_equal 59

    _(second_data[:count]).must_equal 1
    _(second_data[:period]).must_equal 120
    _(second_data[:epoch_time]).must_equal 120
    _(second_request.env['rack.attack.match_data'][:epoch_time]).must_equal 120

    second_rule_data = first_request.env['rack.attack.throttle_data'].fetch('second')
    _(second_rule_data[:count]).must_equal 1
    _(second_rule_data[:period]).must_equal 60
    _(second_rule_data[:epoch_time]).must_equal 120
    _(first_request.env['rack.attack.match_data'][:epoch_time]).must_equal 120

    _(first_count).must_equal 1
    _(second_count).must_equal 1
    _(second_rule_count).must_equal 1
  end
end

describe 'Rack::Attack.throttle with unmatched rules' do
  it 'does not annotate data for rules that do not match' do
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.throttle('matching', limit: 1, period: 60) do |request|
      request.ip if request.path == '/match'
    end
    Rack::Attack.throttle('ignored', limit: 1, period: 120) do |request|
      request.ip if request.path == '/other'
    end

    get '/match', {}, 'REMOTE_ADDR' => '1.2.3.4'

    throttle_data = last_request.env['rack.attack.throttle_data']
    _(throttle_data.keys).must_equal(['matching'])
    _(throttle_data.fetch('matching')[:epoch_time]).must_equal(Time.now.to_i)
  end
end

describe 'Rack::Attack.throttle with throttle_discriminator_normalizer' do
  before do
    @period = 60
    @emails = [
      "person@example.com",
      "PERSON@example.com ",
      " person@example.com\r\n  ",
    ]
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.throttle('logins/email', limit: 4, period: @period) do |req|
      if req.path == '/login' && req.post?
        req.params['email']
      end
    end
  end

  it 'should not differentiate requests when throttle_discriminator_normalizer is enabled' do
    within_same_period do
      post_logins
      key = "rack::attack:#{Time.now.to_i / @period}:logins/email:person@example.com"
      _(Rack::Attack.cache.store.read(key)).must_equal 3
    end
  end

  it 'should differentiate requests when throttle_discriminator_normalizer is disabled' do
    begin
      prev = Rack::Attack.throttle_discriminator_normalizer
      Rack::Attack.throttle_discriminator_normalizer = nil

      within_same_period do
        post_logins
        @emails.each do |email|
          key = "rack::attack:#{Time.now.to_i / @period}:logins/email:#{email}"
          _(Rack::Attack.cache.store.read(key)).must_equal 1
        end
      end
    ensure
      Rack::Attack.throttle_discriminator_normalizer = prev
    end
  end

  def post_logins
    @emails.each do |email|
      post '/login', email: email
    end
  end
end
