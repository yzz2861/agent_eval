# frozen_string_literal: true

require_relative 'spec_helper'
require 'active_support/notifications'

# A fake cache store whose storage calls can be scripted to
# fail in a precise call order. It keeps an independent
# in-memory backend so recovery uses real counters.
class ScriptedStore
  StoreUnavailable = Class.new(StandardError)

  attr_reader :calls

  def initialize(fail_calls: [], fail_operations: [])
    @backend = {}
    @calls = []
    @fail_calls = fail_calls
    @fail_operations = fail_operations.dup
  end

  def read(key)
    storage_call(:read, key) { @backend[key] }
  end

  def write(key, value, options = {})
    storage_call(:write, key, value, options) { @backend[key] = value }
  end

  def increment(key, amount = 1, options = {})
    storage_call(:increment, key, amount, options) do
      @backend[key] = (@backend[key] || 0) + amount
    end
  end

  def delete(key, options = {})
    storage_call(:delete, key, options) { @backend.delete(key) }
  end

  private

  def storage_call(operation, *)
    @calls << operation
    ordinal = @calls.count
    raise StoreUnavailable, "backend down on #{operation}" if
      @fail_calls.include?(ordinal) || !@fail_operations.empty? && @fail_operations.first == operation
    @fail_operations.shift if @fail_operations.any?

    yield
  end
end

class StorageFailureSubscriber
  attr_reader :events

  def initialize
    @events = []
  end

  def call(name, _start, _finish, _id, payload)
    @events << { name: name, payload: payload }
  end
end

describe 'Rack::Attack storage failure policies' do
  before do
    Rack::Attack.storage_failure_policy = :allow
  end

  def use_store(store)
    Rack::Attack.cache.store = store
  end

  describe 'throttle rules' do
    it 'fails open by default and serves the request' do
      use_store(ScriptedStore.new(fail_operations: %i[increment write]))
      Rack::Attack.throttle('by ip', limit: 1, period: 60) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 200
      _(last_response.body).must_equal 'Hello World'
    end

    it 'fails closed with storage_failure: :deny and answers 503' do
      use_store(ScriptedStore.new(fail_calls: [1]))
      Rack::Attack.throttle(
        'by ip', limit: 1, period: 60, storage_failure: :deny
      ) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      _(last_response.body).must_equal "Service unavailable\n"
      failure = last_request.env['rack.attack.storage_failure']
      _(failure[:rule]).must_equal 'by ip'
      _(failure[:policy]).must_equal :deny
      _(failure[:type]).must_equal :throttle
      _(last_request.env['rack.attack.storage_failures'].size).must_equal 1
      _(last_request.env['rack.attack.match_type']).must_be_nil
    end

    it 'covers the increment-fallback write failure too' do
      # Rack::Attack falls back to #write when the
      # store returns nil from increment, as some
      # backends do for uninitialized counters.
      store = ScriptedStore.new
      store.define_singleton_method(:increment) do |*|
        @calls << :increment
        nil
      end
      store.define_singleton_method(:write) do |*|
        @calls << :write
        raise StoreUnavailable, 'write down'
      end
      use_store(store)
      Rack::Attack.throttle(
        'by ip', limit: 1, period: 60, storage_failure: :deny
      ) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      _(store.calls).must_equal %i[increment write]
    end

    it 'distinguishes backend unavailable from quota exhausted' do
      use_store(ActiveSupport::Cache::MemoryStore.new)
      Rack::Attack.throttle('by ip', limit: 1, period: 60) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 429
      _(last_request.env['rack.attack.match_type']).must_equal :throttle
    end

    it 'uses a custom storage failure responder' do
      use_store(ScriptedStore.new(fail_operations: %i[increment write]))
      Rack::Attack.throttle(
        'by ip', limit: 1, period: 60, storage_failure: :deny
      ) { |req| req.ip }
      Rack::Attack.storage_failure_responder = lambda do |req|
        record = req.env['rack.attack.storage_failure']
        [503, {}, ["store down:#{record[:policy]}:#{record[:rule]}"]]
      end

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      _(last_response.body).must_equal 'store down:deny:by ip'
    end

    it 'uses the real counter as soon as the store recovers' do
      store = ScriptedStore.new(fail_calls: [1])
      use_store(store)
      Rack::Attack.throttle(
        'by ip', limit: 2, period: 60, storage_failure: :deny
      ) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 503

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 429
    end

    it 'does not swallow errors raised by the rule block' do
      use_store(ScriptedStore.new)
      Rack::Attack.throttle('by ip', limit: 1, period: 60) { |_req| raise 'boom in rule' }

      _(-> { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }).must_raise(RuntimeError, /boom in rule/)
    end
  end

  describe 'check rules' do
    it 'lets blocklist rules fail open' do
      use_store(ScriptedStore.new)
      Rack::Attack.blocklist('sensitive', storage_failure: :allow) do |req|
        Rack::Attack.cache.read("ban:#{req.ip}")
      end

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200
    end

    it 'lets blocklist rules fail closed' do
      use_store(ScriptedStore.new(fail_operations: %i[read]))
      Rack::Attack.blocklist('sensitive', storage_failure: :deny) do |req|
        Rack::Attack.cache.read("ban:#{req.ip}")
      end

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 503
      failure = last_request.env['rack.attack.storage_failure']
      _(failure[:rule]).must_equal 'sensitive'
      _(failure[:discriminator_fingerprint]).must_be_nil
    end

    it 'does not swallow errors raised by the rule block' do
      use_store(ScriptedStore.new)
      Rack::Attack.blocklist('sensitive') { |_req| raise 'boom in blocklist' }

      _(-> { get '/' }).must_raise(RuntimeError, /boom in blocklist/)
    end

    it 'rejects invalid policies at definition time' do
      use_store(ActiveSupport::Cache::MemoryStore.new)
      _(-> do
        Rack::Attack.blocklist('sensitive', storage_failure: :maybe) { |_req| false }
      end).must_raise(ArgumentError, /Invalid storage failure policy/)
    end
  end

  describe 'stable merging across rules' do
    it 'lets an explicit safelist win over a deny failure in another phase' do
      use_store(ScriptedStore.new(fail_operations: %i[increment write]))
      Rack::Attack.safelist('always') { |req| req.ip == '1.2.3.4' }
      Rack::Attack.throttle(
        'by ip', limit: 1, period: 60, storage_failure: :deny
      ) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 200
    end

    it 'makes deny failure win over real quota exhaustion of another throttle' do
      store = ScriptedStore.new
      use_store(store)
      Rack::Attack.throttle('public', limit: 1, period: 60) { |req| req.ip }
      Rack::Attack.throttle(
        'sensitive', limit: 1, period: 60, storage_failure: :deny
      ) { |req| req.ip }

      # First request populates both counters (4 storage calls).
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200

      # On the second request the public throttle is
      # genuinely exhausted (429), while the sensitive
      # rule's store is unavailable. The deny policy
      # must win over quota exhaustion.
      store.instance_variable_set(:@fail_calls, [3, 4])
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      _(last_request.env['rack.attack.match_type']).wont_equal :throttle
    end

    it 'evaluates rules in definition order regardless of policy mix' do
      store = ScriptedStore.new
      use_store(store)
      Rack::Attack.throttle(
        'first', limit: 1, period: 60, storage_failure: :allow
      ) { |req| req.ip }
      Rack::Attack.throttle(
        'second', limit: 1, period: 60, storage_failure: :deny
      ) { |req| req.ip }

      store.instance_variable_set(:@fail_calls, [1, 2])
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      # Each rule's increment is consulted, in declaration
      # order; a failed increment aborts that rule so the
      # write fallback never runs. Evaluating both proves
      # an earlier :allow failure doesn't stop a later :deny.
      _(store.calls).must_equal %i[increment increment]
    end
  end

  describe 'track rules' do
    it 'observes the rule policy even outside request phases' do
      use_store(ScriptedStore.new(fail_operations: %i[increment write]))
      Rack::Attack.track(
        'sensitive tracking', limit: 1, period: 60, storage_failure: :deny
      ) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
    end
  end
  describe 'fail2ban rules' do
    it 'applies the blocklist policy to storage calls made from the rule block' do
      use_store(ScriptedStore.new(fail_operations: %i[read]))
      Rack::Attack.blocklist('fail2ban pentesters', storage_failure: :deny) do |req|
        Rack::Attack::Fail2Ban.filter(
          "pentesters:#{req.ip}",
          maxretry: 1, findtime: 60, bantime: 60
        ) do
          req.path == '/etc/passwd'
        end
      end

      get '/'

      _(last_response.status).must_equal 503
      _(last_request.env['rack.attack.storage_failure'][:rule]).must_equal 'fail2ban pentesters'
    end
  end

  describe 'global default policy' do
    it 'can switch the default to deny' do
      Rack::Attack.storage_failure_policy = :deny
      use_store(ScriptedStore.new(fail_operations: %i[increment write]))
      Rack::Attack.throttle('by ip', limit: 1, period: 60) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
    end
  end

  describe 'notifications' do
    before do
      @subscriber = StorageFailureSubscriber.new
      ActiveSupport::Notifications.subscribe('storage_failure.rack_attack', @subscriber)
    end

    it 'instruments storage failures without leaking the discriminator' do
      use_store(ScriptedStore.new(fail_operations: %i[increment write]))
      Rack::Attack.throttle(
        'login', limit: 1, period: 60, storage_failure: :deny
      ) { |_req| 'secret-token-12345' }

      get '/'

      event = @subscriber.events.last
      _(event).wont_be_nil
      payload = event[:payload]
      failure = payload[:failure]
      _(failure[:policy]).must_equal :deny
      _(failure[:rule]).must_equal 'login'
      _(failure[:error]).must_equal 'Rack::Attack::StoreError'
      _(failure[:discriminator_fingerprint]).must_match(/\A[0-9a-f]{12}\z/)
      _(failure[:discriminator_fingerprint]).wont_equal 'secret-token-12345'
      _(failure.inspect).wont_include 'secret-token-12345'
      _(payload.inspect).wont_include 'secret-token-12345'
      _(event.inspect).wont_include 'secret-token-12345'
    ensure
      ActiveSupport::Notifications.unsubscribe('storage_failure.rack_attack')
    end
  end
end
