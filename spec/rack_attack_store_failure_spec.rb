# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/scripted_store'

describe 'Rack::Attack storage failure policies' do
  let(:store) { ScriptedStore.new(script: script) }
  let(:script) { {} }
  let(:store_error_events) { [] }

  before do
    Rack::Attack.cache.store = store

    ActiveSupport::Notifications.subscribe('store_error.rack_attack') do |_name, _start, _finish, _id, payload|
      store_error_events << payload
    end
  end

  after do
    ActiveSupport::Notifications.notifier = ActiveSupport::Notifications::Fanout.new
  end

  describe 'failure_policy declaration' do
    it 'defaults to :allow' do
      Rack::Attack.throttle('public', limit: 1, period: 60) { |req| req.ip }

      _(Rack::Attack.throttles['public'].failure_policy).must_equal :allow
    end

    it 'accepts :deny' do
      Rack::Attack.throttle('sensitive', limit: 1, period: 60, failure_policy: :deny) { |req| req.ip }

      _(Rack::Attack.throttles['sensitive'].failure_policy).must_equal :deny
    end

    it 'rejects unknown policies' do
      error = _(-> {
        Rack::Attack.throttle('bad', limit: 1, period: 60, failure_policy: :explode) { |req| req.ip }
      }).must_raise ArgumentError

      _(error.message).must_include ':explode'
    end
  end

  describe 'with failure_policy: :allow (public queries)' do
    before do
      Rack::Attack.throttle('public', limit: 5, period: 60, failure_policy: :allow) { |req| req.ip }
    end

    it 'lets the request through when the backend is unavailable' do
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 200
      _(last_response.body).must_equal 'Hello World'
    end

    it 'does not tag the request as throttled or unavailable' do
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_request.env['rack.attack.match_type']).must_be_nil
      _(last_request.env['rack.attack.matched']).must_be_nil
    end

    it 'uses the real counter immediately after recovery' do
      # First request: backend down, fail-open. Second request: backend back.
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200

      # Six successful counts exhaust the limit; the outage is not cached.
      6.times { get '/', {}, 'REMOTE_ADDR' => '9.9.9.9' }
      _(last_response.status).must_equal 429
    end
  end

  describe 'with failure_policy: :deny (sensitive operations)' do
    before do
      Rack::Attack.throttle('sensitive', limit: 5, period: 60, failure_policy: :deny) { |req| req.ip }
    end

    it 'rejects the request when the backend is unavailable' do
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      _(last_response.body).must_equal "Service Unavailable\n"
    end

    it 'distinguishes backend unavailable from quota exhaustion' do
      # Exhaust the real quota first
      6.times { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }
      _(last_response.status).must_equal 429

      # Then the backend goes down
      script[store.calls.size + 1] = true
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 503
      _(last_request.env['rack.attack.match_type']).must_equal :store_unavailable
    end

    it 'recovers immediately and reports quota exhaustion again with real counts' do
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 503

      6.times { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }
      _(last_response.status).must_equal 429
      _(last_request.env['rack.attack.match_type']).must_equal :throttle
      _(last_request.env['rack.attack.match_data'][:count]).must_equal 6
    end

    it 'uses a dedicated responder' do
      Rack::Attack.store_unavailable_responder = lambda do |req|
        [503, { 'content-type' => 'text/plain' }, ["Down: #{req.env['rack.attack.matched']}"]]
      end
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      _(last_response.body).must_equal 'Down: sensitive'
    end
  end

  describe 'multiple rules with different policies in one request' do
    before do
      Rack::Attack.throttle('public-a', limit: 5, period: 60, failure_policy: :allow) { |req| req.ip }
      Rack::Attack.throttle('sensitive-b', limit: 5, period: 60, failure_policy: :deny) { |req| req.ip }
    end

    it 'denies when the fail-closed rule hits the outage regardless of order' do
      # public-a succeeds, sensitive-b fails
      script[2] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      _(last_request.env['rack.attack.matched']).must_equal 'sensitive-b'
    end

    it 'fails closed even when the deny rule is evaluated before a throttled rule' do
      # Configure deny first by resetting and redeclaring in reverse order
      Rack::Attack.clear_configuration
      Rack::Attack.throttle('sensitive-first', limit: 1, period: 60, failure_policy: :deny) { |req| req.ip }
      Rack::Attack.throttle('exhausted-second', limit: 1, period: 60, failure_policy: :allow) { |req| req.ip }

      # sensitive-first: increment fails (call 1); exhausted-second counts twice
      # across requests; on this request call 3 over the limit => 429 would win
      # unless deny precedence is stable.
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 503
      _(last_request.env['rack.attack.matched']).must_equal 'sensitive-first'
      _(last_request.env['rack.attack.match_type']).must_equal :store_unavailable
    end

    it 'reports quota exhaustion when only fail-open rules are throttled' do
      Rack::Attack.clear_configuration
      Rack::Attack.throttle('only', limit: 1, period: 60, failure_policy: :allow) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 429
      _(last_request.env['rack.attack.match_type']).must_equal :throttle
    end

    it 'emits a throttle event for the winning quota-exhausted rule' do
      Rack::Attack.clear_configuration
      throttle_events = []
      ActiveSupport::Notifications.subscribe('throttle.rack_attack') do |_name, _s, _f, _id, payload|
        throttle_events << payload[:request].env['rack.attack.matched']
      end

      Rack::Attack.throttle('first', limit: 1, period: 60, failure_policy: :allow) { |req| req.ip }
      Rack::Attack.throttle('second', limit: 5, period: 60, failure_policy: :allow) { |req| req.ip }

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 429
      _(throttle_events).must_equal ['first']
    end

    it 'allows when fail-open rules see the outage and no deny rule matches' do
      # Only the fail-open rule hits the outage; the fail-closed rule succeeds.
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 200
    end
  end

  describe 'notifications' do
    before do
      Rack::Attack.throttle('by email', limit: 5, period: 60, failure_policy: :deny) do |req|
        req.params['email']
      end
    end

    it 'does not leak the full discriminator' do
      script[1] = true

      post '/login', { email: 'victim@example.com' }, 'REMOTE_ADDR' => '1.2.3.4'

      _(store_error_events.size).must_equal 1
      event = store_error_events.first

      _(event[:name]).must_equal 'by email'
      _(event[:discriminator_fingerprint]).must_match(/\A[0-9a-f]{12}\z/)
      _(event[:discriminator_fingerprint]).wont_equal 'victim@example.com'
      serialized = event.inspect
      _(serialized).wont_include 'victim@example.com'
      _(last_response.body).wont_include 'victim@example.com'
    end

    it 'uses a stable fingerprint for the same discriminator' do
      script[1] = true
      script[2] = true

      post '/login', { email: 'victim@example.com' }
      post '/login', { email: 'victim@example.com' }

      _(store_error_events.map { |e| e[:discriminator_fingerprint] }.uniq.size).must_equal 1
    end

    it 'notifies for fail-open outages as well' do
      Rack::Attack.clear_configuration
      Rack::Attack.throttle('public', limit: 5, period: 60, failure_policy: :allow) { |req| req.ip }
      script[1] = true

      get '/'

      _(store_error_events.size).must_equal 1
      _(store_error_events.first[:error].message).must_include 'ScriptedStore::BackendUnavailable'
      _(store_error_events.first[:error]).must_be_kind_of Rack::Attack::StoreError
      _(store_error_events.first[:error].cause).must_be_kind_of ScriptedStore::BackendUnavailable
    end
  end

  describe 'rule block errors' do
    it 'does not swallow programming errors raised by the user rule block' do
      Rack::Attack.throttle('buggy', limit: 5, period: 60, failure_policy: :deny) do |_req|
        raise 'boom from user block'
      end

      _(-> { get '/' }).must_raise RuntimeError, /boom from user block/
      _(store_error_events).must_be :empty?
    end

    it 'does not swallow errors raised by dynamic limit/period procs' do
      Rack::Attack.throttle('buggy', limit: ->(_req) { raise 'limit boom' }, period: 60) { |req| req.ip }

      _(-> { get '/' }).must_raise RuntimeError, /limit boom/
    end
  end

  describe 'scripted call ordering' do
    it 'fails exactly the declared call numbers and resumes real counting' do
      Rack::Attack.throttle('exact', limit: 2, period: 60, failure_policy: :deny) { |req| req.ip }
      # Fail the 1st and 3rd count calls only
      script[1] = true
      script[3] = true

      get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'
      _(last_response.status).must_equal 503

      get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'
      _(last_response.status).must_equal 200 # real count = 1

      get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'
      _(last_response.status).must_equal 503

      get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'
      _(last_response.status).must_equal 200 # real count = 2

      get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'
      _(last_response.status).must_equal 429 # real count = 3 > limit 2
    end
  end

  describe 'Fail2Ban with an unavailable store' do
    before do
      Rack::Attack.blocklist('pentest') do |req|
        Rack::Attack::Fail2Ban.filter(req.ip, bantime: 60, findtime: 60, maxretry: 1) do
          req.path == '/private'
        end
      end
    end

    it 'fails open (does not raise) when the backend is down on a triggering request' do
      script[1] = true
      script[2] = true

      get '/private', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 200
    end

    it 'does not treat a ban-read outage as a ban' do
      # Banned status read fails while counting the triggering request
      script[1] = true

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200
    end
  end

  describe 'Allow2Ban with an unavailable store' do
    before do
      Rack::Attack.blocklist('scarce') do |req|
        Rack::Attack::Allow2Ban.filter(req.ip, bantime: 60, findtime: 60, maxretry: 1) do
          req.path == '/scarce'
        end
      end
    end

    it 'fails open when the backend is down' do
      script[1] = true
      script[2] = true

      get '/scarce', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 200
    end
  end

  describe 'track rules with an unavailable store' do
    it 'neither block nor emit a track match notification on outage, but do report the error' do
      track_events = []
      ActiveSupport::Notifications.subscribe('track.rack_attack') do |_name, _s, _f, _id, payload|
        track_events << payload
      end

      Rack::Attack.track('observations', limit: 1, period: 60) { |req| req.ip }
      script[1] = true

      get '/'

      _(last_response.status).must_equal 200
      _(track_events).must_be :empty?
      _(store_error_events.size).must_equal 1
      _(last_request.env['rack.attack.match_type']).must_be_nil
    end
  end
end
