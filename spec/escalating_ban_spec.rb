# frozen_string_literal: true

require_relative 'spec_helper'

class FakeClock
  attr_reader :now

  def initialize(start = Time.at(1_700_000_000))
    @now = start
  end

  def call
    @now
  end

  def advance(seconds)
    @now += seconds
  end
end

describe 'Rack::Attack::EscalatingBan' do
  before do
    @clock = FakeClock.new
    @ban = Rack::Attack::EscalatingBan
    @ban.levels = [60, 300]
    @ban.decay_period = 600
    @ban.clock = @clock
    @ban.store = Rack::Attack::EscalatingBan::MemoryStore.new(clock: @clock)
  end

  after do
    [:@levels, :@decay_period, :@clock, :@store].each do |ivar|
      Rack::Attack::EscalatingBan.instance_variable_set(ivar, nil)
    end
  end

  describe 'escalation' do
    it 'bans a first violation for the first level duration' do
      state = @ban.violation!('1.2.3.4', event_id: 'evt-1')

      _(@ban.banned?('1.2.3.4')).must_equal true
      _(state.level).must_equal 1
      _(state.ban_level).must_equal 1
      _(state.banned_until).must_equal @clock.now + 60
    end

    it 'escalates a repeat violation and renews the ban from now' do
      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      @clock.advance(30)

      state = @ban.violation!('1.2.3.4', event_id: 'evt-2')

      _(state.level).must_equal 2
      _(state.ban_level).must_equal 2
      _(state.banned_until).must_equal @clock.now + 300
    end

    it 'caps the level at the number of configured levels' do
      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      @ban.violation!('1.2.3.4', event_id: 'evt-2')
      state = @ban.violation!('1.2.3.4', event_id: 'evt-3')

      _(state.level).must_equal 2
      _(state.banned_until).must_equal @clock.now + 300
    end
  end

  describe 'idempotent event reporting' do
    it 'does not escalate twice for the same event id' do
      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      state = @ban.violation!('1.2.3.4', event_id: 'evt-1')

      _(state.level).must_equal 1
      _(state.banned_until).must_equal @clock.now + 60
    end

    it 'escalates once per distinct event id' do
      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      state = @ban.violation!('1.2.3.4', event_id: 'evt-2')

      _(state.level).must_equal 2
    end
  end

  describe 'concurrent violations' do
    it 'merges atomically so no escalation is lost' do
      @ban.levels = [10, 20, 30, 40, 50]

      threads = 5.times.map do |i|
        Thread.new { @ban.violation!('1.2.3.4', event_id: "evt-#{i}") }
      end
      threads.each(&:join)

      state = @ban.ban_state('1.2.3.4')
      _(state.level).must_equal 5
      _(state.banned_until).must_equal @clock.now + 50
    end

    it 'escalates only once when racing reports share an event id' do
      threads = 5.times.map do
        Thread.new { @ban.violation!('1.2.3.4', event_id: 'evt-1') }
      end
      threads.each(&:join)

      _(@ban.ban_state('1.2.3.4').level).must_equal 1
    end
  end

  describe 'active ban protection' do
    it 'never shortens a ban that is still in effect' do
      start = @clock.now
      @ban.levels = [60, 600]
      @ban.decay_period = 10

      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      @clock.advance(5)
      @ban.violation!('1.2.3.4', event_id: 'evt-2') # banned until start + 605
      @clock.advance(100) # level decayed away, ban still active

      state = @ban.violation!('1.2.3.4', event_id: 'evt-3')

      _(state.level).must_equal 1
      _(state.ban_level).must_equal 2 # term still attributed to level 2
      _(state.banned_until).must_equal start + 605
    end
  end

  describe 'decay' do
    it 'recovers one level per full decay period without violations' do
      @ban.levels = [60, 300, 900]
      @ban.decay_period = 100

      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      @ban.violation!('1.2.3.4', event_id: 'evt-2')
      @ban.violation!('1.2.3.4', event_id: 'evt-3')
      @clock.advance(250) # two full decay periods of good behavior

      state = @ban.violation!('1.2.3.4', event_id: 'evt-4')

      _(state.level).must_equal 2
    end

    it 'fully recovers after enough quiet time' do
      @ban.levels = [60, 300, 900]
      @ban.decay_period = 100

      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      @ban.violation!('1.2.3.4', event_id: 'evt-2')
      @ban.violation!('1.2.3.4', event_id: 'evt-3')
      @clock.advance(350) # three full decay periods

      state = @ban.violation!('1.2.3.4', event_id: 'evt-4')

      _(state.level).must_equal 1
    end
  end

  describe 'state expiry' do
    it 'keeps the state while the ban or any decay is still pending' do
      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      @clock.advance(599) # ban over, level not fully decayed yet

      state = @ban.ban_state('1.2.3.4')
      _(state.banned?(@clock.now)).must_equal false
      _(state.ban_level).must_equal 1
    end

    it 'expires the state once the ban and all decay periods elapse' do
      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      @clock.advance(601) # past banned_until + level * decay_period

      _(@ban.ban_state('1.2.3.4')).must_be_nil
      _(@ban.banned?('1.2.3.4')).must_equal false
    end
  end

  describe 'reset' do
    it 'clears the ban state' do
      @ban.violation!('1.2.3.4', event_id: 'evt-1')
      @ban.reset('1.2.3.4')

      _(@ban.banned?('1.2.3.4')).must_equal false
      _(@ban.ban_state('1.2.3.4')).must_be_nil
    end
  end

  describe 'filter integration' do
    before do
      Rack::Attack.blocklist('escalating pentest') do |req|
        @ban.filter(req.ip, event_id: req.env['HTTP_X_EVENT_ID']) { req.query_string =~ /OMGHAX/ }
      end
    end

    it 'allows ok requests' do
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 200
    end

    it 'blocks the offending request and subsequent ones while banned' do
      get '/?foo=OMGHAX', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 403

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 403
    end

    it 'allows requests again after the ban expires' do
      get '/?foo=OMGHAX', {}, 'REMOTE_ADDR' => '1.2.3.4'
      @clock.advance(61)

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200
    end

    it 'does not escalate twice for a repeated event id' do
      get '/?foo=OMGHAX', {}, 'REMOTE_ADDR' => '1.2.3.4', 'HTTP_X_EVENT_ID' => 'evt-1'
      get '/?foo=OMGHAX', {}, 'REMOTE_ADDR' => '1.2.3.4', 'HTTP_X_EVENT_ID' => 'evt-1'

      _(@ban.ban_state('1.2.3.4').level).must_equal 1
    end
  end

  describe 'alongside Fail2Ban' do
    before do
      Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
      Rack::Attack.blocklist('fail2ban pentest') do |req|
        Rack::Attack::Fail2Ban.filter(req.ip, bantime: 60, findtime: 60, maxretry: 1) do
          req.query_string =~ /OMGHAX/
        end
      end
    end

    it 'keeps the original Fail2Ban behavior working' do
      get '/?foo=OMGHAX', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 403

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 403
    end
  end
end
