# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/manual_clock'

describe 'Rack::Attack.EscalatingBan' do
  before do
    @clock = ManualClock.new
    @store = Rack::Attack::BanMemoryStore.new(clock: @clock)
    @ban = Rack::Attack::EscalatingBan.new(
      levels: [
        { name: 'short', maxretry: 2, bantime: 60 },
        { name: 'long',  maxretry: 4, bantime: 300 }
      ],
      decay: 900,
      store: @store,
      clock: @clock
    )
  end

  def report(times = 1, event_id = nil)
    status = nil
    @event_sequence ||= 0
    times.times do
      @event_sequence += 1
      status = @ban.report('1.2.3.4', event_id || "evt-#{@event_sequence}")
    end
    status
  end

  describe 'escalation' do
    it 'does not ban before the first threshold' do
      status = report(1)

      _(status.banned?).must_equal false
      _(status.violations).must_equal 1
      _(@ban.banned?('1.2.3.4')).must_equal false
    end

    it 'bans at the first level and records which level produced the ban' do
      status = report(2)

      _(status.banned?).must_equal true
      _(status.level.name).must_equal 'short'
      _(status.level_index).must_equal 0
      _(status.banned_until).must_equal @clock.now + 60
    end

    it 'escalates to the next level when more violations are reported' do
      report(2)

      status = report(2)

      _(status.banned?).must_equal true
      _(status.level.name).must_equal 'long'
      _(status.level_index).must_equal 1
      _(status.banned_until).must_equal @clock.now + 300
    end

    it 'renews at the same level when an offense repeats during a ban' do
      report(2)
      @clock.advance(50)

      status = @ban.report('1.2.3.4', 'renewal')

      _(status.level.name).must_equal 'short'
      _(status.banned_until).must_equal @clock.now + 60
    end

    it 'releases the ban once its duration elapsed' do
      report(2)
      _(@ban.banned?('1.2.3.4')).must_equal true

      @clock.advance(60)

      status = @ban.status('1.2.3.4')
      _(status.banned?).must_equal false
      _(status.banned_until).must_be_nil
      _(status.violations).must_equal 2
    end

    it 'never shortens an ongoing ban from a newer computation' do
      ban = Rack::Attack::EscalatingBan.new(
        levels: [
          { name: 'short', maxretry: 2, bantime: 60 },
          { name: 'long',  maxretry: 4, bantime: 300 }
        ],
        decay: 100,
        store: @store,
        clock: @clock
      )
      %w[a b c d].each { |event_id| ban.report('1.2.3.4', event_id) }
      original_until = @clock.now + 300

      # Old violations decay while the long ban is still running; a new
      # report would only warrant a short (or no) ban. The long ban must
      # neither be shortened nor cleared.
      @clock.advance(101)
      _(ban.status('1.2.3.4').violations).must_equal 0
      status = ban.report('1.2.3.4', 'late')

      _(status.banned?).must_equal true
      _(status.level.name).must_equal 'long'
      _(status.banned_until).must_equal original_until
    end
  end

  describe 'event id deduplication' do
    it 'does not count a repeated event id twice' do
      first = @ban.report('1.2.3.4', 'same-event')
      _(first.violations).must_equal 1
      _(first.banned?).must_equal false

      5.times { @ban.report('1.2.3.4', 'same-event') }
      status = @ban.status('1.2.3.4')

      _(status.violations).must_equal 1
      _(status.banned?).must_equal false
    end

    it 'does not escalate twice at a threshold with duplicate events' do
      @ban.report('1.2.3.4', 'a')
      status = @ban.report('1.2.3.4', 'b')
      _(status.banned?).must_equal true
      _(status.level.name).must_equal 'short'

      @ban.report('1.2.3.4', 'a')
      @ban.report('1.2.3.4', 'b')

      status = @ban.status('1.2.3.4')
      _(status.violations).must_equal 2
      _(status.level.name).must_equal 'short'
    end

    it 'counts the same id again once the prior occurrence decayed' do
      @ban.report('1.2.3.4', 'repeat')
      @clock.advance(901)

      status = @ban.report('1.2.3.4', 'repeat')

      _(status.violations).must_equal 1
      _(status.banned?).must_equal false
    end
  end

  describe 'decay' do
    it 'gradually restores lower levels after quiet periods' do
      @ban.report('1.2.3.4', 'a')
      @ban.report('1.2.3.4', 'b')
      @clock.advance(10)
      @ban.report('1.2.3.4', 'c')
      @ban.report('1.2.3.4', 'd')
      _(@ban.status('1.2.3.4').level.name).must_equal 'long'

      # Long ban (300s) ends; the first two violations decay next.
      @clock.advance(891)
      status = @ban.status('1.2.3.4')
      _(status.banned?).must_equal false
      _(status.violations).must_equal 2
      _(status.level).must_be_nil
      _(status.current_level.name).must_equal 'short'

      # Once everything decayed, two fresh offenses are needed again.
      @clock.advance(10)
      _(@ban.status('1.2.3.4').violations).must_equal 0
      _(@ban.report('1.2.3.4', 'new-1').banned?).must_equal false
      status = @ban.report('1.2.3.4', 'new-2')
      _(status.banned?).must_equal true
      _(status.level.name).must_equal 'short'
    end

    it 'fully forgets a quiet discriminator' do
      report(3)
      @clock.advance(1201)

      status = @ban.status('1.2.3.4')
      _(status.violations).must_equal 0
      _(status.banned?).must_equal false
    end

    it 'physically expires the stored state' do
      report(2)
      key = 'escalatingban:1.2.3.4'
      _(@store.read(key)).wont_be_nil

      @clock.advance(1201)

      _(@store.read(key)).must_be_nil
    end
  end

  describe 'concurrent reporting' do
    it 'atomically merges violations across threads' do
      thread_count = 20
      barrier = Thread::Queue.new

      workers = Array.new(thread_count) do |i|
        Thread.new do
          barrier.pop
          @ban.report('1.2.3.4', "thread-#{i}")
        end
      end
      thread_count.times { barrier << :go }
      workers.each(&:join)

      _(@ban.status('1.2.3.4').violations).must_equal thread_count
    end

    it 'dedupes the same event reported from concurrent threads' do
      thread_count = 20
      barrier = Thread::Queue.new

      workers = Array.new(thread_count) do
        Thread.new do
          barrier.pop
          @ban.report('1.2.3.4', 'shared-event')
        end
      end
      thread_count.times { barrier << :go }
      workers.each(&:join)

      status = @ban.status('1.2.3.4')
      _(status.violations).must_equal 1
      _(status.banned?).must_equal false
    end
  end

  describe '#filter' do
    it 'reports a violation when the block matches and blocks while banned' do
      outcomes = [@ban.filter('1.2.3.4', 'f-1') { true },
                 @ban.filter('1.2.3.4', 'f-2') { true }]

      # Fail2Ban semantics: the violating request itself is blocked, and a
      # second violation also leaves the discriminator banned.
      _(outcomes).must_equal [true, true]
      _(@ban.status('1.2.3.4').banned?).must_equal true
    end

    it 'does not count a violation when the block does not match' do
      outcome = @ban.filter('1.2.3.4', 'f-1') { false }

      _(outcome).must_equal false
      _(@ban.status('1.2.3.4').violations).must_equal 0
    end

    it 'blocks even clean traffic while the discriminator is banned' do
      report(2)

      _(@ban.filter('1.2.3.4', 'clean') { false }).must_equal true
      _(@ban.status('1.2.3.4').violations).must_equal 2
    end
  end

  describe '#reset' do
    it 'clears the ban and recorded violations' do
      report(2)
      @ban.reset('1.2.3.4')

      status = @ban.status('1.2.3.4')
      _(status.banned?).must_equal false
      _(status.violations).must_equal 0
    end
  end

  describe 'configuration' do
    it 'requires decay and at least one level' do
      _(-> { Rack::Attack::EscalatingBan.new(levels: [{ maxretry: 1, bantime: 1 }]) }).must_raise ArgumentError
      _(-> { Rack::Attack::EscalatingBan.new(levels: [], decay: 10) }).must_raise ArgumentError
      _(-> { Rack::Attack::EscalatingBan.new(levels: [{ maxretry: 1 }], decay: 10) }).must_raise ArgumentError
    end

    it 'rejects unordered level thresholds' do
      _(-> do
        Rack::Attack::EscalatingBan.new(
          levels: [{ maxretry: 5, bantime: 10 }, { maxretry: 2, bantime: 20 }],
          decay: 10
        )
      end).must_raise ArgumentError
    end
  end

  describe 'BanMemoryStore' do
    it 'expires keys according to the injected clock' do
      @store.write('k', 1, expires_in: 10)
      _(@store.read('k')).must_equal 1

      @clock.advance(10)
      _(@store.read('k')).must_be_nil
    end

    it 'merges atomically and sets ttl' do
      @store.merge('k', expires_in: 10) { |_value, now| { 'n' => 1, 'seen' => now } }
      @store.merge('k', expires_in: 10) { |value, _now| value.merge('n' => value['n'] + 1) }

      _(@store.read('k')['n']).must_equal 2
    end
  end
end
