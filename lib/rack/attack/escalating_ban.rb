# frozen_string_literal: true

module Rack
  class Attack
    # Escalating ban with configurable levels, a cap, and a decay period.
    #
    # Each violation escalates the discriminator one level and bans it for
    # the duration configured at that level (e.g. 1 minute, then 5 minutes).
    # After +decay_period+ seconds without violations the level decays one
    # step at a time, so well-behaved discriminators gradually recover.
    #
    # Violations are reported with an event id; reporting the same event id
    # again never escalates twice. State merges are atomic and a new
    # computation never shortens a ban that is still in effect.
    #
    #   Rack::Attack::EscalatingBan.levels = [60, 300]
    #   Rack::Attack::EscalatingBan.decay_period = 3600
    #
    #   Rack::Attack.blocklist('pentest') do |req|
    #     Rack::Attack::EscalatingBan.filter(req.ip, event_id: req.env['HTTP_X_EVENT_ID']) do
    #       req.query_string =~ /OMGHAX/
    #     end
    #   end
    class EscalatingBan
      # Immutable snapshot of a discriminator's ban state. +ban_level+ is the
      # level that produced the current +banned_until+ term.
      class State
        attr_reader :level, :ban_level, :banned_until, :last_violation_at, :event_ids

        def initialize(level: 0, ban_level: nil, banned_until: nil, last_violation_at: nil, event_ids: [])
          @level = level
          @ban_level = ban_level
          @banned_until = banned_until
          @last_violation_at = last_violation_at
          @event_ids = event_ids
        end

        def self.empty
          new
        end

        def self.from_h(hash)
          new(
            level: hash['level'],
            ban_level: hash['ban_level'],
            banned_until: hash['banned_until'] && Time.at(hash['banned_until']),
            last_violation_at: hash['last_violation_at'] && Time.at(hash['last_violation_at']),
            event_ids: hash['event_ids'] || []
          )
        end

        def to_h
          {
            'level' => level,
            'ban_level' => ban_level,
            'banned_until' => banned_until && banned_until.to_f,
            'last_violation_at' => last_violation_at && last_violation_at.to_f,
            'event_ids' => event_ids
          }
        end

        def banned?(now)
          !banned_until.nil? && banned_until > now
        end

        def remaining(now)
          banned?(now) ? banned_until - now : 0
        end

        # Level after gradually recovering one step per full decay period
        # elapsed since the last violation.
        def decayed_level(now, decay_period)
          return 0 if last_violation_at.nil?

          elapsed_periods = [((now - last_violation_at) / decay_period).floor, 0].max
          [level - elapsed_periods, 0].max
        end
      end

      # Process-safe in-memory store with TTL support. Mutations happen
      # atomically under a mutex, so concurrent violations merge instead of
      # racing. Other stores can be injected as long as they respond to
      # #read, #delete, and #update(key) with a block returning
      # [value, expires_in] (or nil to delete the key).
      class MemoryStore
        def initialize(clock: -> { Time.now })
          @clock = clock
          @data = {}
          @mutex = Mutex.new
        end

        def read(key)
          @mutex.synchronize do
            prune_if_expired(key)
            entry = @data[key]
            entry && entry[0]
          end
        end

        def update(key)
          @mutex.synchronize do
            prune_if_expired(key)
            entry = @data[key]
            result = yield(entry && entry[0])

            if result.nil?
              @data.delete(key)
              nil
            else
              value, expires_in = result
              @data[key] = [value, @clock.call + expires_in]
              value
            end
          end
        end

        def delete(key)
          @mutex.synchronize { @data.delete(key) }
        end

        def clear
          @mutex.synchronize { @data.clear }
        end

        private

        def prune_if_expired(key)
          entry = @data[key]
          @data.delete(key) if entry && entry[1] <= @clock.call
        end
      end

      class << self
        attr_accessor :levels, :decay_period
        attr_writer :clock, :store

        # Ban durations per level, in seconds. Its length is the level cap.
        def levels
          @levels ||= [60, 300]
        end

        # Seconds without violations before the level decays one step.
        def decay_period
          @decay_period ||= 3600
        end

        def clock
          @clock ||= -> { Time.now }
        end

        def store
          @store ||= MemoryStore.new(clock: -> { clock.call })
        end

        # Mirrors Fail2Ban.filter: true when banned (block the request);
        # otherwise a truthy block result records a violation and blocks.
        def filter(discriminator, event_id: nil)
          if banned?(discriminator)
            true
          elsif yield
            violation!(discriminator, event_id: event_id)
            true
          else
            false
          end
        end

        # Records a violation and returns the resulting State. Reporting the
        # same +event_id+ again is a no-op and returns the current State.
        def violation!(discriminator, event_id: nil)
          now = clock.call
          stored = store.update(key(discriminator)) do |current|
            state = current ? State.from_h(current) : State.empty
            state = escalate(state, now, event_id) unless event_id && state.event_ids.include?(event_id)
            [state.to_h, expires_in(state, now)]
          end
          State.from_h(stored)
        end

        def banned?(discriminator)
          state = ban_state(discriminator)
          !state.nil? && state.banned?(clock.call)
        end

        # Current State (including which level produced the ban term), or nil
        # once the state has fully decayed and expired.
        def ban_state(discriminator)
          raw = store.read(key(discriminator))
          raw && State.from_h(raw)
        end

        def reset(discriminator)
          store.delete(key(discriminator))
        end

        private

        def key(discriminator)
          "escalating_ban:#{discriminator}"
        end

        def max_level
          levels.length
        end

        def escalate(state, now, event_id)
          decayed = state.decayed_level(now, decay_period)
          base = decayed.zero? && !state.banned?(now) ? State.empty : state
          level = [decayed + 1, max_level].min
          candidate_until = now + levels[level - 1]

          # A new computation never shortens a ban that is still in effect;
          # the kept term stays attributed to the level that produced it.
          if base.banned?(now) && base.banned_until > candidate_until
            banned_until = base.banned_until
            ban_level = base.ban_level
          else
            banned_until = candidate_until
            ban_level = level
          end

          State.new(
            level: level,
            ban_level: ban_level,
            banned_until: banned_until,
            last_violation_at: now,
            event_ids: event_id ? base.event_ids + [event_id] : base.event_ids
          )
        end

        # Keep the state until the ban is over and every level has decayed.
        def expires_in(state, now)
          fully_decayed_at = state.last_violation_at + state.level * decay_period
          expiry = [state.banned_until, fully_decayed_at].compact.max
          (expiry - now).ceil + 1
        end
      end
    end
  end
end
