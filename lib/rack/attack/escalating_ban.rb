# frozen_string_literal: true

module Rack
  class Attack
    # Escalating bans: a configurable ladder of ban levels with different
    # violation thresholds, ban durations and a sliding decay window.
    #
    # Repeated offenses move the discriminator up the ladder (e.g. ban for
    # 1 minute the first time, then 5 minutes, ...). After a quiet period of
    # +decay+ seconds the recorded violations expire and the discriminator
    # gradually falls back to lower levels.
    #
    # Every reported violation carries an +event_id+. Reporting the same
    # event id twice never counts twice. All updates happen inside a single
    # atomic store merge, so concurrent violations cannot be lost, and a new
    # ban never shortens one that is still in effect.
    #
    #   ban = Rack::Attack::EscalatingBan.new(
    #     levels: [
    #       { maxretry: 3, bantime: 60 },
    #       { maxretry: 5, bantime: 300 }
    #     ],
    #     decay: 900
    #   )
    #
    #   Rack::Attack.blocklist('escalating') do |req|
    #     ban.filter(req.ip, req.env['HTTP_X_EVENT_ID']) { bad_request?(req) }
    #   end
    class EscalatingBan
      Level = Struct.new(:name, :maxretry, :bantime)

      # Snapshot of a discriminator's ban state. +level+ (a Level instance)
      # tells which level produced the current ban, and +banned_until+ is the
      # absolute time (Integer, seconds since epoch) at which it ends.
      # +current_level+ is the level the current violation count sits on,
      # even when no ban is active.
      BanStatus = Struct.new(:banned, :level, :level_index, :current_level, :banned_until, :violations) do
        def banned?
          banned
        end

        # Backwards-friendly predicate.
        def active?
          banned
        end
      end

      KEY_PREFIX = 'escalatingban'

      attr_reader :levels, :decay

      def initialize(levels:, decay:, store: nil, clock: -> { Time.now.to_i })
        raise ArgumentError, 'Must pass decay option' if decay.nil?
        raise ArgumentError, 'Must pass at least one level' if levels.nil? || levels.empty?

        @clock = clock
        @decay = decay.to_i
        @levels = levels.each_with_index.map do |level, index|
          maxretry = level[:maxretry] or raise ArgumentError, 'Each level must pass maxretry'
          bantime  = level[:bantime]  or raise ArgumentError, 'Each level must pass bantime'
          Level.new(level[:name] || (index + 1).to_s, maxretry.to_i, bantime.to_i)
        end
        validate_levels!

        @store = store || BanMemoryStore.new(clock: clock)
      end

      # Fail2Ban-compatible integration point for a blocklist. Returns true
      # while the discriminator is banned, and reports a violation (with the
      # given event id) whenever the block evaluates to true.
      def filter(discriminator, event_id = nil)
        violated = block_given? ? yield : false
        status = violated ? report(discriminator, event_id) : self.status(discriminator)
        violated || status.banned?
      end

      # Atomically report a violation and return the resulting BanStatus.
      # Duplicate event ids are ignored; concurrent reports are merged.
      def report(discriminator, event_id = nil)
        state = store.merge(key(discriminator), expires_in: state_ttl) do |current, now|
          merge_state(current, now, event_id)
        end
        status_for(state, @clock.call.to_i)
      end

      def status(discriminator)
        state = store.read(key(discriminator))
        status_for(state, @clock.call.to_i)
      end

      def banned?(discriminator)
        status(discriminator).banned?
      end

      def reset(discriminator)
        store.delete(key(discriminator))
      end

      private

      attr_reader :store

      def validate_levels!
        maxretries = @levels.map(&:maxretry)
        unless maxretries.each_cons(2).all? { |lower, higher| higher >= lower }
          raise ArgumentError, 'Level maxretry values must be ordered from least to most severe'
        end
        unless @levels.map(&:bantime).all?(&:positive?) && @decay.positive?
          raise ArgumentError, 'Level bantime and decay must be positive'
        end
      end

      def key(discriminator)
        "#{KEY_PREFIX}:#{discriminator}"
      end

      # The state is kept alive while violations can still matter: the decay
      # window plus the longest possible ban the highest level can hand out.
      def state_ttl
        @decay + @levels.map(&:bantime).max
      end

      def merge_state(current, now, event_id)
        events = prune(current&.dig('events'), now)
        ban = current&.dig('ban')
        ban = nil if ban && ban['banned_until'].to_i <= now

        unless event_id.nil? || events.any? { |event| event['id'] == event_id }
          events << { 'id' => event_id, 'at' => now }
        end

        count = events.size
        level_index = level_index_for(count)
        new_ban = ban

        if level_index
          banned_until = now + @levels[level_index].bantime
          if ban.nil?
            new_ban = { 'level_index' => level_index, 'banned_until' => banned_until }
          else
            # Never shorten an ongoing ban; renew/upgrade only when the new
            # computation ends later.
            if banned_until > ban['banned_until']
              new_ban = { 'level_index' => level_index, 'banned_until' => banned_until }
            end
          end
        end

        { 'events' => events, 'ban' => new_ban }
      end

      def prune(events, now)
        Array(events).select { |event| event['at'].to_i > now - @decay }
      end

      def level_index_for(count)
        index = nil
        @levels.each_with_index do |level, i|
          index = i if count >= level.maxretry
        end
        index
      end

      def status_for(state, now)
        events = prune(state&.dig('events'), now)
        ban = state&.dig('ban')
        active_ban = ban if ban && ban['banned_until'].to_i > now

        if active_ban
          level_index = active_ban['level_index']
          level = @levels[level_index]
          BanStatus.new(true, level, level_index, level, active_ban['banned_until'], events.size)
        else
          level_index = level_index_for(events.size)
          level = level_index && @levels[level_index]
          BanStatus.new(false, nil, nil, level, nil, events.size)
        end
      end
    end
  end
end
