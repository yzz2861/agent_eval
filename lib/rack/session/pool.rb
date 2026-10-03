# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2023, by Samuel Williams.

require_relative 'abstract/id'

module Rack
  module Session
    # Rack::Session::Pool provides simple cookie based session management.
    # Session data is stored in a hash held by @pool.
    # In the context of a multithreaded environment, sessions being
    # committed to the pool is done in a merging manner.
    #
    # The :drop option is available in rack.session.options if you wish to
    # explicitly remove the session from the session cache.
    #
    # Example:
    #   myapp = MyRackApp.new
    #   sessioned = Rack::Session::Pool.new(myapp,
    #     :domain => 'foo.com',
    #     :expire_after => 2592000
    #   )
    #   Rack::Handler::WEBrick.run sessioned

    class Pool < Abstract::PersistedSecure
      attr_reader :mutex, :pool
      DEFAULT_OPTIONS = Abstract::ID::DEFAULT_OPTIONS.merge(drop: false, allow_fallback: true)

      def initialize(app, options = {})
        super
        @pool = Hash.new
        @timestamps = Hash.new
        @last_seen_time = Hash.new
        @mutex = Mutex.new
        @allow_fallback = @default_options.delete(:allow_fallback)
      end

      def generate_sid(*args, use_mutex: true)
        loop do
          sid = super(*args)
          break sid unless use_mutex ? @mutex.synchronize { @pool.key? sid.private_id } : @pool.key?(sid.private_id)
        end
      end

      def find_session(req, sid)
        @mutex.synchronize do
          unless sid and session = get_session_with_fallback(sid)
            sid, session = generate_sid(use_mutex: false), {}
            @pool.store sid.private_id, session
            initialize_timestamps(sid)
          end

          if session_expired?(req, sid, session, @default_options)
            @pool.delete(sid.private_id)
            @pool.delete(sid.public_id)
            @timestamps.delete(sid.private_id)
            @last_seen_time.delete(sid.private_id)
            sid, session = generate_sid(use_mutex: false), {}
            @pool.store sid.private_id, session
            initialize_timestamps(sid)
          elsif !@timestamps.key?(sid.private_id)
            initialize_timestamps(sid)
          end

          [sid, session]
        end
      end

      def write_session(req, session_id, new_session, options)
        @mutex.synchronize do
          return false unless get_session_with_fallback(session_id)
          @pool.store session_id.private_id, new_session

          if manages_session_time?(options)
            current_time = now
            timestamps = @timestamps[session_id.private_id]
            if !valid_session_time?(timestamps&.first) || !valid_session_time?(timestamps&.last)
              timestamps = [current_time, current_time]
            elsif !skip_idle_renewal?(req, options)
              created_at, _last_accessed_at = timestamps
              timestamps = [created_at, current_time]
            end
            @timestamps.store session_id.private_id, timestamps
            remember_seen_time(session_id, current_time)
          end

          session_id
        end
      end

      def delete_session(req, session_id, options)
        @mutex.synchronize do
          @pool.delete(session_id.public_id)
          @pool.delete(session_id.private_id)
          @timestamps.delete(session_id.private_id)
          @last_seen_time.delete(session_id.private_id)

          unless options[:drop]
            sid = generate_sid(use_mutex: false)
            @pool.store(sid.private_id, {})
            sid
          end
        end
      end

      private

      def timestamps_for(req, sid, session, current_time)
        @timestamps[sid.private_id]
      end

      def session_expired?(req, sid, session, options, current_time = now)
        return false unless manages_session_time?(options)

        created_at, last_accessed_at = timestamps_for(req, sid, session, current_time)
        return true unless valid_session_time?(created_at) && valid_session_time?(last_accessed_at)
        return true if created_at > last_accessed_at

        observed_time = @last_seen_time[sid.private_id] || current_time

        if (idle_timeout = options[:idle_timeout])
          return true if current_time >= last_accessed_at + idle_timeout
          return true if observed_time > last_accessed_at + idle_timeout
        end

        if (absolute_timeout = options[:absolute_timeout])
          return true if current_time - created_at >= absolute_timeout
        end

        false
      end

      def initialize_timestamps(sid)
        current_time = now
        @timestamps.store(sid.private_id, [current_time, current_time])
        @last_seen_time.store(sid.private_id, current_time)
      end

      def remember_seen_time(sid, current_time = now)
        previous_seen = @last_seen_time[sid.private_id]
        @last_seen_time.store(sid.private_id, previous_seen ? [current_time, previous_seen].max : current_time)
      end

      def get_session_with_fallback(sid)
        @pool[sid.private_id] || (@pool[sid.public_id] if @allow_fallback)
      end
    end
  end
end
