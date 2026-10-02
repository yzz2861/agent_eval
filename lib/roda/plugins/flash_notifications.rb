# frozen_string_literal: true

class Roda
  module RodaPlugins
    # The flash_notifications plugin stores notifications in the session until
    # they expire or are explicitly acknowledged by ID. Unlike the flash plugin,
    # reading notifications does not consume them. This is useful when page and
    # polling requests may both receive the same notification before the client
    # has acknowledged it.
    #
    # This plugin requires session support, such as Roda's sessions plugin or
    # other rack session middleware.
    #
    #   plugin :sessions, secret: SECRET
    #   plugin :flash_notifications
    #
    #   route do |r|
    #     r.get 'notifications' do
    #       flash_notifications.to_json
    #     end
    #
    #     r.post 'notifications', String do |id|
    #       {acknowledged: ack_flash_notification(id)}.to_json
    #     end
    #
    #     r.post 'things' do
    #       id = add_flash_notification('Saved')
    #       {id: id}.to_json
    #     end
    #   end
    #
    # Each notification is a hash with "id", "message", and "expires_at"
    # entries. Notification IDs are session-local monotonically increasing
    # integers. A notification added after older data has been removed receives
    # a new ID, so an old acknowledgment cannot delete it based on array
    # position. The ID sequence remains in the session while it exists.
    #
    # Notifications are limited by both retention time and capacity. Expired
    # notifications are removed when notifications are read, added, or
    # acknowledged. When a notification is added, expired notifications are
    # removed first and, if necessary, the oldest remaining notifications are
    # evicted to make room for the newest notification.
    #
    # This plugin can be used with the regular flash plugin; the two features
    # use separate session keys and do not affect each other.
    #
    # == Concurrency
    #
    # Concurrent readers can safely reread notifications. However, making an
    # acknowledgment durable has the same read-modify-write requirements as any
    # other session update. This plugin relies on the configured session store
    # to provide its usual concurrency guarantees (such as request locking or an
    # atomic update mechanism). It does not implement optimistic concurrency,
    # compare-and-swap, or server-side notification storage, and cannot prevent
    # lost updates when two concurrent requests modify a session whose backend
    # does not serialize those updates, including separate cookie-bearing
    # requests using the standard encrypted cookie session without external
    # coordination.
    #
    # == Options
    #
    # :retention :: Default number of seconds from creation until a notification
    #               expires (default: 86400). A per-notification value can be
    #               supplied when adding a notification.
    # :capacity :: Maximum number of notifications to retain per session
    #              (default: 20).
    # :session_key :: Session key used for notifications (default:
    #                 '_flash_notifications').
    # :sequence_session_key :: Session key used for the ID sequence (default:
    #                          '_flash_notification_sequence').
    # :clock :: Callable returning the current integer timestamp, intended for
    #           testing (default: current Unix time).
    module FlashNotifications
      DEFAULT_OPTIONS = {
        :session_key=>'_flash_notifications'.freeze,
        :sequence_session_key=>'_flash_notification_sequence'.freeze,
        :retention=>86400,
        :capacity=>20,
        :clock=>lambda{Time.now.to_i}.freeze
      }.freeze

      SCOPE_INSTANCE_VARIABLES = [:@_flash_notification_store].freeze

      # Session-backed collection of unacknowledged notifications.
      class NotificationStore
        include Enumerable

        # The ordered notifications that have not expired or been acknowledged.
        attr_reader :notifications, :sequence

        # Initialize the store with the notification data, sequence counter,
        # and configured retention, capacity, and clock.
        def initialize(notifications, sequence, retention, capacity, clock)
          @notifications = normalize(notifications)
          @sequence = [sequence.to_i, *@notifications.map{|notification| notification['id']}].max
          @retention = retention
          @capacity = capacity
          @clock = clock
          prune
          enforce_capacity
        end

        # Add a notification and return its ID. Expired notifications are
        # removed before oldest notifications are evicted so the new
        # notification fits within the configured capacity.
        def add(message, retention=@retention)
        unless retention.is_a?(Numeric) && retention > 0 && retention.finite?
            raise RodaError, "flash notification retention must be a positive number"
          end

          prune
          @sequence += 1
          notification = {
            'id'=>@sequence,
            'message'=>message,
            'expires_at'=>now + retention
          }
          enforce_capacity
          @notifications << notification
          @sequence
        end

        # Acknowledge the notification with the given ID and return whether a
        # current notification was removed. Repeating an acknowledgment or
        # acknowledging an unknown or expired ID returns false.
        def ack(id)
          prune
          id = notification_id(id)
          return false unless id
          before = @notifications.length
          @notifications.delete_if{|notification| notification['id'] == id}
          @notifications.length != before
        end

        # Iterate over current notifications in insertion order.
        def each(&block)
          prune
          @notifications.each(&block)
        end

        private

        # Remove expired notifications.
        def prune
          current_time = now
          @notifications.reject!{|notification| notification['expires_at'] <= current_time}
        end

        # Current integer timestamp from the configured clock.
        def now
          @clock.call.to_i
        end

        # Return a valid integer notification ID or nil for values that cannot
        # identify a notification.
        def notification_id(id)
          case id
          when Integer
            id if id > 0
          when String
            id =~ /\A[1-9]\d*\z/ ? id.to_i : nil
          end
        end

        # Discard malformed session data while retaining entries that have an
        # integer ID, message, and expiration timestamp.
        def normalize(notifications)
          return [] unless notifications.is_a?(Array)
          notifications.map do |notification|
            next unless notification.is_a?(Hash)
            id = notification['id']
            message = notification['message']
            expires_at = notification['expires_at']
            next unless id.is_a?(Integer) && id > 0 && expires_at.is_a?(Numeric) && notification.key?('message')
            {'id'=>id, 'message'=>message, 'expires_at'=>expires_at.to_i}
          end.compact
        end

        # Keep only the newest notifications up to the configured capacity.
        def enforce_capacity
          @notifications.shift while @notifications.length > @capacity
        end
      end

      def self.configure(app, opts=OPTS)
        options = if app.opts[:flash_notifications]
          app.opts[:flash_notifications].merge(opts)
        else
          DEFAULT_OPTIONS.merge(opts)
        end

        unless options[:session_key].is_a?(String) && options[:sequence_session_key].is_a?(String)
          raise RodaError, "flash_notifications :session_key and :sequence_session_key options must be strings"
        end

        if options[:session_key] == options[:sequence_session_key]
          raise RodaError, "flash_notifications :session_key and :sequence_session_key options must be different strings"
        end

        unless options[:retention].is_a?(Numeric) && options[:retention] > 0 && options[:retention].finite?
          raise RodaError, "flash_notifications :retention option must be a positive number"
        end

        unless options[:capacity].is_a?(Integer) && options[:capacity] > 0
          raise RodaError, "flash_notifications :capacity option must be a positive integer"
        end

        unless options[:clock].respond_to?(:call)
          raise RodaError, "flash_notifications :clock option must respond to call"
        end

        app.opts[:flash_notifications] = options.freeze
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :flash_notifications, name: :flash_notifications_opts)
      end

      module InstanceMethods
        # Return the current notifications without consuming them.
        def flash_notifications
          _flash_notification_store.to_a
        end

        # Add a notification and return its unique session-local ID.
        def add_flash_notification(message, retention=nil)
          _flash_notification_store.add(message, retention || self.class.flash_notifications_opts[:retention])
        end

        # Acknowledge and remove the notification with the given ID.
        def ack_flash_notification(id)
          _flash_notification_store.ack(id)
        end

        private

        # Access the notification store, loading it from the session if needed.
        def _flash_notification_store
          @_flash_notification_store ||=
            begin
              opts = self.class.flash_notifications_opts
              notifications = session[opts[:session_key]]
              sequence = session[opts[:sequence_session_key]] || 0
              NotificationStore.new(notifications, sequence, opts[:retention], opts[:capacity], opts[:clock])
            end
        end

        # Persist notification changes while leaving regular flash data alone.
        def _roda_after_40__flash_notifications(_)
          return unless store = @_flash_notification_store
          opts = self.class.flash_notifications_opts

          if store.notifications.empty?
            session.delete(opts[:session_key])
          else
            session[opts[:session_key]] = store.notifications
          end

          if store.sequence == 0
            session.delete(opts[:sequence_session_key])
          else
            session[opts[:sequence_session_key]] = store.sequence
          end
        end
      end
    end

    register_plugin(:flash_notifications, FlashNotifications)
  end
end
