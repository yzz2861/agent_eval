# frozen-string-literal: true

require 'securerandom'

class Roda
  module RodaPlugins
    # The flash_notifications plugin extends the flash plugin with notifications
    # that remain available until they are explicitly acknowledged or expire.
    # This is useful when a page request and a polling request may both receive
    # the same notification; unlike regular flash entries, reading a notification
    # does not consume it.
    #
    #   plugin :sessions, secret: SECRET
    #   plugin :flash_notifications, retention_period: 300, max_notifications: 20
    #
    #   route do |r|
    #     r.get 'notifications' do
    #       flash_notifications
    #     end
    #
    #     r.post 'notifications' do
    #       id = flash_notify(r.params['message'])
    #       id
    #     end
    #
    #     r.post 'notifications/ack' do
    #       ack_flash_notification(r.params['id']) ? 'acknowledged' : 'unknown'
    #     end
    #   end
    #
    # = Options
    #
    # :retention_period :: Number of seconds to retain each notification (default: 300).
    # :max_notifications :: Maximum number of notifications to retain (default: 20).
    #                     When exceeded, oldest notifications are removed first.
    # :session_key :: Session key where notifications are stored
    #                  (default: '_flash_notifications').
    #
    # Each notification is a JSON-compatible hash with "id", "message", and
    # "expires_at" entries. Notifications are returned oldest first. By default,
    # notifications are retained for 300 seconds and at most 20 notifications are
    # stored. When the capacity is exceeded, the oldest notifications are removed.
    #
    # Acknowledging a notification removes only the notification with the given
    # server-generated ID. Acknowledging an unknown, expired, or already
    # acknowledged ID returns false and makes no other change. Notification IDs
    # are random and are not reused.
    #
    # == Concurrency
    #
    # This plugin keeps separate read and acknowledge operations, but it stores
    # the complete notification list in the session. It therefore depends on the
    # concurrency guarantees of the session storage. Concurrent requests that
    # both read, modify, and write the session can still lose updates if the
    # underlying session store does not serialize or atomically persist those
    # changes. The plugin does not implement locking or prevent lost updates.
    module FlashNotifications
      SCOPE_INSTANCE_VARIABLES = [:@_flash_notifications].freeze

      DEFAULT_OPTIONS = {
        :retention_period=>300,
        :max_notifications=>20,
        :session_key=>'_flash_notifications'.freeze
      }.freeze

      # Stores notifications in the session until they expire or are
      # acknowledged.
      class FlashNotificationStore
        def initialize(session, session_key, now, retention_period, max_notifications)
          @session = session
          @session_key = session_key
          @now = now
          @retention_period = retention_period
          @max_notifications = max_notifications

          @notifications = session[session_key]
          unless @notifications.is_a?(Array)
            @notifications = []
            session[session_key] = @notifications
          end
          prune
        end

        # Return active notifications, oldest first, without removing them.
        def notifications
          prune
          @notifications.map(&:dup)
        end

        # Add a notification and return its unique ID.
        def add(message)
          prune

          id = nil
          loop do
            id = SecureRandom.uuid
            break unless @notifications.any? { |notification| notification['id'] == id }
          end

          @notifications << {
            'id'=>id,
            'message'=>message,
            'expires_at'=>@now + @retention_period
          }
          cap!
          id
        end

        # Remove and return whether the notification with the given ID was active.
        def acknowledge(id)
          prune
          index = @notifications.index { |notification| notification['id'] == id }
          return false unless index

          @notifications.delete_at(index)
          true
        end

        # Remove the session key when no notifications remain.
        def persist
          if @notifications.empty?
            @session.delete(@session_key)
          else
            @session[@session_key] = @notifications
          end
        end

        private

        def prune
          @notifications.select! do |notification|
            notification.is_a?(Hash) &&
              notification['id'].is_a?(String) &&
              notification['expires_at'].is_a?(Integer) &&
              notification['expires_at'] > @now
          end
          cap!
        end

        def cap!
          if @notifications.length > @max_notifications
            @notifications.replace(@notifications.last(@max_notifications))
          end
        end
      end

      def self.load_dependencies(app, _=OPTS)
        app.plugin :flash
      end

      def self.configure(app, opts=OPTS)
        options = DEFAULT_OPTIONS.merge(app.opts[:flash_notifications] || OPTS)
        options = options.merge(opts)

        unless options[:retention_period].is_a?(Integer) && options[:retention_period] > 0
          raise RodaError, "flash_notifications :retention_period option must be a positive Integer"
        end
        unless options[:max_notifications].is_a?(Integer) && options[:max_notifications] > 0
          raise RodaError, "flash_notifications :max_notifications option must be a positive Integer"
        end
        unless options[:session_key].is_a?(String) && !options[:session_key].empty?
          raise RodaError, "flash_notifications :session_key option must be a nonempty String"
        end

        app.opts[:flash_notifications] = options.freeze
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :flash_notifications)
      end

      module InstanceMethods
        # Return the active notifications for the current request.
        def flash_notifications
          flash_notification_store.notifications
        end

        # Add a notification and return the generated notification ID.
        def flash_notify(message)
          flash_notification_store.add(message)
        end

        # Acknowledge a notification by ID. Returns true only if an active
        # notification with that ID was removed.
        def ack_flash_notification(id)
          flash_notification_store.acknowledge(id)
        end

        private

        def flash_notification_store
          @_flash_notifications ||= _flash_notification_store
        end

        def _flash_notification_store
          options = self.class.flash_notifications
          FlashNotificationStore.new(
            session,
            options[:session_key],
            Time.now.to_i,
            options[:retention_period],
            options[:max_notifications]
          )
        end

        def _roda_after_40__flash_notifications(_)
          @_flash_notifications.persist if @_flash_notifications
        end
      end
    end

    register_plugin(:flash_notifications, FlashNotifications)
  end
end
