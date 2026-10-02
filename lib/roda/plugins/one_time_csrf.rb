# frozen-string-literal: true

require 'securerandom'

class Roda
  module RodaPlugins
    # The one_time_csrf plugin builds on the route_csrf plugin to provide
    # one-time CSRF tokens for sensitive operations such as account deletion.
    # Unlike the regular route_csrf tokens, which can be reused any number of
    # times, a one-time CSRF token is consumed by the first request that
    # successfully validates it, so it cannot be replayed.
    #
    # Each one-time token is bound to the session it was generated in, the
    # HTTP request method, and the normalized target path, and has a short
    # lifetime (5 minutes by default).  Regular forms can keep using the
    # existing route_csrf tokens; the one-time mode is opt-in per sensitive
    # action.
    #
    # == Usage
    #
    #   plugin :one_time_csrf
    #
    #   route do |r|
    #     r.get 'delete-account' do
    #       # render form containing one_time_csrf_tag('/delete-account')
    #     end
    #
    #     r.post 'delete-account' do
    #       check_one_time_csrf!
    #       # perform sensitive operation
    #     end
    #   end
    #
    # This plugin supports the following options:
    #
    # :field :: Form input parameter name for the one-time CSRF token
    #           (default: '_one_time_csrf')
    # :session_key :: Session key for the random session identifier the tokens
    #                 are bound to (default: '_roda_one_time_csrf_session')
    # :store :: Object implementing the token storage protocol described below
    #           (default: a new OneTimeCsrf::MemoryStore instance)
    # :ttl :: Number of seconds a one-time token remains valid (default: 300)
    #
    # == Storage Protocol
    #
    # The :store option accepts any object implementing the following
    # protocol:
    #
    # store.write(token, data, ttl) :: Store the given data (a hash) under the
    #                                  token key, expiring it ttl seconds from now.
    # store.read(token) :: Return the data stored under the token key, or nil if
    #                      there is no such entry or it has expired.  Must not
    #                      remove the entry.
    # store.consume(token, data) :: Atomically remove the entry for the token key
    #                               if and only if it currently holds the given
    #                               data and has not expired, returning true if
    #                               the entry was removed and false otherwise.
    #
    # +consume+ must be atomic: if two requests concurrently attempt to consume
    # the same token, exactly one of them may succeed.  Validation reads the
    # token data and checks the session, request method, and path bindings
    # before consuming, so a failed validation never consumes a token.  If the
    # store raises an error during validation (for example, because the storage
    # backend is unavailable), the CSRF check fails closed and the sensitive
    # operation is rejected.
    #
    # The plugin ships with OneTimeCsrf::MemoryStore, an in-memory
    # implementation of the protocol.  It is only suitable for single-process
    # deployments; multi-process deployments should provide a store backed by
    # shared storage with an atomic compare-and-delete operation.
    #
    # == Methods
    #
    # This adds the following instance methods:
    #
    # check_one_time_csrf!(opts={}) :: Requires that the request contain a valid
    #                                  one-time CSRF token bound to the current
    #                                  session, request method, and path.
    #                                  Consumes the token on success.  If a block
    #                                  is provided, it is treated as a routing
    #                                  block when the token is invalid; otherwise
    #                                  a Roda::RodaPlugins::RouteCsrf::InvalidToken
    #                                  exception is raised.  The :token option can
    #                                  be used to specify the submitted token
    #                                  instead of looking in the parameters.
    # one_time_csrf_field :: The field name to use for the hidden tag containing
    #                        the one-time CSRF token.
    # one_time_csrf_tag(action=nil, method='POST') :: An HTML hidden input tag
    #                        string containing a one-time CSRF token.  Takes the
    #                        same arguments as one_time_csrf_token.
    # one_time_csrf_token(action=nil, method='POST') :: The value of a one-time
    #                        CSRF token bound to the current session, the given
    #                        request method, and the normalized target path (the
    #                        action argument is treated like a form action and
    #                        normalized using the route_csrf plugin's csrf_path
    #                        method; nil uses the current request path).
    # valid_one_time_csrf?(opts={}) :: Whether the submitted one-time CSRF token
    #                        is valid.  Note this consumes the token if it is
    #                        valid.  Takes the same option hash as
    #                        check_one_time_csrf!.
    module OneTimeCsrf
      # Default one_time_csrf option values
      DEFAULTS = {
        :field => '_one_time_csrf'.freeze,
        :session_key => '_roda_one_time_csrf_session'.freeze,
        :ttl => 300
      }.freeze

      # In-memory implementation of the one-time CSRF token storage protocol.
      # Consumption is atomic via a mutex, so only one of any number of
      # concurrent requests can consume a given token.  The clock can be
      # overridden (mainly useful for testing) by passing an object responding
      # to +call+ and returning the current time in seconds.
      class MemoryStore
        def initialize(clock: nil)
          @clock = clock || lambda{Process.clock_gettime(Process::CLOCK_MONOTONIC)}
          @mutex = Mutex.new
          @entries = {}
        end

        # Store the data under the token key, expiring it ttl seconds from now.
        def write(token, data, ttl)
          now = @clock.call
          @mutex.synchronize do
            prune(now)
            @entries[token] = [data, now + ttl]
          end
          nil
        end

        # Return the data stored under the token key, or nil if there is no
        # such entry or it has expired.  Does not remove the entry.
        def read(token)
          now = @clock.call
          @mutex.synchronize do
            if (entry = @entries[token]) && entry[1] > now
              entry[0]
            end
          end
        end

        # Atomically remove the entry for the token key if and only if it
        # currently holds the given data and has not expired.  Returns true if
        # the entry was removed, false otherwise.
        def consume(token, data)
          now = @clock.call
          @mutex.synchronize do
            if (entry = @entries[token]) && entry[1] > now && entry[0] == data
              @entries.delete(token)
              true
            else
              false
            end
          end
        end

        private

        # Remove all expired entries.  Must be called with the mutex held.
        def prune(now)
          @entries.delete_if{|_, entry| entry[1] <= now}
        end
      end

      def self.load_dependencies(app, opts=OPTS, &_)
        app.plugin :route_csrf
      end

      def self.configure(app, opts=OPTS, &_)
        options = app.opts[:one_time_csrf] = (app.one_time_csrf_opts || DEFAULTS).merge(opts)
        options[:store] ||= MemoryStore.new
        options.freeze
      end

      module ClassMethods
        RodaPlugins.opt_attr_reader(self, :one_time_csrf, name: :one_time_csrf_opts)
      end

      module InstanceMethods
        # Require that the request contain a valid one-time CSRF token bound to
        # the current session, request method, and path.  Consumes the token on
        # success.  If the token is invalid and a block is given, treat the
        # block as a routing block; otherwise, raise a
        # Roda::RodaPlugins::RouteCsrf::InvalidToken exception.
        def check_one_time_csrf!(opts=OPTS, &block)
          return if valid_one_time_csrf?(opts)

          if block
            @_request.on(&block)
          end

          raise RouteCsrf::InvalidToken, "invalid or expired one-time CSRF token"
        end

        # The name of the hidden input tag containing the one-time CSRF token.
        def one_time_csrf_field
          one_time_csrf_options[:field]
        end

        # An HTML hidden input tag string containing a one-time CSRF token.
        # See one_time_csrf_token for arguments.
        def one_time_csrf_tag(*args)
          "<input type=\"hidden\" name=\"#{one_time_csrf_field}\" value=\"#{one_time_csrf_token(*args)}\" \/>"
        end

        # The value of a one-time CSRF token bound to the current session, the
        # given request method (POST by default), and the normalized target
        # path.  The action argument is treated like an HTML form action and
        # normalized using csrf_path; nil uses the current request path.
        def one_time_csrf_token(action=nil, method='POST')
          options = one_time_csrf_options
          token = SecureRandom.base64(32)
          options[:store].write(token, {
            :session=>one_time_csrf_session_id(options),
            :method=>method.to_s.upcase,
            :path=>csrf_path(action)
          }, options[:ttl])
          token
        end

        # Whether the submitted one-time CSRF token is valid for the current
        # session, request method, and path.  Consumes the token if valid.
        # Fails closed (returning false) if the token store is unavailable.
        def valid_one_time_csrf?(opts=OPTS)
          options = opts.empty? ? one_time_csrf_options : one_time_csrf_options.merge(opts)
          token = options[:token] || @_request.params[options[:field]]
          return false unless token.is_a?(String)

          store = options[:store]
          begin
            data = store.read(token)
          rescue StandardError
            # Token store unavailable, fail closed
            return false
          end

          return false unless data.is_a?(Hash)
          return false unless (session_id = session[options[:session_key]]) && data[:session] == session_id
          return false unless data[:method] == csrf_request_method.to_s.upcase
          return false unless data[:path] == @_request.path

          begin
            store.consume(token, data)
          rescue StandardError
            # Token store unavailable, fail closed
            false
          end
        end

        private

        # Helper for getting the plugin options.
        def one_time_csrf_options
          self.class.one_time_csrf_opts
        end

        # The random identifier for the current session that one-time CSRF
        # tokens are bound to, generating and storing it in the session if it
        # is not already present.
        def one_time_csrf_session_id(options)
          session[options[:session_key]] ||= SecureRandom.base64(32)
        end
      end
    end

    register_plugin(:one_time_csrf, OneTimeCsrf)
  end
end
