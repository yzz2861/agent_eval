# frozen_string_literal: true

module Dry
  module Configurable
    # A read-only, bounded view over a {Config} that resolves secret settings
    # through an injected provider.
    #
    # The config itself only ever stores secret *references* (such as vault key
    # names). Resolved secret values are yielded from the scope on demand and are
    # never cached on either the scope or the config. The resource handed out by
    # the provider's `#open` is always returned through `#close` when the scope
    # finishes, even when the block raises.
    #
    # A provider is any object responding to:
    #
    #   - `#open` -> a resource (a client, session, ...) shared by all reads
    #   - `#read(resource, reference)` -> the secret value
    #   - `#close(resource)` -> releases the resource
    #
    # `#read` should raise {SecretNotFoundError} when no secret exists for the
    # reference; any other failure is wrapped in {SecretReadError}. Provider
    # error messages are never copied into the wrapped error text, so a faulty
    # provider cannot leak secret material through exception messages.
    #
    # @api public
    class SecretScope
      # @api private
      State = Struct.new(:closed)

      # @api private
      def self.open(config, provider, &block)
        validate_provider!(provider)

        resource = provider.open
        scope = new(config, provider, resource, State.new(false), false)

        return scope unless block

        begin
          yield(scope)
        ensure
          scope.close
        end
      end

      # @api private
      def self.validate_provider!(provider)
        missing = %i[open read close].reject { |method_name|
          provider.respond_to?(method_name)
        }

        return if missing.empty?

        raise SecretProviderError,
          "secret provider must respond to #{missing.map { |n| "##{n}" }.join(", ")}"
      end

      # @api private
      def initialize(config, provider, resource, state, borrowed)
        @config = config
        @provider = provider
        @resource = resource
        @state = state
        @borrowed = borrowed
      end

      # Reads a setting by name. Secret settings are resolved through the
      # provider; nested configs are returned as nested scopes.
      #
      # @param [String,Symbol] name
      #
      # @return [Object]
      #
      # @raise [SecretNotFoundError] when no secret reference is configured or
      #   no secret exists for the reference
      # @raise [SecretReadError] when the provider fails while reading
      #
      # @api public
      def [](name)
        ensure_open!

        name = name.to_sym
        setting = @config._settings[name]

        raise ArgumentError, "+#{name}+ is not a setting name" unless setting

        return resolve_secret(name, setting) if setting.secret?

        value = @config[name]
        value.is_a?(Config) ? borrow(value) : value
      end

      # Releases the resource obtained from the provider. Nested scopes borrow
      # the outer resource and do not release it; the outermost scope always
      # releases exactly once.
      #
      # @return [void]
      #
      # @api public
      def close
        return if @borrowed || @state.closed

        @state.closed = true
        @provider.close(@resource)
      ensure
        @resource = nil
        @provider = nil
      end

      # @return [Boolean]
      #
      # @api public
      def open?
        !@state.closed
      end

      # @return [String]
      #
      # @api public
      def inspect
        state = open? ? "open" : "closed"
        "#<Dry::Configurable::SecretScope #{state}>"
      end
      alias_method :to_s, :inspect

      private

      def borrow(config)
        self.class.new(config, @provider, @resource, @state, true)
      end

      def resolve_secret(name, setting = @config._settings[name])
        reference = @config[name]

        if reference.nil? || reference.equal?(Undefined)
          raise SecretNotFoundError,
            "no secret reference is configured for +#{name}+ setting"
        end

        value =
          begin
            @provider.read(@resource, reference)
          rescue SecretNotFoundError
            raise
          rescue StandardError => error
            raise SecretReadError,
              "failed to read secret for +#{name}+ setting " \
              "(reference #{reference.inspect}): #{error.class}"
          end

        setting.constructor.(value)
      end

      def ensure_open!
        return unless @state.closed

        raise SecretProviderError, "cannot read secrets outside of their scope"
      end

      def method_missing(name, *args)
        setting_name = name.to_s.tr("=", "").to_sym
        setting = @config._settings[setting_name]

        super unless setting

        if name.end_with?("=")
          raise FrozenConfigError, "secret scopes are read-only"
        end

        self[setting_name]
      end

      def respond_to_missing?(meth, include_private = false)
        @config._settings.key?(meth.to_s.tr("=", "").to_sym) || super
      end
    end
  end
end
