# frozen_string_literal: true

module Dry
  class Container
    # Read-only access to a fixed subset of a container
    #
    # A view does not mutate or copy the source container. Its visibility rules
    # apply consistently to {#resolve}, {#key?}, {#keys}, and {#each}. Requests
    # outside the view raise the same error whether the key exists in the source
    # container or not, so an unauthorized caller cannot use the message to tell
    # whether a secret key exists.
    #
    # Namespaces are prefixes scoped by the source container's namespace
    # separator. A view for +"payments"+ grants +"payments.gateway"+, but not
    # +"payments_other"+.
    #
    # Security boundary: this object limits access through its own API only. It
    # is still Ruby, so resolving an item executes that item's registered code.
    # If an accessible factory was defined with a closure over the original
    # container (or returns that container), the code can access data outside
    # the view. Freezing the source prevents later registration, but it does not
    # neutralize a closure that already has the source. Do not grant access to
    # factories that intentionally return unrestricted capabilities.
    #
    # @example with explicit keys
    #   container.register("public.time", -> { Time.now })
    #   container.register("private.signing_key", "secret")
    #   view = container.read_only_view(keys: "public.time")
    #   view.resolve("public.time")
    #   view.resolve("private.signing_key") # raises KeyError
    #
    # @example with a namespace
    #   view = container.read_only_view(namespaces: "public")
    #   view.keys # only includes keys below "public"
    #
    # @api public
    class ReadOnlyView
      include ::Enumerable

      # @param [Dry::Container::Mixin] container
      #   Source container to resolve values from.
      # @param [Array<String, Symbol>] keys
      #   Explicit full keys exposed by the view.
      # @param [String, Symbol, nil] key
      #   A single explicit full key exposed by the view.
      # @param [Array<String, Symbol>] namespaces
      #   Namespaces exposed by the view.
      # @param [String, Symbol, nil] namespace
      #   A single namespace exposed by the view.
      #
      # @raise [ArgumentError] when no key or namespace is given
      #
      # @api public
      def initialize(container, keys: [], key: nil, namespaces: [], namespace: nil)
        @container = container
        @separator = container.config.namespace_separator
        @keys = normalize(keys).concat(normalize(key)).uniq.freeze
        raw_namespaces = normalize(namespaces).concat(normalize(namespace))

        if raw_namespaces.any? && (!@separator.is_a?(::String) || @separator.empty?)
          raise ArgumentError, "a non-empty namespace separator is required for namespaces"
        end

        @namespaces = raw_namespaces.map { |namespace|
          namespace.delete_suffix(@separator)
        }.uniq.freeze

        if @keys.empty? && @namespaces.empty?
          raise ArgumentError, "at least one key or namespace must be given"
        end

        freeze
      end

      # Resolve an authorized item from the source container
      #
      # A fallback block is called only when the requested key is authorized by
      # the view but absent from the source. An unauthorized request raises
      # regardless of whether a block was supplied.
      #
      # @param [String, Symbol] key requested full container key
      # @yield optional fallback for an authorized but missing key
      # @return [Object] the resolved item
      # @raise [KeyError] when the key is missing or not visible to the view
      #
      # @api public
      def resolve(key, &block)
        normalized_key = key.to_s

        unless visible?(normalized_key)
          raise restricted_key_error(normalized_key)
        end

        if container.key?(normalized_key)
          begin
            container.resolve(normalized_key)
          rescue Dry::Container::KeyError => error
            unless error.receiver.equal?(container._container) &&
                   error.key == normalized_key
              raise
            end

            raise restricted_key_error(normalized_key)
          end
        elsif block
          yield(key)
        else
          raise restricted_key_error(normalized_key)
        end
      end

      # Return whether the key is both registered and authorized for this view
      #
      # @param [String, Symbol] key requested full container key
      # @return [Boolean]
      #
      # @api public
      def key?(key)
        normalized_key = key.to_s
        visible?(normalized_key) && container.key?(normalized_key)
      end

      # Return all currently registered keys visible through the view
      #
      # @return [Array<String>]
      #
      # @api public
      def keys
        container.config.resolver.keys(container._container).select { |key|
          visible?(key)
        }.freeze
      end

      # Iterate over each currently visible key and its resolved value
      #
      # The source container is consulted lazily. Values are resolved only as
      # the enumerator is consumed.
      #
      # @return [Enumerator, Array<Array(String, Object)>]
      #
      # @api public
      def each(&block)
        return to_enum(:each) unless block

        keys.each { |key| yield(key, resolve(key)) }
      end

      # Iterate over each currently visible key
      #
      # @return [Enumerator, self]
      #
      # @api public
      def each_key(&block)
        return to_enum(:each_key) unless block

        keys.each(&block)
        self
      end

      # Alias for {#resolve}; it uses the same visibility check
      #
      # @see #resolve
      # @api public
      def [](key)
        resolve(key)
      end

      # Expose access rules without revealing which allowed keys currently exist
      #
      # @return [Hash{Symbol => Array<String>}]
      #
      # @api public
      def allowed
        {keys: @keys, namespaces: @namespaces}.freeze
      end

      private

      # @private
      attr_reader :container

      # @private
      def visible?(key)
        @keys.include?(key) || @namespaces.any? { |namespace| within_namespace?(key, namespace) }
      end

      # @private
      def within_namespace?(key, namespace)
        key.start_with?(namespace + @separator)
      end

      # @private
      def normalize(values)
        Array(values).map { |value| value.to_s }.reject(&:empty?)
      end

      # @private
      def restricted_key_error(key)
        Dry::Container::KeyError.new(
          %(key not found: "#{key}"),
          key: key,
          receiver: self
        )
      end
    end

    # Compatibility alias for callers using the resolver-oriented name
    ResolverView = ReadOnlyView

    # Short public name for the restricted read-only view
    View = ReadOnlyView
  end
end
