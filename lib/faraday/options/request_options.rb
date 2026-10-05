# frozen_string_literal: true

module Faraday
  # @!parse
  #   # RequestOptions contains the configurable properties for a Faraday request.
  #   #
  #   # @!attribute params_encoder
  #   #   @return [Object] the params encoder used to serialize the request params
  #   #
  #   # @!attribute proxy
  #   #   @return [ProxyOptions] proxy options for this request
  #   #
  #   # @!attribute bind
  #   #   @return [Hash] the local host and port to bind the connection to
  #   #
  #   # @!attribute timeout
  #   #   @return [Integer] time limit for the entire request (in seconds)
  #   #
  #   # @!attribute open_timeout
  #   #   @return [Integer] time limit for just the connection phase (in seconds)
  #   #
  #   # @!attribute read_timeout
  #   #   @return [Integer] time limit for the first response byte received from
  #   #           the server (in seconds)
  #   #
  #   # @!attribute write_timeout
  #   #   @return [Integer] time limit for the client to send the request to the
  #   #           server (in seconds)
  #   #
  #   # @!attribute boundary
  #   #   @return [String] the boundary used for multipart request bodies
  #   #
  #   # @!attribute oauth
  #   #   @return [Hash] OAuth options used by the OAuth middleware
  #   #
  #   # @!attribute context
  #   #   @return [Hash] free-form storage carried alongside the request
  #   #
  #   # @!attribute on_data
  #   #   @return [Proc] callback invoked with each chunk when streaming the response
  #   #
  #   # @!attribute required_capabilities
  #   #   @return [Array<Symbol>] capabilities the adapter must declare for this
  #   #           request. An error is raised before the request reaches the
  #   #           adapter if any of them is missing.
  #   class RequestOptions < Options; end
  RequestOptions = Options.new(:params_encoder, :proxy, :bind,
                               :timeout, :open_timeout, :read_timeout,
                               :write_timeout, :boundary, :oauth,
                               :context, :on_data, :required_capabilities) do
    def []=(key, value)
      if key && key.to_sym == :proxy
        super(key, value ? ProxyOptions.from(value) : nil)
      else
        super
      end
    end

    def stream_response?
      on_data.is_a?(Proc)
    end

    def required_capabilities=(value)
      self[:required_capabilities] = Array(value).map(&:to_sym)
    end

    def required_capabilities
      self[:required_capabilities] || []
    end

    # Hidden from +inspect+ when unset, so requests without capability
    # requirements still render as (empty).
    def inspect
      values = []
      members.each do |member|
        value = member == :required_capabilities ? self[member] : send(member)
        values << "#{member}=#{value.inspect}" if value
      end
      values = values.empty? ? '(empty)' : values.join(', ')

      %(#<#{self.class} #{values}>)
    end

    # Declares capabilities that the adapter must support for this request.
    # Values are appended to any previously declared ones.
    #
    # @param capabilities [Array<Symbol>] required capabilities.
    # @return [Array<Symbol>] the full list of required capabilities.
    def require_capabilities(*capabilities)
      current = self[:required_capabilities] || []
      merged = current.concat(capabilities.flatten.map(&:to_sym))
      merged.uniq!
      self[:required_capabilities] = merged
    end
  end
end
