# frozen_string_literal: true

module Faraday
  module Batch
    # A single request inside a batch. The target is kept as given, so it may
    # be a relative path such as +/users/1+ as required by the batching API.
    class Part
      # @return [String, Symbol] HTTP method, e.g. +:get+ or +"GET".
      attr_accessor :method
      # @return [String] Request target. Relative targets such as +"/users/1"
      #   are preserved as given.
      attr_accessor :path
      alias target path
      alias target= path=
      # @return [Faraday::Utils::Headers] Request headers.
      attr_reader :headers
      # @return [Object] Request body.
      attr_accessor :body
      # @return [String] Unique identifier used as the part Content-ID.
      attr_accessor :content_id
      alias id content_id
      alias id= content_id=

      # @param method [String, Symbol, nil] HTTP method.
      # @param path [String, nil] Request target, relative or absolute.
      # @param headers [Hash{String => String}, nil] Request headers.
      # @param body [#to_s, #read, nil] Request body.
      # @param content_id [#to_s, nil] Unique Content-ID; a random one is
      #   generated when omitted.
      def initialize(method: nil, path: nil, headers: nil, body: nil, content_id: nil)
        @method = method
        @path = path
        @headers = Faraday::Utils::Headers.new
        @headers.update(headers) if headers
        @body = body
        @content_id = content_id.nil? ? Coder.generate_content_id : content_id.to_s
      end

      # @return [String, nil] Binary-safe String body, or nil when there is
      #   none. IO-like objects are read once.
      def encoded_body
        Coder.coerce_body(body)
      end
    end
  end
end
