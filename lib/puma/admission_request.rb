# frozen_string_literal: true

require_relative 'const'

module Puma

  # A read-only snapshot of a request's start line and headers, created right
  # after the request headers have been parsed and before the request body is
  # read (and before any +100 Continue+ is sent).
  #
  # An instance of this class is the only argument passed to the
  # +header_admission+ hook (see {Puma::DSL#header_admission}). It is frozen,
  # exposes no socket or IO object, and cannot be used to consume any of the
  # request body. Header names are normalized to lower case with dashes,
  # e.g. +content-length+ or +x-forwarded-for+.
  #
  class AdmissionRequest

    include Const

    # @!attribute [r] request_method
    # The HTTP request method, e.g. +"GET"+, +"POST"+.
    #
    # @!attribute [r] path
    # The request path, e.g. +"/upload"+.
    #
    # @!attribute [r] query_string
    # The query string, without a leading +?+. May be +nil+.
    #
    # @!attribute [r] http_version
    # The HTTP version of the request, e.g. +"HTTP/1.1"+.
    #
    # @!attribute [r] headers
    # A frozen Hash of the request headers. Keys are lower-cased header names
    # with dashes (e.g. +"content-length"+), values are frozen strings.
    attr_reader :request_method, :path, :query_string, :http_version, :headers

    def initialize(env)
      headers = {}

      env.each do |key, value|
        next unless value.is_a?(String)

        if key.start_with?('HTTP_')
          # Header names are stored CGI-style in env. Underscores sent by the
          # client are still masked as commas at this point, unmask them the
          # same way ClientEnv#req_env_post_parse does.
          name = key.delete_prefix('HTTP_').tr('_,', '-_').downcase
          headers[name] = value.dup.freeze
        elsif key == CONTENT_LENGTH || key == 'CONTENT_TYPE'
          headers[key.tr('_', '-').downcase] = value.dup.freeze
        end
      end

      @headers = headers.freeze

      @request_method = env[REQUEST_METHOD]&.dup&.freeze
      @path           = (env[REQUEST_PATH] || env[REQUEST_URI])&.dup&.freeze
      @query_string   = env[QUERY_STRING]&.dup&.freeze
      @http_version   = env[SERVER_PROTOCOL]&.dup&.freeze

      freeze
    end

    # Returns the value of a request header, or +nil+ if not present.
    # The lookup is case-insensitive, dashes and underscores are equivalent.
    # @param name [String, Symbol] e.g. +'Content-Length'+, +:content_length+
    # @return [String, nil]
    def [](name)
      normalized = name.to_s.downcase
      @headers[normalized] || @headers[normalized.tr('_', '-')]
    end

    # The declared size of the request body, based on the +Content-Length+
    # header. Returns +nil+ when the header is missing or invalid.
    # @return [Integer, nil]
    def content_length
      if (value = @headers[CONTENT_LENGTH2]) && value.match?(/\A\d+\z/)
        value.to_i
      end
    end
  end
end
