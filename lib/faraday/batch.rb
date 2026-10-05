# frozen_string_literal: true

require 'securerandom'

module Faraday
  # Batch provides encode/decode support for wrapping several sub-requests
  # into one +multipart/mixed+ HTTP message and for correlating the returned
  # sub-responses by their +Content-ID+.
  #
  # Each part carries a complete HTTP request or response (+application/http,
  # RFC 9110), the method/relative target/headers/body of the sub-request and
  # a unique +Content-ID+. Sub-responses may arrive out of order: they are
  # matched back to the requests by +Content-ID+, and every requested ID is
  # always present in the result, even when no part was returned for it.
  #
  # Encoding and decoding are binary-safe: a body may contain any bytes,
  # including the multipart boundary delimiter.
  #
  # @example Encoding a batch
  #   parts = [
  #     Faraday::Batch::Part.new(method: :get, path: '/users/1'),
  #     Faraday::Batch::Part.new(method: :post, path: '/users',
  #                              body: '{"name":"Ada"}',
  #                              headers: { 'Content-Type' => 'application/json' })
  #   ]
  #   encoded = Faraday::Batch::Coder.encode_request(parts)
  #   # POST encoded.body with encoded.content_type to the batch endpoint.
  #
  # @example Decoding a batch response
  #   ids = parts.map(&:content_id)
  #   batch = Faraday::Batch::Coder.decode_response(body, content_type, ids)
  #   batch.results.all?(&:success?)
  module Batch
    MIME_TYPE = 'multipart/mixed'.freeze
    HTTP_MIME_TYPE = 'application/http'.freeze
    CONTENT_TYPE = 'Content-Type'.freeze
    CONTENT_ID = 'Content-ID'.freeze
    CONTENT_LENGTH = 'Content-Length'.freeze
    BOUNDARY_PREFIX = 'faraday-batch-'.freeze
    # RFC 2046 bcharsnospace minus tspecials and whitespace.
    BOUNDARY_VALUE = /\A[0-9a-zA-Z'()+_,.=-]+\z/.freeze
    DEFAULT_BOUNDARY_RETRIES = 5
    HTTP_VERSION = 'HTTP/1.1'.freeze
    CRLF = "\r\n".freeze
    CRLFCRLF = "\r\n\r\n".freeze
    DASHES = '--'.freeze

    # Reason phrases emitted by {Coder#encode_response}.
    HTTP_REASONS = {
      200 => 'OK',
      201 => 'Created',
      202 => 'Accepted',
      204 => 'No Content',
      301 => 'Moved Permanently',
      302 => 'Found',
      304 => 'Not Modified',
      400 => 'Bad Request',
      401 => 'Unauthorized',
      403 => 'Forbidden',
      404 => 'Not Found',
      407 => 'Proxy Authentication Required',
      408 => 'Request Timeout',
      409 => 'Conflict',
      422 => 'Unprocessable Content',
      429 => 'Too Many Requests',
      500 => 'Internal Server Error',
      502 => 'Bad Gateway',
      503 => 'Service Unavailable'
    }.freeze

    # Base error for all batch related failures.
    class Error < Faraday::Error; end

    # Raised when two or more parts share the same Content-ID, either while
    # encoding a request or decoding a response.
    class DuplicateContentIdError < Error; end

    # Raised when a part is missing a required attribute such as a method or
    # target.
    class InvalidPartError < Error; end

    # Raised when a batch message cannot be parsed: bad multipart structure,
    # invalid boundary, missing Content-ID or a malformed inner HTTP message.
    class MalformedBatchError < Error; end

    # Raised when an explicitly provided boundary is invalid or collides with
    # the encoded bodies.
    class BoundaryCollisionError < MalformedBatchError; end

    # Raised for a requested Content-ID that has no matching response part.
    class MissingPartError < Error; end

    # An encoded multipart/mixed message.
    #
    # @!attribute body
    #   @return [String] Binary multipart body.
    # @!attribute boundary
    #   @return [String] Multipart boundary used in the body.
    # @!attribute content_type
    #   @return [String] Value for the outer Content-Type header.
    # @!attribute content_ids
    #   @return [Array<String>] Content-IDs in part order.
    EncodedBatch = Struct.new(:body, :boundary, :content_type, :content_ids)

    # Sub-response status codes mapped to a specific Faraday error class.
    STATUS_ERRORS = {
      400 => Faraday::BadRequestError,
      401 => Faraday::UnauthorizedError,
      403 => Faraday::ForbiddenError,
      404 => Faraday::ResourceNotFound,
      407 => Faraday::ProxyAuthError,
      408 => Faraday::RequestTimeoutError,
      409 => Faraday::ConflictError,
      422 => Faraday::UnprocessableContentError,
      429 => Faraday::TooManyRequestsError
    }.freeze
  end
end

require 'faraday/batch/part'
require 'faraday/batch/part_result'
require 'faraday/batch/batch_result'
require 'faraday/batch/coder'
