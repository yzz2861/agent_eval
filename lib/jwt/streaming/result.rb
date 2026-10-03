# frozen_string_literal: true

module JWT
  module Streaming
    # Outcome of {JWT::Streaming.sign}.
    class SignResult
      # @param header [Hash] the JWS header that was signed.
      # @param encoded_header [String] base64url encoded header.
      # @param signature [String] binary signature bytes.
      # @param stats [Stats] statistics of the body read.
      def initialize(header:, encoded_header:, signature:, stats:)
        @header = header
        @encoded_header = encoded_header
        @signature = signature
        @stats = stats
      end

      attr_reader :header, :encoded_header, :signature, :stats

      # The encoded (base64url unpadded) signature.
      def encoded_signature
        @encoded_signature ||= ::JWT::Base64.url_encode(signature)
      end

      # The compact detached JWS: `header..signature` with an empty payload segment.
      def jws
        @jws ||= [encoded_header, '', encoded_signature].join('.')
      end
    end

    # Outcome of {JWT::Streaming.verify} and {JWT::Streaming.verify!}.
    class VerifyResult
      def initialize(valid:, header:, stats:)
        @valid = valid
        @header = header
        @stats = stats
      end

      attr_reader :header, :stats

      def valid?
        @valid
      end
    end
  end
end
