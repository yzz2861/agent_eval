# frozen_string_literal: true

require 'base64'

module JWT
  module Streaming
    # Produces unpadded base64url output incrementally.
    #
    # Only the 0-2 byte remainder of the last 3-byte boundary is carried
    # between chunks, so chunk boundaries never change the encoded result and
    # the complete payload is never held in memory.
    class Base64urlEncoder
      def initialize
        @remainder = ''.b
      end

      # Encodes a raw chunk and returns the base64url part that is complete
      # (always a multiple of four characters without padding).
      def encode(chunk)
        data = @remainder + chunk.b
        boundary = (data.bytesize / 3) * 3
        if boundary.zero?
          @remainder = data
          return ''.b
        end

        @remainder = data.byteslice(boundary, data.bytesize - boundary)
        ::Base64.urlsafe_encode64(data.byteslice(0, boundary), padding: false)
      end

      # Flushes the final bytes as unpadded base64url.
      def finish
        ::Base64.urlsafe_encode64(@remainder, padding: false)
      ensure
        @remainder = ''.b
      end
    end
  end
end
