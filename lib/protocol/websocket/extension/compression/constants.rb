# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2022-2026, by Samuel Williams.

require "zlib"

require_relative "../../frame"

module Protocol
	module WebSocket
		module Extension
			module Compression
				NAME = "permessage-deflate"
				
				# Zlib is not capable of handling < 9 window bits.
				MINIMUM_WINDOW_BITS = 9
				
				# The maximum LZ77 window size allowed by the extension, in bits.
				MAXIMUM_WINDOW_BITS = 15
				
				# The reserved frame bit used to mark compressed frames.
				RESERVED_BITS = Frame::RSV1
			end
		end
	end
end
