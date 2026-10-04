# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "protocol/websocket/error"

# A deliberately buggy WebSocket endpoint, used to demonstrate and verify the
# session reducer.
#
# The endpoint reassembles fragmented text messages. It contains a stale-offset
# defect: while processing a continuation, it indexes the continuation bytes
# using an offset derived from the required opener prefix "REQ-" (a value left
# over from an earlier parsing stage). The marker "TRIGGER" therefore only
# fires when:
#
#   * the opener fragment is exactly "REQ-", and
#   * the continuation begins with exactly 4 noise bytes before the marker, so
#     the stale offset lands on "TRIGGER".
#
# Dropping the opener, changing its bytes, or removing the leading noise bytes
# all make the defect disappear or raise a different error. This models a real
# maintenance-test failure needing a precise ordered prefix plus payload bytes.
module Protocol
	module WebSocket
		module Reduction
			class StaleFragmentOffset < StandardError
			end
			
			class BuggyEndpoint
				PREFIX = "REQ-"
				MARKER = "TRIGGER"
				
				# RFC 6455 masking direction for a *received* session: a client session
				# must have been masked; a server session must not be.
				def self.verify_masking!(session)
					session.frames.each do |frame|
						if session.role == :client
							unless frame.mask.is_a?(String) && frame.mask.bytesize == 4
								raise Protocol::WebSocket::ProtocolError, "client frame is not masked!"
							end
						elsif frame.mask
							raise Protocol::WebSocket::ProtocolError, "server frame must not be masked!"
						end
					end
				end
				
				# Run the session through the buggy reassembler.
				# @raises [StaleFragmentOffset] when the defect fires.
				def self.replay(session)
					verify_masking!(session)
					
					buffer = nil
					
					session.frames.each do |frame|
						next if frame.control?
						
						payload = Session.unmasked(frame)
						
						if frame.opcode == 0x1
							buffer = payload.b
						elsif frame.opcode == 0x2
							buffer = nil
						elsif frame.opcode == 0x0
							# A continuation without an opener is a protocol error, so
							# the opener fragment is a required prefix and cannot be dropped.
							raise Protocol::WebSocket::ProtocolError, "Received unexpected continuation!" if buffer.nil?
							
							# BUG: the continuation is indexed at a stale offset carried
							# over from the opener prefix length.
							offset = buffer == PREFIX ? PREFIX.bytesize : 0
							if payload.byteslice(offset, MARKER.bytesize) == MARKER
								raise StaleFragmentOffset, "stale fragment offset at #{offset}!"
							end
							
							buffer << payload
						end
						
						if frame.finished?
							buffer = nil
						end
					end
					
					return true
				end
				
				# Oracle suitable for {Minimizer}: returns a stable signature string
				# on the defect, nil otherwise.
				def self.oracle
					lambda do |session|
						replay(session)
						nil
					rescue StaleFragmentOffset => error
						error.message
					end
				end
			end
		end
	end
end
