# frozen_string_literal: true

require_relative "../framer"
require_relative "session"

require "stringio"

module Protocol
	module WebSocket
		module Minimize
			# Replays a session file against real endpoint objects, using the
			# actual {Framer} wire format. This is what makes a minimized
			# session independently reproducible: the JSON file alone is enough
			# to drive the failure again, with no shrinking machinery involved.
			module Replay
				# Replay a session, delivering each frame to the receiving
				# endpoint.
				#
				# Frames sent by the client are delivered to +server+, and
				# frames sent by the server are delivered to +client+. Each
				# endpoint is a {Connection}-like object: frames are delivered
				# via {Frame#apply}, exactly as {Connection#read_frame} does.
				#
				# Mask direction is derived from the handshake configuration and
				# each frame's sender role, exactly as on a real connection.
				#
				# @parameter session [Session] The session to replay.
				# @parameter client [Object | Nil] Handler for server-to-client frames.
				# @parameter server [Object | Nil] Handler for client-to-server frames.
				def self.call(session, client: nil, server: nil)
					receivers = {client: server, server: client}
					maximum_frame_size = session.handshake.maximum_frame_size || MAXIMUM_ALLOWED_FRAME_SIZE
					
					session.entries.each_with_index do |entry, index|
						frame = build_frame(session, entry, index)
						
						# Round-trip through the real wire format:
						io = StringIO.new
						Framer.new(io).write_frame(frame)
						io.rewind
						received = Framer.new(io).read_frame(maximum_frame_size)
						
						if receiver = receivers[entry.endpoint]
							received.apply(receiver)
						end
					end
				end
				
				# Reconstruct a concrete {Frame} from a session entry, applying
				# the mask direction mandated by the handshake configuration.
				#
				# @returns [Frame]
				def self.build_frame(session, entry, index)
					klass = FRAMES[entry.opcode] || Frame
					
					mask =
						if session.handshake.mask_for?(entry.endpoint)
							entry.mask || default_mask(index)
						else
							false
						end
					
					frame = klass.new(entry.finished, nil, flags: entry.flags, opcode: entry.opcode, mask: mask)
					frame.payload = mask ? apply_mask(entry.payload, mask) : entry.payload
					
					return frame
				end
				
				# A deterministic mask for frames that don't carry one from the
				# capture, so replay is fully reproducible.
				def self.default_mask(index)
					Digest::SHA256.digest("websocket-minimize-mask-#{index}")[0, 4]
				end
				
				def self.apply_mask(data, mask)
					result = String.new(encoding: Encoding::BINARY)
					
					data.bytes.each_with_index do |byte, index|
						result << (byte ^ mask.getbyte(index % 4))
					end
					
					return result
				end
			end
		end
	end
end
