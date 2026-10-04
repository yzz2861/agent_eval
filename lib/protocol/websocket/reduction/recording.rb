# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "json"
require "stringio"

require_relative "../framer"
require_relative "session"

module Protocol
	module WebSocket
		module Reduction
			# A portable JSON encoding of a {Session}.
			#
			# Payloads are stored exactly as they appear on the wire (masked for a
			# client), alongside the mask key, so a recording replays byte-for-byte
			# without re-deriving any state.
			module Recording
				FORMAT_VERSION = 1
				
			OPCODES = {
					0x0 => ContinuationFrame,
					0x1 => TextFrame,
					0x2 => BinaryFrame,
					0x8 => CloseFrame,
					0x9 => PingFrame,
					0xA => PongFrame,
			}.freeze
			
				def self.encode64(data)
					[data.to_s].pack("m0")
				end
				
				def self.decode64(data)
					data.to_s.unpack1("m0")
				end
				
				# @returns [String] JSON representation of the session.
				def self.dump(session)
					JSON.pretty_generate(
						version: FORMAT_VERSION,
						role: session.role.to_s,
						extensions: session.extensions,
						frames: session.frames.map do |frame|
							{
								"fin" => frame.finished?,
								"flags" => frame.flags,
								"opcode" => frame.opcode,
								"mask" => frame.mask ? encode64(frame.mask) : nil,
								"payload" => encode64(frame.payload.to_s),
							}
						end
					)
				end

				# @parameter json [String, Hash] JSON text or an already-parsed hash.
				# @returns [Session] the decoded session.
				def self.load(json)
					data = json.is_a?(String) ? JSON.parse(json) : json
					
					frames = data.fetch("frames").map do |entry|
						opcode = entry.fetch("opcode")
						klass = OPCODES.fetch(opcode, Frame)
						mask = entry["mask"] ? decode64(entry.fetch("mask")) : false
						payload = decode64(entry.fetch("payload"))
						
						klass.new(
							entry.fetch("fin"),
							payload,
							flags: entry.fetch("flags", 0),
							opcode: opcode,
							mask: mask
						)
					end
					
					Session.new(
						role: data.fetch("role").to_sym,
						frames: frames,
						extensions: data.fetch("extensions", [])
					)
				end
				
				# Serialize a session to raw RFC 6455 wire bytes using a {Framer}.
				# @returns [String] binary data.
				def self.to_wire(session)
					stream = StringIO.new
					framer = Framer.new(stream)
					
					session.frames.each do |frame|
						framer.write_frame(frame)
					end
					
					return stream.string
				end
				
				# Parse raw RFC 6455 wire bytes back into frame objects.
				# @returns [Array(Frame)]
				def self.from_wire(bytes)
					framer = Framer.new(StringIO.new(bytes))
					frames = []
					
					while (frame = framer.read_frame)
						frames << frame
					end
					
					return frames
				rescue EOFError
					return frames
				end
				
				def self.write(path, session)
					File.write(path, dump(session))
				end
				
				def self.read(path)
					load(File.read(path))
				end
			end
		end
	end
end
