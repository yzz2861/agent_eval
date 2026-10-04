# frozen_string_literal: true

require "digest"
require "json"

module Protocol
	module WebSocket
		module Minimize
			# An immutable, serializable description of a captured protocol session:
			# the negotiated handshake configuration plus an ordered sequence of
			# frames, each annotated with the role of the endpoint that sent it.
			#
			# The session file is the unit of exchange between the shrinker, the
			# user-provided failure oracle, and the standalone replay tool.
			class Session
				# The negotiated connection configuration. These values are part of
				# the test setup and are never modified by the shrinker.
				class Handshake
					DEFAULTS = {
						client_mask: true,
						server_mask: false,
						reserved: 0,
						maximum_frame_size: nil,
						extensions: [],
					}.freeze
					
					def initialize(client_mask: true, server_mask: false, reserved: 0, maximum_frame_size: nil, extensions: [])
						@client_mask = client_mask
						@server_mask = server_mask
						@reserved = reserved
						@maximum_frame_size = maximum_frame_size
						@extensions = extensions
					end
					
					# @attribute [Boolean] Whether client-to-server frames are masked.
					attr :client_mask
					
					# @attribute [Boolean] Whether server-to-client frames are masked.
					attr :server_mask
					
					# @attribute [Integer] Reserved (RSV) flag bits negotiated by extensions.
					attr :reserved
					
					# @attribute [Integer | Nil] The maximum acceptable frame size.
					attr :maximum_frame_size
					
					# @attribute [Array(String)] Negotiated extension names (informational).
					attr :extensions
					
					# Should frames sent by the given endpoint be masked on the wire?
					#
					# @parameter endpoint [Symbol] Either +:client+ or +:server+.
					# @returns [Boolean]
					def mask_for?(endpoint)
						endpoint == :client ? @client_mask : @server_mask
					end
					
					def self.from_h(hash)
						hash = hash.transform_keys(&:to_sym)
						new(**DEFAULTS.merge(hash))
					end
					
					def to_h
						{
							client_mask: @client_mask,
							server_mask: @server_mask,
							reserved: @reserved,
							maximum_frame_size: @maximum_frame_size,
							extensions: @extensions,
						}
					end
				end
				
				# A single captured frame and the role of the endpoint that sent it.
				class Entry
					def initialize(endpoint:, opcode:, payload:, finished: true, flags: 0, mask: nil, pinned: false)
						@endpoint = endpoint.to_sym
						@opcode = opcode
						@payload = payload
						@finished = finished
						@flags = flags
						@mask = mask
						@pinned = pinned
					end
					
					# @attribute [Symbol] The role of the sender, +:client+ or +:server+.
					attr :endpoint
					
					# @attribute [Integer] The frame opcode.
					attr :opcode
					
					# @attribute [String] The cleartext (unmasked) payload.
					attr :payload
					
					# @attribute [Boolean] Whether the FIN bit is set.
					attr :finished
					
					# @attribute [Integer] The RSV flag bits.
					attr :flags
					
					# @attribute [String | Nil] The explicit 4-byte mask from the capture, if any.
					attr :mask
					
					# @attribute [Boolean] Whether the shrinker is forbidden from removing or modifying this frame.
					attr :pinned
					
					def pinned?
						@pinned
					end
					
					# @returns [Boolean] Whether the FIN bit is set.
					def finished?
						@finished
					end
					
					# @returns [Boolean] Whether this is a control frame.
					def control?
						@opcode & 0x8 != 0
					end
					
					# @returns [Boolean] Whether this is a continuation fragment.
					def continuation?
						@opcode.zero?
					end
					
					# A copy of this entry with the given fields changed.
					def with(**changes)
						Entry.new(
							endpoint: changes.fetch(:endpoint, @endpoint),
							opcode: changes.fetch(:opcode, @opcode),
							payload: changes.fetch(:payload, @payload),
							finished: changes.fetch(:finished, @finished),
							flags: changes.fetch(:flags, @flags),
							mask: changes.fetch(:mask, @mask),
							pinned: changes.fetch(:pinned, @pinned),
						)
					end
					
					def self.from_h(hash)
						new(
							endpoint: hash.fetch("endpoint"),
							opcode: hash.fetch("opcode"),
							payload: [hash.fetch("payload", "")].pack("H*"),
							finished: hash.fetch("finished", true),
							flags: hash.fetch("flags", 0),
							mask: hash["mask"] && [hash["mask"]].pack("H*"),
							pinned: hash.fetch("pinned", false),
						)
					end
					
					def to_h
						result = {
							"endpoint" => @endpoint.to_s,
							"opcode" => @opcode,
							"finished" => @finished,
							"flags" => @flags,
							"payload" => @payload.unpack1("H*"),
						}
						
						result["mask"] = @mask.unpack1("H*") if @mask
						result["pinned"] = true if @pinned
						
						return result
					end
				end
				
				def initialize(handshake: Handshake.new, entries: [])
					@handshake = handshake
					@entries = entries.freeze
				end
				
				# @attribute [Handshake] The negotiated handshake configuration.
				attr :handshake
				
				# @attribute [Array(Entry)] The ordered frames of the session.
				attr :entries
				
				# @returns [Integer] The number of frames in the session.
				def size
					@entries.size
				end
				
				# @returns [Integer] The total cleartext payload size in bytes.
				def payload_size
					@entries.sum{|entry| entry.payload.bytesize}
				end
				
				# A copy of this session with different entries.
				def with_entries(entries)
					Session.new(handshake: @handshake, entries: entries)
				end
				
				# A stable content digest, used to cache oracle results.
				#
				# @returns [String]
				def digest
					Digest::SHA256.hexdigest(JSON.generate(to_h))
				end
				
				# Structural validity of the frame sequence. The shrinker never
				# produces candidates that violate these rules, regardless of what
				# the oracle would say:
				#
				# - A continuation fragment requires an open fragmented message
				#   from the same endpoint (necessary prefix fragments cannot be
				#   dropped).
				# - A new data frame cannot start while a fragmented message from
				#   the same endpoint is still open.
				# - Control frames must be finished and at most 125 bytes.
				#
				# @returns [Boolean]
				def valid?
					open = {client: false, server: false}
					
					@entries.each do |entry|
						if entry.control?
							return false unless entry.finished
							return false if entry.payload.bytesize > 125
						elsif entry.continuation?
							return false unless open[entry.endpoint]
							open[entry.endpoint] = false if entry.finished
						else
							return false if open[entry.endpoint]
							open[entry.endpoint] = true unless entry.finished
						end
					end
					
					return true
				end
				
				def self.from_h(hash)
					new(
						handshake: Handshake.from_h(hash.fetch("handshake", {})),
						entries: hash.fetch("frames", []).map{|entry| Entry.from_h(entry)},
					)
				end
				
				def to_h
					{
						"handshake" => JSON.parse(JSON.generate(@handshake.to_h)),
						"frames" => @entries.map(&:to_h),
					}
				end
				
				# Load a session from a JSON file.
				#
				# @parameter path [String]
				# @returns [Session]
				def self.load_file(path)
					from_h(JSON.parse(File.read(path)))
				end
				
				# Write the session to a JSON file.
				def save_file(path)
					File.write(path, JSON.pretty_generate(to_h) + "\n")
				end
			end
		end
	end
end
