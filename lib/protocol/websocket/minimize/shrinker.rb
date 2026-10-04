# frozen_string_literal: true

require_relative "oracle"
require_relative "session"

module Protocol
	module WebSocket
		module Minimize
			# Reduces a captured session to a smaller one that still triggers the
			# same failure, according to the user-provided oracle.
			#
			# Reduction proceeds in three phases, in order of decreasing
			# structural impact:
			#
			# 1. Frame reduction (ddmin over the frame sequence). Pinned frames
			#    are never removed, and candidates that violate the structural
			#    rules (see {Session#valid?}) are rejected without spending
			#    oracle budget.
			# 2. Payload reduction (ddmin over the bytes of each remaining
			#    frame's payload).
			# 3. Optional field reduction (clearing RSV flag bits).
			#
			# The handshake configuration and the mask direction of each frame
			# are part of the session identity and are never modified.
			class Shrinker
				# The outcome of a shrink run.
				class Result
					def initialize(status:, session:, oracle:, log:)
						@status = status
						@session = session
						@oracle = oracle
						@log = log
					end
					
					# @attribute [Symbol] One of +:minimized+, +:unstable+,
					#   +:not_reproduced+, +:budget_exhausted+ or +:unverified+.
					attr :status
					
					# @attribute [Session] The smallest session found.
					attr :session
					
					# @attribute [Oracle] The oracle, including execution count.
					attr :oracle
					
					# @attribute [Array(String)] Human-readable progress log.
					attr :log
					
					# @returns [Boolean] Whether a stable, verified minimal result
					#   was produced.
					def minimized?
						@status == :minimized
					end
					
					# @returns [String] A one-line summary of the outcome.
					def summary
						"#{@status}: #{@session.size} frame(s), #{@session.payload_size} payload byte(s), #{@oracle.evaluations}/#{@oracle.limit} oracle evaluation(s)"
					end
				end
				
				# @parameter oracle [Oracle] The failure oracle.
				# @parameter verify_runs [Integer] Repetitions used to check
				#   oracle stability at the start and end of the run.
				def initialize(oracle, verify_runs: 3)
					@oracle = oracle
					@verify_runs = verify_runs
					@log = []
				end
				
				# Shrink the given session.
				#
				# @parameter session [Session] The captured session. It must
				#   reproduce the failure, otherwise the run aborts early.
				# @returns [Result]
				def call(session)
					# Confirm the original session actually and reliably
					# reproduces the failure before spending budget on shrinking:
					case @oracle.verify(session, runs: @verify_runs)
					when :unstable
						return result(:unstable, session)
					when :boring, :unknown
						return result(:not_reproduced, session)
					end
					
					current = session
					current = reduce_frames(current)
					current = reduce_payloads(current)
					current = reduce_flags(current)
					
					# Re-verify the final candidate. An unstable answer here is
					# reported, never announced as success:
					case @oracle.verify(current, runs: @verify_runs)
					when :interesting
						return result(:minimized, current)
					when :unstable
						return result(:unstable, current)
					else
						return result(@oracle.exhausted? ? :budget_exhausted : :unverified, current)
					end
				end
				
				private
				
				# A copy of +entries+ with the entry at +index+ replaced.
				def replace(entries, index, entry)
					copy = entries.dup
					copy[index] = entry
					return copy
				end
				
				def result(status, session)
					status = :budget_exhausted if status == :minimized && @oracle.exhausted?
					Result.new(status: status, session: session, oracle: @oracle, log: @log)
				end
				
				# Reserve enough budget for the final verification runs.
				def budget_low?
					@oracle.remaining <= @verify_runs
				end
				
				# Test a candidate session: structurally invalid candidates are
				# rejected for free; the oracle is only consulted within budget.
				def interesting?(session)
					return false unless session.valid?
					return false if budget_low?
					
					@oracle.interesting?(session)
				end
				
				# Classic delta-debugging: try removing chunks of decreasing
				# granularity until no chunk (down to a single item) can be
				# removed. Items are identified by index so duplicate values are
				# handled correctly.
				def ddmin(indices, &test)
					indices = indices.dup
					n = 2
					
					while indices.size >= 2 and !budget_low?
						chunk_size = (indices.size.to_f / n).ceil
						reduced = false
						
						indices.each_slice(chunk_size) do |chunk|
							candidate = indices - chunk
							
							if test.call(candidate)
								indices = candidate
								n = [n - 1, 2].max
								reduced = true
								break
							end
						end
						
						unless reduced
							break if n >= indices.size
							n = [n * 2, indices.size].min
						end
					end
					
					return indices
				end
				
				def reduce_frames(session)
					removable = session.entries.each_index.reject{|index| session.entries[index].pinned?}
					
					kept = ddmin(removable) do |candidate_indices|
						candidate = session.with_entries(
							session.entries.each_with_index.filter_map do |entry, index|
								entry if entry.pinned? or candidate_indices.include?(index)
							end
						)
						
						interesting?(candidate)
					end
					
					entries = session.entries.each_with_index.filter_map do |entry, index|
						entry if entry.pinned? or kept.include?(index)
					end
					
					if entries.size != session.size
						@log << "frames: #{session.size} -> #{entries.size}"
					end
					
					return session.with_entries(entries)
				end
				
				def reduce_payloads(session)
					entries = session.entries.dup
					
					entries.each_with_index do |entry, index|
						break if budget_low?
						next if entry.pinned? or entry.payload.empty?
						
						original = entry.payload
						
						# Try the empty payload first, it is the cheapest win:
if interesting?(session.with_entries(replace(entries, index, entry.with(payload: ""))))
							entry = entries[index] = entry.with(payload: "")
							@log << "payload[#{index}]: #{original.bytesize} -> 0 byte(s)"
							next
						end
						
						bytes = original.bytes
						
						kept = ddmin((0...bytes.size).to_a) do |candidate_indices|
							payload = candidate_indices.map{|byte_index| bytes[byte_index]}.pack("C*")
							candidate = session.with_entries(replace(entries, index, entry.with(payload: payload)))
							
							interesting?(candidate)
						end
						
						payload = kept.map{|byte_index| bytes[byte_index]}.pack("C*")
						
						if payload != original
							entry = entries[index] = entry.with(payload: payload)
							@log << "payload[#{index}]: #{original.bytesize} -> #{payload.bytesize} byte(s)"
						end
					end
					
					return session.with_entries(entries)
				end
				
				def reduce_flags(session)
					entries = session.entries.dup
					
					entries.each_with_index do |entry, index|
						break if budget_low?
						next if entry.pinned? or entry.flags.zero?
						
						# Try clearing all optional flag bits at once, then fall
						# back to clearing one bit at a time:
						cleared = entry.with(flags: 0)
						
if interesting?(session.with_entries(replace(entries, index, cleared)))
							@log << "flags[#{index}]: 0x#{entry.flags.to_s(16)} -> 0x0"
							entries[index] = cleared
						else
							flags = entry.flags
							
							[Frame::RSV1, Frame::RSV2, Frame::RSV3].each do |bit|
								next if (flags & bit).zero?
								
								candidate = entries[index].with(flags: flags & ~bit)
								
if interesting?(session.with_entries(replace(entries, index, candidate)))
									@log << "flags[#{index}]: 0x#{flags.to_s(16)} -> 0x#{(flags & ~bit).to_s(16)}"
									flags &= ~bit
									entries[index] = candidate
								end
							end
						end
					end
					
					return session.with_entries(entries)
				end
			end
		end
	end
end
