# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require_relative "session"

module Protocol
	module WebSocket
		module Reduction
			# The outcome of a reduction run.
			Result = Struct.new(:status, :session, :signature, :invocations, keyword_init: true) do
				# @returns [Boolean] whether a smaller, reliably-reproducing sample was
				# produced.
				def reduced?
					status == :reduced
				end
			end
			
			# Delta-debug a captured WebSocket session against a user-provided oracle.
			#
			# The oracle is any callable accepting a {Session} and returning:
			# - a truthy failure signature (String) when the same defect fires,
			# - `nil`/`false` when the candidate does not fail, or
			# - raising an exception, in which case its class and message form the
			#   signature. A signature change means a *different* failure and is never
			#   accepted.
			#
			# Reduction has two stages, matching RFC 6455 structure: frames are
			# removed first (delta debugging over frame units), then payload bytes and
			# optional (RSV) fields are shrunk. Handshake configuration, mask direction
			# and every prefix needed to keep the sequence valid are preserved.
			class Minimizer
				# Default maximum number of oracle invocations per run.
				DEFAULT_BUDGET = 500
				
				# How many identical outcomes must be observed before a verdict is
				# considered stable.
				STABLE_RUNS = 2
				
				# Inherits from Exception so it bypasses the oracle's StandardError
				# capture inside {#invoke}.
				class BudgetExhausted < Exception
				end
				
				# Convenience entry point; see {#initialize}.
				def self.reduce(session, oracle, budget: DEFAULT_BUDGET)
					new(session, oracle, budget: budget).call
				end
				
				# @parameter session [Session] the original failing session.
				# @parameter oracle [#call] the user-provided failure judge.
				# @parameter budget [Integer] maximum oracle invocations.
				def initialize(session, oracle, budget: DEFAULT_BUDGET)
					raise ArgumentError, "budget must be at least #{STABLE_RUNS}!" if budget < STABLE_RUNS
					
					@session = session
					@oracle = oracle
					@budget = budget
					@invocations = 0
					@saw_flaky = false
				end
				
				# @returns [Result] the reduction outcome.
				def call
					original_size = @session.wire_size
					
					begin
						target = evaluate(@session, initial: true)
						
						case target
						when nil
							return result(:does_not_fail)
						when :flaky
							return result(:flaky_original)
						end
						
						loop do
							before = state_key
							
							reduce_frames(target)
							reduce_fields(target)
							
							break if state_key == before
						end
					rescue BudgetExhausted
						return result(:budget_exhausted, target)
					end
					
					if @saw_flaky
						return result(:flaky, target)
					elsif @session.wire_size < original_size
						return result(:reduced, target)
					else
						return result(:not_reducible, target)
					end
				end
				
				private
				
				# Classic delta debugging (ddmin) over indexed units. The block maps a
				# list of surviving indices to acceptance; the method mutates and
				# returns the smallest stable surviving index list it finds.
				def ddmin(count)
					indices = (0 ... count).to_a
					n = 2
					
					while indices.length > 1
						size = (indices.length.to_f / n).ceil
						reduced = false
						
					# Try dropping each chunk in turn.
						(0 ... n).each do |start|
						kept = indices.each_with_index.reject do |_index, position|
							position >= start * size && position < (start + 1) * size
						end.map(&:first)
						
						if kept.length < indices.length && yield(kept)
								indices = kept
								n = 2
								reduced = true
								break
							end
						end
						
						# Try keeping each chunk in isolation.
						unless reduced
							(0 ... n).each do |start|
							kept = indices.each_with_index.select do |_index, position|
								position >= start * size && position < (start + 1) * size
							end.map(&:first)
							
							next if kept.empty?
								
								if kept.length < indices.length && yield(kept)
									indices = kept
									n = [n - 1, 2].max
									reduced = true
									break
								end
							end
						end
						
						break unless reduced || n < indices.length
						n = [n * 2, indices.length].min if !reduced && n < indices.length
					end
					
					return indices
				end
				
				def reduce_frames(target)
					frames = @session.frames
					indices = ddmin(frames.length) do |kept|
						try(@session.with(kept.map {|index| frames[index]}), target)
					end
					
					# A single surviving frame still allows trying the empty sequence.
					if indices.length == 1
						try(@session.with([]), target)
					end
				end
				
				# Shrink optional RSV bits, then payload bytes, for every frame.
				def reduce_fields(target)
					@session.frames.each_index do |index|
						frame = @session.frames[index]
						
						optional_rsv_bits(frame).each do |bit|
							next if (frame.flags & bit).zero?
							
							copy = copy_frame(frame)
							copy.flags &= ~bit
							candidate = @session.with(replace(@session.frames, index, copy))
							
							if try(candidate, target, shrink_required: false)
								frame = @session.frames[index]
							end
						end
						
						reduce_payload(frame, target)
					end
				end
				
				# RSV bits whose extension was negotiated are part of the handshake
				# configuration and must not be dropped; only un-negotiated bits are
				# optional.
				def optional_rsv_bits(frame)
					bits = [Frame::RSV2, Frame::RSV3]
					bits.unshift(Frame::RSV1) unless @session.extensions.include?(Session::COMPRESSION_EXTENSION)
					bits
				end
				
				# Delta-debug the unmasked payload bytes of one frame.
				def reduce_payload(frame, target)
					data = Session.unmasked(frame)
					return false if data.empty?
					
					# A close frame's 2-byte status code is a required prefix.
					prefix = frame.opcode == 0x8 ? 2 : 0
					head = data.byteslice(0, prefix).b
					body = data.byteslice(prefix, data.bytesize)
					return false if body.empty?
					
					bytes = body.bytes
					# Stage 0 of ddmin: try dropping the whole body in one shot.
					return true if try_payload(frame, head, bytes, [], target)
					
					positions = ddmin(bytes.length) do |kept|
						try_payload(frame, head, bytes, kept, target)
					end
					
					return positions.length < body.bytesize
				end
				
				def try_payload(frame, head, bytes, kept_indices, target)
					plain = head + bytes.values_at(*kept_indices).pack("C*")
					copy = repack(frame, plain)
					
					frames = @session.frames
					index = frames.index(frame)
					return false unless index
					
					return try(@session.with(replace(frames, index, copy)), target)
				end
				
				def replace(frames, index, frame)
					copy = frames.dup
					copy[index] = frame
					copy
				end
				
				def copy_frame(frame)
					frame.class.new(
						frame.finished,
						frame.payload,
						flags: frame.flags,
						opcode: frame.opcode,
						mask: frame.mask
					)
				end
				
				# Repack plain (unmasked) bytes onto a copy of the frame, re-applying
					# the frame's mask so the masking direction is preserved.
				def repack(frame, plain)
					copy = copy_frame(frame)
					Frame.instance_method(:pack).bind_call(copy, plain)
					copy
				end
				
				# Accept gate: candidate must be valid, produce the same stable
				# signature, and (by default) be strictly smaller.
				def try(candidate, target, shrink_required: true)
					return false unless candidate.structurally_valid?
					return false if shrink_required && candidate.wire_size >= @session.wire_size
					
					verdict = evaluate(candidate)
					return false unless verdict == target
					
					@session = candidate
					return true
				end
				
				# Invoke the oracle STABLE_RUNS times and classify the result.
				# The initial confirmation of the supplied session is always allowed
				# to complete so its stability can be judged; candidate evaluations
				# stop as soon as the budget is reached.
				# @returns [String, nil, :flaky]
				def evaluate(candidate, initial: false)
					signatures = Array.new(STABLE_RUNS) do |run|
						invoke(candidate, force: initial && run < STABLE_RUNS)
					end.uniq
					
					if signatures.length > 1
						@saw_flaky = true
						return :flaky
					end
					
					signatures.first
				end
				
				def invoke(candidate, force: false)
					raise BudgetExhausted if !force && @invocations >= @budget
					@invocations += 1
					
					outcome = @oracle.call(candidate)
					return nil if outcome.nil? || outcome == false
					
					return "returned:#{outcome}"
				rescue StandardError => error
					return "exception:#{error.class}:#{error.message}"
				end
				
				def state_key
					@session.frames.map(&:to_ary)
				end
				
				def result(status, signature = nil)
					signature = nil if signature == :flaky
					
					Result.new(
						status: status,
						session: @session,
						signature: signature,
						invocations: @invocations
					)
				end
			end
		end
	end
end
