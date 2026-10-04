# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

module Protocol
	module WebSocket
		# Tracks the progress and outcome of the closing handshake, including the close code and reason sent by the local end, the close code and reason received from the remote end, and the final result of the connection.
		class CloseState
			def initialize
				@local_code = nil
				@local_reason = nil
				
				@remote_code = nil
				@remote_reason = nil
				
				@result = nil
				@error = nil
			end
			
			# @attribute [Integer | Nil] The close code sent by the local end, if any.
			attr :local_code
			
			# @attribute [String | Nil] The close reason sent by the local end, if any.
			attr :local_reason
			
			# @attribute [Integer | Nil] The close code received from the remote end, if any.
			attr :remote_code
			
			# @attribute [String | Nil] The close reason received from the remote end, if any.
			attr :remote_reason
			
			# @attribute [Symbol | Nil] The final result of the connection: `:closed` if a close frame was received from the remote end, `:eof` if the connection was terminated without a close frame, `:timeout` if the closing handshake timed out, or `:error` if an error occurred during the closing handshake.
			attr :result
			
			# @attribute [Exception | Nil] The error that occurred during the closing handshake, if any.
			attr :error
			
			# Record a close frame sent by the local end.
			#
			# @parameter code [Integer | Nil] The close code that was sent.
			# @parameter reason [String | Nil] The close reason that was sent.
			def local_close(code, reason)
				@local_code = code
				@local_reason = reason
			end
			
			# Record a close frame received from the remote end.
			#
			# @parameter code [Integer | Nil] The close code that was received.
			# @parameter reason [String | Nil] The close reason that was received.
			def remote_close(code, reason)
				@remote_code = code
				@remote_reason = reason
			end
			
			# Record the final result of the connection. The first result recorded wins.
			#
			# @parameter result [Symbol] The final result of the connection.
			# @parameter error [Exception | Nil] The error that caused the connection to terminate, if any.
			def finish!(result, error = nil)
				@result ||= result
				@error ||= error
				
				return self
			end
			
			# @returns [Boolean] Whether the connection has finished closing.
			def finished?
				!@result.nil?
			end
		end
	end
end
