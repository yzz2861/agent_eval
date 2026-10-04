# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

module Protocol
	module WebSocket
		# Tracks the progress and outcome of the WebSocket closing handshake.
		#
		# Records the close code and reason sent by the local end, the close code and
		# reason received from the remote end (if any), and the final cause which
		# terminated the connection.
		class CloseResult
			# The remote end responded with a close frame.
			REMOTE_CLOSE = :remote_close
			
			# The underlying connection reached EOF before the remote end sent a close frame.
			EOF = :eof
			
			# The local close frame could not be sent.
			SEND_ERROR = :send_error
			
			# The remote end did not respond with a close frame within the allotted time.
			TIMEOUT = :timeout
			
			def initialize
				@local_code = nil
				@local_reason = nil
				@local_close = false
				
				@remote_code = nil
				@remote_reason = nil
				@remote_close = false
				
				@cause = nil
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
			
			# @attribute [Symbol | Nil] The cause which terminated the connection: `:remote_close`, `:eof`, `:send_error` or `:timeout`. Nil while the closing handshake is still in progress.
			attr :cause
			
			# @attribute [Exception | Nil] The error which occurred while sending the close frame, if any.
			attr :error
			
			# Record the close frame sent by the local end.
			#
			# @parameter code [Integer] The close code that was sent.
			# @parameter reason [String] The close reason that was sent.
			def local_close!(code, reason)
				@local_code = code
				@local_reason = reason
				@local_close = true
				
				return self
			end
			
			# @returns [Boolean] Whether the local end has sent a close frame.
			def local_close?
				@local_close
			end
			
			# Record the close frame received from the remote end.
			#
			# @parameter code [Integer | Nil] The close code that was received.
			# @parameter reason [String | Nil] The close reason that was received.
			def remote_close!(code, reason)
				@remote_code = code
				@remote_reason = reason
				@remote_close = true
				
				@cause ||= REMOTE_CLOSE
					
				return self
			end
			
			# @returns [Boolean] Whether the remote end responded with a close frame.
			def remote_close?
				@remote_close
			end
			
			# Mark the closing handshake as finished with the given cause. The first cause recorded takes precedence.
			#
			# @parameter cause [Symbol] The cause which terminated the connection.
			# @parameter error [Exception | Nil] The error associated with the cause, if any.
			def finish!(cause, error = nil)
				@cause ||= cause
				@error ||= error
				
				return self
			end
			
			# @returns [Boolean] Whether the closing handshake has finished.
			def finished?
				!@cause.nil?
			end
		end
	end
end
