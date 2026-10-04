# frozen_string_literal: true

require "protocol/websocket/connection"

require "stringio"

# A deliberately defective WebSocket server endpoint used to demonstrate the
# session minimizer. The defect is entirely artificial but deterministic:
#
# - Receiving a ping arms a latent "diagnostic" code path.
# - The next completed message is routed through that path, which crashes
#   if the reassembled message contains the substring "BOOM".
#   The crash raises {DefectTriggered}, which is how the oracle recognizes
#   *this specific* failure (and not, say, an unrelated protocol error).
#
# Triggering it therefore requires a *prefix* (the ping) followed by a
# specific *payload* ("BOOM"), possibly spread over several fragments --
# exactly the kind of multi-frame, stateful failure that is painful to
# reduce by hand.
class DefectiveServer < Protocol::WebSocket::Connection
	# Raised when the artificial defect fires.
	class DefectTriggered < StandardError
		def initialize
			super("ARTIFICIAL DEFECT: diagnostic path crashed on armed message")
		end
	end
	
	def initialize
		# The server is not connected to a real peer; replies are written to
		# an in-memory stream and ignored.
		super(Protocol::WebSocket::Framer.new(StringIO.new))
		
		@diagnostic_armed = false
	end
	
	def receive_ping(frame)
		# Artificial state leak: any ping arms the diagnostic path.
		@diagnostic_armed = true
	end
	
	def receive_text(frame)
		super
		
		process_message if frame.finished?
	end
	
	def receive_binary(frame)
		super
		
		process_message if frame.finished?
	end
	
	def receive_continuation(frame)
		super
		
		process_message if frame.finished?
	end
	
	private
	
	def process_message
		message = @frames.map{|frame| frame.unpack}.join
		@frames.clear
		
		if @diagnostic_armed and message.include?("BOOM")
			raise DefectTriggered
		end
		
		# Any completed message disarms the diagnostic path again:
		@diagnostic_armed = false
	end
end
