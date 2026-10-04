# frozen_string_literal: true

require "protocol/websocket/minimize"

# Builds the captured session used by the example: a realistic ~25 frame
# exchange in which a 2-frame failure trigger is buried. Deterministic, so
# the whole example is reproducible.
module ExampleSession
	Entry = Protocol::WebSocket::Minimize::Session::Entry
	
	def self.build
		entries = []
		
		frame = ->(endpoint, opcode, payload, **options) do
			entries << Entry.new(endpoint: endpoint, opcode: opcode, payload: payload, **options)
		end
		
		# Ordinary application traffic (noise):
		frame.call(:client, 0x1, "hello server")
		frame.call(:server, 0x1, "welcome, client")
		
		3.times do |index|
			frame.call(:client, 0x9, "keepalive-#{index}")
			frame.call(:server, 0xA, "keepalive-#{index}")
		end
		
		frame.call(:client, 0x2, "binary-blob-" + "b" * 64)
		
		# A fragmented notice from the server (noise): the minimizer must drop
		# the whole chain, never a fragment in the middle.
		frame.call(:server, 0x1, "chunked-notice-part-1-", finished: false)
		frame.call(:server, 0x0, "chunked-notice-part-2-", finished: false)
		frame.call(:server, 0x0, "chunked-notice-part-3", finished: true)
		
		frame.call(:client, 0x1, "status: all green, nothing to see here")
		frame.call(:server, 0x1, "ack: status")
		
		# The trigger, part 1: a ping arms the defective diagnostic path. The
		# capture carries an RSV1 flag from the negotiated (fictional)
		# extension -- an optional field the minimizer can clear.
		frame.call(:client, 0x9, "diagnostic-probe", flags: Protocol::WebSocket::Frame::RSV1)
		frame.call(:server, 0xA, "diagnostic-probe")
		
		# The trigger, part 2: a fragmented text message whose reassembled
		# payload contains "BOOM", padded with 240 bytes of noise.
		frame.call(:client, 0x1, "x" * 120 + "BO", finished: false)
		frame.call(:client, 0x0, "OM" + "y" * 120, finished: true)
		
		# Trailing noise after the crash point:
		frame.call(:server, 0x1, "message received")
		
		2.times do |index|
			frame.call(:client, 0x9, "keepalive-late-#{index}")
			frame.call(:server, 0xA, "keepalive-late-#{index}")
		end
		
		frame.call(:client, 0x8, [1000].pack("n") + "done")
		frame.call(:server, 0x8, [1000].pack("n") + "done")
		
		Protocol::WebSocket::Minimize::Session.new(
			handshake: Protocol::WebSocket::Minimize::Session::Handshake.new(
				client_mask: true,
				server_mask: false,
				reserved: Protocol::WebSocket::Frame::RSV1,
				maximum_frame_size: 4096,
				extensions: ["x-diagnostic-extension"],
			),
			entries: entries,
		)
	end
end

if __FILE__ == $0
	path = ARGV[0] || File.join(__dir__, "session.json")
	ExampleSession.build.save_file(path)
	puts "Wrote #{ExampleSession.build.size} frame session to #{path}"
end

