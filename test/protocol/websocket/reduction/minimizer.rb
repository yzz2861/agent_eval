# frozen_string_literal: true

# Released under the MIT License.
# Copyright, 2026, by Samuel Williams.

require "tmpdir"
require "open3"

require "protocol/websocket/reduction"

require File.expand_path("../../../../fixtures/protocol/websocket/reduction/stale_fragment_offset", __dir__)

Reduction = Protocol::WebSocket::Reduction
Session = Reduction::Session
Minimizer = Reduction::Minimizer
Recording = Reduction::Recording

describe Reduction do
	def masked_frame(frame_class, finished, plain, mask: "abcd", flags: 0, opcode: nil)
		frame =
			if opcode
				frame_class.new(finished, flags: flags, opcode: opcode, mask: mask)
			else
				frame_class.new(finished, flags: flags, mask: mask)
			end
		
		frame.pack(plain)
		frame
	end
	
	def unmasked_frame(frame_class, finished, plain, flags: 0)
		frame = frame_class.new(finished, flags: flags)
		frame.pack(plain)
		frame
	end
	
	# A 40-frame session which needs ~36 frames of noise removal and a payload
	# trim before the stale-offset defect is isolated.
	let(:original) do
		frames = []
		
		# First text fragment: a short prefix is a required precondition. RSV1 is
		# set because permessage-deflate was negotiated.
		opener = Protocol::WebSocket::TextFrame.new(false, flags: Protocol::WebSocket::Frame::RSV1)
		opener.pack("REQ-")
		frames << opener
		
		# 36 unrelated, correctly-terminated control frames that merely pad the
		# trace. One carries an optional RSV2 bit that reduction can remove.
		36.times do |index|
			ping = Protocol::WebSocket::PingFrame.new(true)
			ping.flags = Protocol::WebSocket::Frame::RSV2 if index == 0
			ping.pack("x")
			frames << ping
		end
		
		# Final fragment carrying the marker inside junk bytes.
		continuation = Protocol::WebSocket::ContinuationFrame.new(true)
		continuation.pack("xxxxTRIGGERzzz")
		frames << continuation
		
		Session.new(
			role: :server,
			frames: frames,
			extensions: ["permessage-deflate"]
		)
	end
	
	with "the reproducible artificial defect" do
		it "reproduces on the original session" do
			expect do
				Reduction::BuggyEndpoint.replay(original)
			end.to raise_exception(Reduction::StaleFragmentOffset, message: be =~ /stale fragment offset/)
		end
		
		it "needs the short prefix fragment" do
			without_prefix = original.with(original.frames[1..])
			
			expect do
				Reduction::BuggyEndpoint.replay(without_prefix)
			end.to raise_exception(Protocol::WebSocket::ProtocolError, message: be =~ /unexpected continuation/i)
		end
		end
	
	it "removes frames first, then shrinks payload and optional fields" do
		result = Minimizer.reduce(original, Reduction::BuggyEndpoint.oracle)
		
		expect(result.status).to be == :reduced
		expect(result.session.frames.length).to be == 2
		
		opener, continuation = result.session.frames
		expect(opener).to be_a(Protocol::WebSocket::TextFrame)
		expect(opener.finished?).to be == false
		expect(Session.unmasked(opener)).to be == "REQ-"
		
		expect(continuation).to be_a(Protocol::WebSocket::ContinuationFrame)
		expect(continuation.finished?).to be == true
		# The four leading bytes position the marker at the stale offset, so they
		# survive; the trailing junk does not.
		expect(Session.unmasked(continuation)).to be == "xxxxTRIGGER"
		
		# The compression handshake owns RSV1, so it is never dropped.
		expect((opener.flags & Protocol::WebSocket::Frame::RSV1) != 0).to be == true
		expect((opener.flags & Protocol::WebSocket::Frame::RSV2)).to be == 0
	end
	
	it "preserves the mask direction for a client session" do
		frames = [
			masked_frame(Protocol::WebSocket::TextFrame, false, "REQ-", mask: "key!"),
			masked_frame(Protocol::WebSocket::ContinuationFrame, true, "xxxxTRIGGERzzz", mask: "key!"),
		]
		session = Session.new(role: :client, frames: frames)
		
		result = Minimizer.reduce(session, Reduction::BuggyEndpoint.oracle)
		
		expect(result.status).to be == :reduced
		expect(result.session.frames.length).to be == 2
		expect(Session.unmasked(result.session.frames.last)).to be == "xxxxTRIGGER"
		result.session.frames.each do |frame|
			expect(frame.mask).to be == "key!"
		end
	end
	
	with "oracle budget" do
		it "reports budget exhaustion without claiming success" do
			result = Minimizer.reduce(original, Reduction::BuggyEndpoint.oracle, budget: 4)
			
			expect(result.status).to be == :budget_exhausted
			expect(result.invocations).to be == 4
		end
		
		it "rejects a budget smaller than the stability confirmation runs" do
			expect do
				Minimizer.reduce(original, Reduction::BuggyEndpoint.oracle, budget: 1)
			end.to raise_exception(ArgumentError, message: be =~ /at least 2/)
		end
	end
	
	with "unstable results" do
		it "reports a flaky original instead of reducing" do
			session = Session.new(
				role: :server,
				frames: [
					unmasked_frame(Protocol::WebSocket::TextFrame, false, "REQ-"),
					unmasked_frame(Protocol::WebSocket::PingFrame, true, "p"),
					unmasked_frame(Protocol::WebSocket::ContinuationFrame, true, "xxxxTRIGGER"),
				]
			)
			calls = 0
			oracle = lambda do |candidate|
				calls += 1
				# The original (3 frames) is reproducible; anything smaller flips.
				if candidate.frames.length == session.frames.length
					"stale fragment offset at 4!"
				elsif calls.odd?
					nil
				else
					"stale fragment offset at 4!"
				end
			end
			
			result = Minimizer.reduce(session, oracle)
			
			expect(result.status).to be == :flaky
			expect(result.session.frames.length).to be == session.frames.length
		end
		
		it "reports a flaky original that cannot be confirmed" do
			# First confirmation run fails, the second passes: the original itself
			# is not reliably reproducible, so nothing may be claimed.
			calls = 0
			oracle = lambda do |_candidate|
				calls += 1
				calls == 1 ? "stale fragment offset at 4!" : nil
			end
			
			result = Minimizer.reduce(original, oracle, budget: 4)
			
			expect(result.status).to be == :flaky_original
			expect(result.invocations).to be == 2
			expect(result.session.frames.length).to be == original.frames.length
		end
	end
	
	with "a passing session" do
		it "reports that it does not fail" do
			oracle = lambda {|_session| nil}
			result = Minimizer.reduce(original, oracle)
			
			expect(result.status).to be == :does_not_fail
		end
	end
	
	with Session do
		it "rejects unmasked client frames" do
			frame = Protocol::WebSocket::TextFrame.new(true, "hi")
			session = Session.new(role: :client, frames: [frame])
			
			expect(session.structurally_valid?).to be == false
		end
		
		it "rejects masked server frames" do
			frame = masked_frame(Protocol::WebSocket::TextFrame, true, "hi")
			session = Session.new(role: :server, frames: [frame])
			
			expect(session.structurally_valid?).to be == false
		end
		
		it "rejects a dangling fragment" do
			session = Session.new(
				role: :server,
				frames: [unmasked_frame(Protocol::WebSocket::TextFrame, false, "abc")]
			)
			
			expect(session.structurally_valid?).to be == false
		end
		
		it "rejects a continuation without an opener" do
			session = Session.new(
				role: :server,
				frames: [unmasked_frame(Protocol::WebSocket::ContinuationFrame, true, "abc")]
			)
			
			expect(session.structurally_valid?).to be == false
		end
		
		it "rejects a reserved RSV bit that was not negotiated" do
			opener = Protocol::WebSocket::TextFrame.new(false, flags: Protocol::WebSocket::Frame::RSV1)
			opener.pack("abc")
			continuation = unmasked_frame(Protocol::WebSocket::ContinuationFrame, true, "d")
			session = Session.new(role: :server, frames: [opener, continuation])
			
			expect(session.structurally_valid?).to be == false
		end
		
		it "keeps the handshake immutable" do
			expect(original.extensions).to be == ["permessage-deflate"]
			Minimizer.reduce(original, Reduction::BuggyEndpoint.oracle)
			expect(original.extensions).to be == ["permessage-deflate"]
		end
	end
	
	with Recording do
		it "round-trips a masked session preserving wire bytes" do
			frames = [
				masked_frame(Protocol::WebSocket::TextFrame, false, "REQ-", flags: Protocol::WebSocket::Frame::RSV1),
				masked_frame(Protocol::WebSocket::ContinuationFrame, true, "TRIGGER"),
			]
			session = Session.new(role: :client, frames: frames, extensions: ["permessage-deflate"])
			
			decoded = Recording.load(Recording.dump(session))
			
			expect(decoded.role).to be == :client
			expect(Recording.to_wire(decoded)).to be == Recording.to_wire(session)
		end
		
		it "produces a recording that replays independently in a fresh process" do
			result = Minimizer.reduce(original, Reduction::BuggyEndpoint.oracle)
			expect(result.status).to be == :reduced
			
			Dir.mktmpdir do |directory|
				path = File.join(directory, "reduced-session.json")
				Recording.write(path, result.session)
				
				expect(File.read(path)).to be =~ /"role": "server"/
				
				replay = File.expand_path(
					"../../../../fixtures/protocol/websocket/reduction/replay_recording",
					__dir__
				)
				
				stdout, stderr, status = Open3.capture3("bundle", "exec", "ruby", replay, path)
				
				expect(status.exitstatus).to be == 0
				expect(stderr).to be =~ /REPRODUCED: Protocol::WebSocket::Reduction::StaleFragmentOffset/
				expect(stderr).to be =~ /frames=2/
				expect(stdout).to be == ""
			end
		end
	end
end
