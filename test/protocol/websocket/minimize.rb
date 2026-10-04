# frozen_string_literal: true

require "protocol/websocket/minimize"

require "tmpdir"

EXAMPLES = File.expand_path("../../../examples/minimize", __dir__)

describe Protocol::WebSocket::Minimize::Session do
	let(:handshake) {Protocol::WebSocket::Minimize::Session::Handshake.new}
	
	def entry(endpoint: :client, opcode: 1, payload: "data", **options)
		Protocol::WebSocket::Minimize::Session::Entry.new(
			endpoint: endpoint, opcode: opcode, payload: payload, **options
		)
	end
	
	it "round-trips through JSON with a stable digest" do
		session = Protocol::WebSocket::Minimize::Session.new(
			handshake: handshake,
			entries: [
				entry(opcode: 9, payload: "ping", flags: 4, mask: "mask", pinned: true),
				entry(endpoint: :server, opcode: 10, payload: "pong"),
			],
		)
		
		Dir.mktmpdir do |directory|
			path = File.join(directory, "session.json")
			session.save_file(path)
			loaded = Protocol::WebSocket::Minimize::Session.load_file(path)
			
			expect(loaded.digest).to be == session.digest
			expect(loaded.entries.first.mask).to be == "mask"
			expect(loaded.entries.first.pinned?).to be == true
			expect(loaded.entries.first.flags).to be == 4
		end
	end
	
	it "derives mask direction from the handshake configuration" do
		expect(handshake.mask_for?(:client)).to be == true
		expect(handshake.mask_for?(:server)).to be == false
	end
	
	with "#valid?" do
		it "accepts a complete fragmented message" do
			session = Protocol::WebSocket::Minimize::Session.new(entries: [
				entry(opcode: 1, finished: false),
				entry(opcode: 0, finished: true),
			])
			
			expect(session.valid?).to be == true
		end
		
		it "rejects a continuation without its prefix fragment" do
			session = Protocol::WebSocket::Minimize::Session.new(entries: [
				entry(opcode: 0, finished: true),
			])
			
			expect(session.valid?).to be == false
		end
		
		it "rejects interleaved data frames from the same endpoint" do
			session = Protocol::WebSocket::Minimize::Session.new(entries: [
				entry(opcode: 1, finished: false),
				entry(opcode: 2, finished: true),
			])
			
			expect(session.valid?).to be == false
		end
		
		it "allows independent fragmentation state per endpoint" do
			session = Protocol::WebSocket::Minimize::Session.new(entries: [
				entry(endpoint: :client, opcode: 1, finished: false),
				entry(endpoint: :server, opcode: 1, finished: true),
				entry(endpoint: :client, opcode: 0, finished: true),
			])
			
			expect(session.valid?).to be == true
		end
		
		it "rejects fragmented control frames" do
			session = Protocol::WebSocket::Minimize::Session.new(entries: [
				entry(opcode: 9, finished: false),
			])
			
			expect(session.valid?).to be == false
		end
	end
end

describe Protocol::WebSocket::Minimize::Oracle do
	let(:session) {Protocol::WebSocket::Minimize::Session.new}
	
	it "enforces the execution limit" do
		calls = 0
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 2) do |candidate|
			calls += 1
			true
		end
		
		3.times {oracle.interesting?(Protocol::WebSocket::Minimize::Session.new(entries: [Protocol::WebSocket::Minimize::Session::Entry.new(endpoint: :client, opcode: 1, payload: calls.to_s)]))}
		
		expect(calls).to be == 2
		expect(oracle.exhausted?).to be == true
		expect(oracle.interesting?(Protocol::WebSocket::Minimize::Session.new)).to be == false
	end
	
	it "caches results by session digest" do
		calls = 0
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 10) do |candidate|
			calls += 1
			true
		end
		
		2.times {oracle.interesting?(session)}
		
		expect(calls).to be == 1
	end
	
	it "detects unstable results during verification" do
		states = [true, false, true]
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 10) do |candidate|
			states.shift
		end
		
		expect(oracle.verify(session, runs: 3)).to be == :unstable
	end
	
	it "reports unknown when the budget is too small to verify" do
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 0) {|candidate| true}
		
		expect(oracle.verify(session, runs: 3)).to be == :unknown
	end
	
	it "supports external commands" do
		interesting = Protocol::WebSocket::Minimize::Oracle.command("true")
		boring = Protocol::WebSocket::Minimize::Oracle.command("false")
		
		expect(interesting.interesting?(session)).to be == true
		expect(boring.interesting?(session)).to be == false
	end
end

describe Protocol::WebSocket::Minimize::Shrinker do
	# A test endpoint with the same artificial defect as the example: a ping
	# arms a diagnostic path, and the next message containing "BOOM" crashes.
	let(:defect_oracle) do
		->(session) do
			armed = false
			message = +""
			
			session.entries.each do |entry|
				case entry.opcode
				when 9
					armed = true
				when 1, 2
					message = entry.payload.dup
					if entry.finished?
						return true if armed and message.include?("BOOM")
						armed = false
					end
				when 0
					message << entry.payload
					if entry.finished?
						return true if armed and message.include?("BOOM")
						armed = false
					end
				end
			end
			
			false
		end
	end
	
	def build_session(payload_padding: 20)
		entry = ->(endpoint, opcode, payload, **options) do
			Protocol::WebSocket::Minimize::Session::Entry.new(
				endpoint: endpoint, opcode: opcode, payload: payload, **options
			)
		end
		
		entries = [
			entry.call(:client, 1, "hello"),
			entry.call(:server, 1, "welcome"),
			entry.call(:client, 9, "keepalive"),
			entry.call(:server, 10, "keepalive"),
			entry.call(:server, 1, "part-1-", finished: false),
			entry.call(:server, 0, "part-2", finished: true),
			entry.call(:client, 9, "diagnostic", flags: Protocol::WebSocket::Frame::RSV1),
			entry.call(:server, 10, "diagnostic"),
			entry.call(:client, 1, "x" * payload_padding + "BO", finished: false),
			entry.call(:client, 0, "OM" + "y" * payload_padding, finished: true),
			entry.call(:server, 1, "received"),
		]
		
		Protocol::WebSocket::Minimize::Session.new(
			handshake: Protocol::WebSocket::Minimize::Session::Handshake.new(
				reserved: Protocol::WebSocket::Frame::RSV1,
			),
			entries: entries,
		)
	end
	
	it "reduces frames first, then payloads and optional fields" do
		session = build_session
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 500, &defect_oracle)
		
		result = Protocol::WebSocket::Minimize::Shrinker.new(oracle).call(session)
		
		expect(result.status).to be == :minimized
		
		entries = result.session.entries
		expect(entries.size).to be == 3
		
		# The necessary prefix (ping) and both fragments survive:
		expect(entries[0].opcode).to be == 9
		expect(entries[1].opcode).to be == 1
		expect(entries[1].finished).to be == false
		expect(entries[2].opcode).to be == 0
		
		# Payloads are minimized:
		expect(entries[0].payload).to be == ""
		expect(entries[1].payload).to be == "BO"
		expect(entries[2].payload).to be == "OM"
		
		# Optional flags are cleared:
		expect(entries[0].flags).to be == 0
		
		# The handshake configuration is untouched:
		expect(result.session.handshake.reserved).to be == Protocol::WebSocket::Frame::RSV1
		expect(result.session.handshake.client_mask).to be == true
	end
	
	it "never removes pinned frames" do
		session = build_session
		pinned = Protocol::WebSocket::Minimize::Session::Entry.new(
			endpoint: :server, opcode: 1, payload: "keep me", pinned: true,
		)
		session = session.with_entries([pinned] + session.entries)
		
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 500, &defect_oracle)
		result = Protocol::WebSocket::Minimize::Shrinker.new(oracle).call(session)
		
		expect(result.session.entries.first.payload).to be == "keep me"
		expect(result.session.size).to be == 4
	end
	
	it "never presents structurally invalid candidates to the oracle" do
		session = build_session
		seen = []
		
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 500) do |candidate|
			seen << candidate
			true
		end
		
		Protocol::WebSocket::Minimize::Shrinker.new(oracle).call(session)
		
		expect(seen).not.to be(:empty?)
		expect(seen.all?(&:valid?)).to be == true
	end
	
	it "stops when the oracle budget is exhausted" do
		session = build_session
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 10, &defect_oracle)
		
		result = Protocol::WebSocket::Minimize::Shrinker.new(oracle).call(session)
		
		expect(oracle.evaluations).to be <= 10
		expect(result.status).to be == :budget_exhausted
	end
	
	it "reports unstable oracles instead of announcing success" do
		session = build_session
		states = [true, false, true, false].cycle
		
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 500) do |candidate|
			states.next
		end
		
		result = Protocol::WebSocket::Minimize::Shrinker.new(oracle).call(session)
		
		expect(result.status).to be == :unstable
		expect(result.minimized?).to be == false
	end
	
	it "reports sessions that do not reproduce the failure" do
		session = build_session
		oracle = Protocol::WebSocket::Minimize::Oracle.new(limit: 500) {|candidate| false}
		
		result = Protocol::WebSocket::Minimize::Shrinker.new(oracle).call(session)
		
		expect(result.status).to be == :not_reproduced
	end
end

describe Protocol::WebSocket::Minimize::Replay do
	it "delivers frames to the receiving endpoint with the negotiated mask direction" do
		received = []
		
		endpoint = Class.new do
			define_method(:initialize) {|sink| @sink = sink}
			define_method(:method_missing) {|name, frame| @sink << frame}
			define_method(:respond_to_missing?) {|name, include_private| true}
		end
		
		server = endpoint.new(received)
		
		session = Protocol::WebSocket::Minimize::Session.new(
			entries: [
				Protocol::WebSocket::Minimize::Session::Entry.new(endpoint: :client, opcode: 1, payload: "from client"),
				Protocol::WebSocket::Minimize::Session::Entry.new(endpoint: :server, opcode: 1, payload: "from server"),
			],
		)
		
		Protocol::WebSocket::Minimize::Replay.call(session, client: server, server: server)
		
		expect(received.size).to be == 2
		
		# Client-to-server frames are masked, server-to-client frames are not:
		expect(received[0].mask).to be_a(String)
		expect(received[0].mask.bytesize).to be == 4
		expect(received[0].unpack).to be == "from client"
		
		expect(received[1].mask).to be == false
		expect(received[1].unpack).to be == "from server"
	end
end

# End-to-end: the artificial defect example proves that a minimized session
# file reproduces the failure on its own, in a separate Ruby process that
# only loads the replay tool (no oracle, no shrinker).
describe "examples/minimize" do
	def example_oracle
		Protocol::WebSocket::Minimize::Oracle.new(limit: 500) do |candidate|
			server = DefectiveServer.new
			
			begin
				Protocol::WebSocket::Minimize::Replay.call(candidate, server: server)
				false
			rescue DefectiveServer::DefectTriggered
				true
			end
		end
	end
	
	it "minimizes the captured session and replays the result independently" do
		require_relative "../../../examples/minimize/generate"
		require_relative "../../../examples/minimize/defective_server"
		
		session = ExampleSession.build
		result = Protocol::WebSocket::Minimize::Shrinker.new(example_oracle).call(session)
		
		expect(result.status).to be == :minimized
		expect(result.session.size).to be == 3
		
		Dir.mktmpdir do |directory|
			minimized = File.join(directory, "minimized.json")
			result.session.save_file(minimized)
			
			replay = File.join(EXAMPLES, "replay.rb")
			system("bundle", "exec", "ruby", replay, minimized, [:out, :err] => File::NULL) or
				raise "replay.rb failed for #{minimized}"
			
			expect($?.exitstatus).to be == 0
		end
	end
	
	it "oracle.rb recognizes the defect in the captured session" do
		require_relative "../../../examples/minimize/generate"
		
		Dir.mktmpdir do |directory|
			original = File.join(directory, "original.json")
			ExampleSession.build.save_file(original)
			
			oracle = File.join(EXAMPLES, "oracle.rb")
			system("bundle", "exec", "ruby", oracle, original, [:out, :err] => File::NULL)
			
			expect($?.exitstatus).to be == 0
		end
	end
end
