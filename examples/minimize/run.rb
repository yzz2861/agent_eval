#!/usr/bin/env ruby
# frozen_string_literal: true

# End-to-end driver for the session minimizer example.
#
# Usage: run.rb [original.json] [minimized.json]
#
# Builds the captured session (see generate.rb), shrinks it using the
# external failure predicate (oracle.rb), and writes the minimized session.
# The result can be replayed independently with replay.rb.

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)

require "protocol/websocket/minimize"

require_relative "generate"

original_path = ARGV[0] || File.join(__dir__, "session.json")
minimized_path = ARGV[1] || File.join(__dir__, "minimized.json")
limit = (ENV["LIMIT"] || 500).to_i

session = ExampleSession.build
session.save_file(original_path)
puts "Captured session: #{session.size} frames, #{session.payload_size} payload bytes -> #{original_path}"

oracle = Protocol::WebSocket::Minimize::Oracle.command(
	["ruby", File.expand_path("oracle.rb", __dir__)],
	limit: limit,
)

result = Protocol::WebSocket::Minimize::Shrinker.new(oracle).call(session)

result.log.each{|line| puts "  #{line}"}

result.session.save_file(minimized_path)

puts "Result: #{result.summary}"
puts "Minimized session written to #{minimized_path}"
puts "Replay it independently with: ruby #{File.expand_path("replay.rb", __dir__)} #{minimized_path}"

exit(result.minimized? ? 0 : 1)

