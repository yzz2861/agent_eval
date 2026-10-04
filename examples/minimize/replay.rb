#!/usr/bin/env ruby
# frozen_string_literal: true

# Standalone replay proof: reproduce the defect from a session file alone,
# without any of the shrinking machinery (no oracle, no minimizer).
#
# Usage: replay.rb <session.json>

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)

require "protocol/websocket/minimize/session"
require "protocol/websocket/minimize/replay"

require_relative "defective_server"

path = ARGV.fetch(0)
session = Protocol::WebSocket::Minimize::Session.load_file(path)
server = DefectiveServer.new

begin
	Protocol::WebSocket::Minimize::Replay.call(session, server: server)
rescue DefectiveServer::DefectTriggered => error
	puts "DEFECT REPRODUCED by #{path}: #{error.message}"
	exit 0
end

puts "Not reproduced: #{path} ran without triggering the defect."
exit 1
