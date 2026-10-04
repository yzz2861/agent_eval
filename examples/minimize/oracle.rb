#!/usr/bin/env ruby
# frozen_string_literal: true

# Failure predicate ("oracle") for the session minimizer.
#
# Usage: oracle.rb <session.json>
#
# Exit status 0 means the session triggers the defect (interesting);
# anything else means it does not.

$LOAD_PATH.unshift File.expand_path("../../lib", __dir__)

require "protocol/websocket/minimize/session"
require "protocol/websocket/minimize/replay"

require_relative "defective_server"

session = Protocol::WebSocket::Minimize::Session.load_file(ARGV.fetch(0))
server = DefectiveServer.new

begin
	Protocol::WebSocket::Minimize::Replay.call(session, server: server)
rescue DefectiveServer::DefectTriggered
	# The specific defect fired: this session is interesting.
	exit 0
end

exit 1
