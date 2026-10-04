# frozen_string_literal: true

require "fileutils"
require "shellwords"
require "tmpdir"

require_relative "session"

module Protocol
	module WebSocket
		module Minimize
			# Wraps the user-provided failure predicate ("oracle") with:
			#
			# - A hard limit on the number of executions.
			# - Result caching keyed by session content digest.
			# - Stability verification: repeated evaluation of the same session
			#   to detect flaky (unstable) oracles, which are reported rather
			#   than silently treated as success.
			#
			# The oracle answers one question: "does this session still trigger
			# the failure?" (+true+ = interesting, keep shrinking).
			class Oracle
				# @parameter limit [Integer] The maximum number of oracle executions.
				# @parameter callable [Proc] The failure predicate, called with a {Session}.
				def initialize(limit: 100, &callable)
					@limit = limit
					@callable = callable
					@evaluations = 0
					@cache = {}
				end
				
				# @attribute [Integer] The maximum number of oracle executions.
				attr :limit
				
				# @attribute [Integer] The number of oracle executions so far.
				attr :evaluations
				
				# @returns [Integer] The number of executions still available.
				def remaining
					@limit - @evaluations
				end
				
				# @returns [Boolean] Whether the execution limit has been reached.
				def exhausted?
					remaining <= 0
				end
				
				# Evaluate the oracle for a session, using the cache when possible.
				# Returns +false+ without calling the oracle when the budget is
				# exhausted, so the shrinker can wind down gracefully.
				#
				# @parameter session [Session]
				# @returns [Boolean] Whether the session triggers the failure.
				def interesting?(session)
					digest = session.digest
					
					if @cache.key?(digest)
						return @cache[digest]
					end
					
					return false if exhausted?
					
					@cache[digest] = evaluate(session)
				end
				
				# Evaluate the same session multiple times (bypassing the cache)
				# to determine whether the oracle gives a stable answer.
				#
				# @parameter session [Session]
				# @parameter runs [Integer] The number of repetitions.
				# @returns [Symbol] +:interesting+, +:boring+, +:unstable+, or
				#   +:unknown+ (insufficient budget to verify).
				def verify(session, runs: 3)
					results = []
					
					runs.times do
						break if exhausted?
						results << evaluate(session)
					end
					
					if results.empty?
						:unknown
					elsif results.all?
						:interesting
					elsif results.none?
						:boring
					else
						:unstable
					end
				end
				
				# Build an oracle that invokes an external command. The command
				# receives the path of a temporary session file; exit status 0
				# means the failure was reproduced (interesting).
				#
				# @parameter command [String | Array(String)] The oracle command.
				#   If a string contains +%{path}+, it is substituted with the
				#   session file path; otherwise the path is appended.
				# @parameter limit [Integer] The maximum number of oracle executions.
				# @parameter directory [String] Where to write candidate sessions.
				# @returns [Oracle]
				def self.command(command, limit: 100, directory: Dir.mktmpdir("websocket-minimize"))
					FileUtils.mkdir_p(directory)
					
					self.new(limit: limit) do |session|
						path = File.join(directory, "candidate-#{session.digest[0, 16]}.json")
						session.save_file(path)
						
						result =
							case command
							when String
								argv =
									if command.include?("%{path}")
										command % {path: path}
									else
										"#{command} #{Shellwords.escape(path)}"
									end
								
								system(argv, out: File::NULL, err: File::NULL)
							else
								system(*command, path, out: File::NULL, err: File::NULL)
							end
						
						result ? true : false
					end
				end
				
				private
				
				def evaluate(session)
					@evaluations += 1
					!!@callable.call(session)
				end
			end
		end
	end
end
