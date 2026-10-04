# frozen_string_literal: true

require_relative "minimize/session"
require_relative "minimize/oracle"
require_relative "minimize/shrinker"
require_relative "minimize/replay"

module Protocol
	module WebSocket
		# Tools for reducing captured protocol sessions to a minimal
		# failure-triggering sample. See {Minimize::Shrinker}.
		module Minimize
		end
	end
end

