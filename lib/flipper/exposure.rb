require 'flipper/exposure/event'
require 'flipper/exposure/decision'
require 'flipper/exposure/collectors/memory'

module Flipper
  # Public: Explicit exposure credentials.
  #
  # Evaluating a feature may happen ahead of its actual use (e.g. a server
  # pre-reads several features for a request but the page only ends up using
  # one of them). To keep exposure attribution honest, evaluation returns a
  # confirmable Decision instead of recording anything. Only when the caller
  # confirms the decision was actually used is an exposure Event submitted to
  # the configured collector.
  module Exposure
  end
end
