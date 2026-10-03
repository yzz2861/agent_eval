# frozen_string_literal: true

require_relative 'audit/transition_record'
require_relative 'audit/machine_definition'
require_relative 'audit/replay_error'
require_relative 'audit/replay_result'
require_relative 'audit/replay_validator'

module StateMachines
  # Audit provides pure, serializable state-history replay tooling.  None of
  # the classes under Audit execute machine actions or re-evaluate guards;
  # they only inspect declared transitions and chain continuity so that an
  # auditor can verify an imported log without the original runtime context.
  module Audit
  end
end
