# Incremental parsing support for parslet.
#
# Parslet::Incremental keeps a persistent packrat memo table across parses
# so that a stateful {Parslet::Incremental::Session} can reparse a document
# after a small interval edit (insertion, deletion or replacement) while
# reusing all parse results that the edit could not have influenced.
#
# Reuse is not decided by the span of successful matches alone: every memo
# entry records the full extent of input it *observed* while being computed,
# including lookahead, failed alternative branches and end-of-input checks.
# An entry is only reused when the edit is provably outside everything the
# entry observed, so incremental results are identical to a full reparse of
# the new text, down to failure positions.
#
# Usage:
#
#   session = Parslet::Incremental::Session.new(parser, text)
#   tree = session.parse
#   session.edit(10, 15, 'replacement')  # replace chars 10...15
#   tree = session.parse                 # reuses unaffected results
#   session.stats                        # => { hits:, misses:, ... }
#
module Parslet
  module Incremental
    # Replaces all slices contained in a cached parse value with equivalent
    # slices that point into +source+ (the current text), adding
    # +byte_shift+ to their positions. Cached values must never leak slices
    # that still reference a previous generation of the text.
    #
    def self.rebase_value(value, source, byte_shift)
      case value
      when Parslet::Slice
        source.rebase_slice(value, byte_shift)
      when Array
        value.map { |element| rebase_value(element, source, byte_shift) }
      when Hash
        value.each_with_object({}) do |(key, element), hash|
          hash[key] = rebase_value(element, source, byte_shift)
        end
      else
        value
      end
    end
  end
end

require 'parslet/incremental/tracker'
require 'parslet/incremental/entry'
require 'parslet/incremental/tracking_source'
require 'parslet/incremental/context'
require 'parslet/incremental/session'
