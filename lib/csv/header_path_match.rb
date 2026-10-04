# frozen_string_literal: true

class CSV
  # A \CSV::HeaderPathMatch represents the result of looking up columns
  # by a multi-row header path when more than one column matches.
  #
  # It is an \Array of two-element \Array entries
  # <tt>[column_index, field_value]</tt>, one for each matching column,
  # in column order; column identities are therefore retained even when
  # the full header paths are duplicated.
  #
  # Use #matches? to distinguish a multi-match result from an ordinary
  # \Array field value:
  #   row.field_path(["去年", "金额"]).class       # => CSV::HeaderPathMatch
  #   row.field_path(["去年", "金额"]).matches?    # => true
  class HeaderPathMatch < Array
    # Returns +true+ to indicate that more than one column matched;
    # +false+ otherwise.
    def matches?
      true
    end
  end
end
