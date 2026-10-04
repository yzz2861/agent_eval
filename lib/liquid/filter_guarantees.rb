# frozen_string_literal: true

module Liquid
  # Mixin for filter modules to declare the output-safety guarantees of
  # their filters. Declarations are only consulted when rendering with an
  # explicit output mode (see Context#output_mode); in the default mode
  # they have no effect.
  #
  # A filter result keeps a safety marker only if the filter explicitly
  # declares that it produces or preserves the corresponding guarantee.
  # Undeclared filters (including plain concatenation such as +append+)
  # always return an unmarked value, even when their input was marked.
  #
  #   module MyFilters
  #     extend Liquid::FilterGuarantees
  #
  #     guarantees_output :escape, context: :html
  #     preserves_output_guarantees :upcase, contexts: [:html, :html_attribute]
  #   end
  module FilterGuarantees
    # Declares that the named filters always return output that is safe for
    # the given context, regardless of their input.
    def guarantees_output(*method_names, context:)
      method_names.each do |name|
        output_guarantee_declarations[name.to_s] = [:produce, context]
      end
    end

    # Declares that the named filters cannot introduce output that is unsafe
    # for a context their input was already safe for, so the input's
    # guarantee carries over to the result. Without +:contexts+, the
    # declaration applies to every guarantee.
    def preserves_output_guarantees(*method_names, contexts: SafeValue::OUTPUT_MODES)
      method_names.each do |name|
        output_guarantee_declarations[name.to_s] = [:preserve, contexts]
      end
    end

    def output_guarantee_declarations
      @output_guarantee_declarations ||= {}
    end
  end
end
