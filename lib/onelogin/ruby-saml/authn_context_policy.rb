module OneLogin
  module RubySaml
    class AuthnContextPolicy
      COMPARISONS = ["exact", "minimum", "maximum", "better"].freeze

      attr_reader :requested_contexts
      attr_reader :actual_context
      attr_reader :comparison
      attr_reader :comparator
      attr_reader :error

      def initialize(requested_contexts, actual_context, comparison = "exact", comparator = nil, &block)
        @requested_contexts = Array(requested_contexts)
        @actual_context = actual_context
        @comparison = comparison.to_s
        @comparator = block || comparator
      end

      def match?
        return invalid("Requested AuthnContext must contain at least one context") if requested_contexts.empty?
        return invalid("Unsupported AuthnContext comparison: #{comparison}") unless COMPARISONS.include?(comparison)
        return invalid("Response must contain exactly one AuthnContext reference") unless actual_context.is_a?(Array) && actual_context.size == 1

        actual_ref = actual_context.first
        return invalid("Response must contain a non-empty AuthnContext reference") unless valid_ref?(actual_ref)

        case comparison
        when "exact"
          unless requested_contexts.any? { |requested_ref| equal_context?(actual_ref, requested_ref) }
            return invalid("Response AuthnContext does not exactly match a requested AuthnContext")
          end
        when "minimum"
          unless requested_contexts.any? { |requested_ref| satisfies_minimum?(actual_ref, requested_ref) }
            return invalid("Response AuthnContext is weaker than the minimum requested AuthnContext")
          end
        when "maximum"
          unless requested_contexts.any? { |requested_ref| satisfies_maximum?(actual_ref, requested_ref) }
            return invalid("Response AuthnContext is stronger than the maximum requested AuthnContext")
          end
        when "better"
          unless requested_contexts.all? { |requested_ref| better_than?(actual_ref, requested_ref) }
            return invalid("Response AuthnContext is not better than all requested AuthnContexts")
          end
        end

        @error = nil
        true
      end

      private

      def invalid(message)
        @error = message
        false
      end

      def valid_ref?(ref)
        ref.is_a?(Array) &&
          ref.size == 2 &&
          ["class", "decl"].include?(ref.first) &&
          ref.last.is_a?(String) &&
          !ref.last.strip.empty?
      end

      def equal_context?(actual_ref, requested_ref)
        return false unless valid_ref?(requested_ref)
        actual_ref.first == requested_ref.first && actual_ref.last == requested_ref.last
      end

      def compare_contexts(actual_ref, requested_ref)
        return nil unless valid_ref?(requested_ref)
        return nil unless actual_ref.first == requested_ref.first
        return nil unless comparator.respond_to?(:call)

        result = comparator.call(actual_ref.last, requested_ref.last)
        return nil unless [-1, 0, 1].include?(result)
        result
      end

      def satisfies_minimum?(actual_ref, requested_ref)
        comparison_result = compare_contexts(actual_ref, requested_ref)
        comparison_result == 0 || comparison_result == 1
      end

      def satisfies_maximum?(actual_ref, requested_ref)
        comparison_result = compare_contexts(actual_ref, requested_ref)
        comparison_result == -1 || comparison_result == 0
      end

      def better_than?(actual_ref, requested_ref)
        compare_contexts(actual_ref, requested_ref) == 1
      end
    end
  end
end
