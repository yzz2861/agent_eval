module OneLogin
  module RubySaml
    class AuthnContextPolicy
      COMPARISONS = ["exact", "minimum", "maximum", "better"].freeze

      attr_reader :class_refs, :decl_refs, :comparison, :comparator, :actual_class_refs, :actual_decl_refs, :errors

      def initialize(class_refs, decl_refs, actual_refs, comparison = "exact", comparator = nil)
        @class_refs = normalize_refs(class_refs)
        @decl_refs = normalize_refs(decl_refs)
        if actual_refs.is_a?(Hash)
          @actual_class_refs = normalize_refs(actual_refs[:class_ref] || actual_refs["class_ref"])
          @actual_decl_refs = normalize_refs(actual_refs[:decl_ref] || actual_refs["decl_ref"])
        else
          @actual_class_refs = normalize_refs(actual_refs)
          @actual_decl_refs = []
        end
        @comparison = comparison.to_s
        @comparator = comparator
        @errors = []
      end

      def match?
        @errors = []

        unless COMPARISONS.include?(comparison)
          return add_error("Unsupported AuthnContext comparison: #{comparison}")
        end

        if class_refs.empty? && decl_refs.empty?
          return add_error("Requested AuthnContext is missing")
        end

        unless class_refs.empty? || decl_refs.empty?
          return add_error("Requested AuthnContext cannot contain both ClassRef and DeclRef")
        end

        actual_type = class_refs.empty? ? :decl_ref : :class_ref
        actual_candidates = actual_refs.select do |actual|
          actual[0] == actual_type
        end
        unless actual_candidates.size == 1
          ref_name = actual_type == :class_ref ? "AuthnContextClassRef" : "AuthnContextDeclRef"
          return add_error("Response AuthnContext must contain exactly one #{ref_name}")
        end

        actual_ref = actual_candidates.first[1]
        return compare_actual(actual_type, actual_ref) if comparison == "exact"

        unless comparator.respond_to?(:call) || comparator.is_a?(Hash)
          return add_error("AuthnContext comparator is required for #{comparison} comparison")
        end

        requested_candidates(actual_type).each do |requested_ref|
          relation = compare(requested_ref, actual_ref)
          next unless relation && satisfies?(relation)

          return true
        end

        false
      end

      private

      def actual_refs
        actual_class_refs.map { |ref| [:class_ref, ref] } + actual_decl_refs.map { |ref| [:decl_ref, ref] }
      end

      def requested_candidates(type)
        type == :class_ref ? class_refs : decl_refs
      end

      def compare_actual(actual_type, actual_ref)
        requested_candidates(actual_type).include?(actual_ref)
      end

      def compare(requested_ref, actual_ref)
        relation =
          if comparator.is_a?(Hash)
            compare_with_hash(requested_ref, actual_ref)
          else
            comparator.call(requested_ref, actual_ref)
          end

        return relation if relation.nil? || [-1, 0, 1].include?(relation)

        add_error("AuthnContext comparator returned an invalid relation: #{relation.inspect}")
        nil
      rescue StandardError
        add_error("AuthnContext comparator could not compare #{requested_ref.inspect} and #{actual_ref.inspect}")
        nil
      end

      def compare_with_hash(requested_ref, actual_ref)
        requested_level = comparator.fetch(requested_ref)
        actual_level = comparator.fetch(actual_ref)
        raise ArgumentError, "incomparable" if requested_level.nil? || actual_level.nil?

        relation = actual_level <=> requested_level
        raise ArgumentError, "incomparable" if relation.nil?
        relation
      end

      def satisfies?(relation)
        case comparison
        when "minimum"
          relation >= 0
        when "maximum"
          relation <= 0
        when "better"
          relation == 1
        end
      end

      def normalize_refs(refs)
        Array(refs).map { |ref| ref.to_s.strip }.reject { |ref| ref.empty? }
      end

      def add_error(message)
        errors << message unless errors.include?(message)
        false
      end
    end
  end
end
