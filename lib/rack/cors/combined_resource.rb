# frozen_string_literal: true

module Rack
  class Cors
    # Effective resource produced by intersecting every Resource that matches
    # a request when the middleware is configured with <tt>combine:
    # :intersection</tt>. All combination helpers here are order independent.
    class CombinedResource < Resource
      attr_reader :matched_resources

      def initialize(resources)
        @matched_resources = resources
        @public_resource = resources.all?(&:public?)

        self.methods      = combine_methods
        self.headers      = combine_headers
        self.expose       = combine_expose
        self.max_age      = combine_max_age
        self.credentials  = resources.all?(&:credentials)
        self.vary_headers = combine_vary
        self.pattern      = nil
        self.if_proc      = nil
        self.owner        = nil
        self.path_glob    = nil
      end

      # An empty method intersection is an explicit denial, independent of the
      # incoming request method.
      def deny_methods?
        methods.empty?
      end

      def process_preflight(env, result)
        return denied_headers(result) if deny_methods?

        super
      end

      def to_headers(env)
        return {} if deny_methods?

        super
      end

      private

      def denied_headers(result)
        result.miss(Result::MISS_DENY_METHOD)
        {}
      end

      def combine_methods
        return [] if matched_resources.empty?

        matched_resources.map(&:methods).reduce(:&).sort
      end

      def combine_headers
        return :any if matched_resources.all? { |r| r.headers == :any }
        return nil if matched_resources.any? { |r| r.headers.nil? }

        matched_resources
          .reject { |r| r.headers == :any }
          .map(&:headers)
          .reduce(:&)
          .sort
      end

      # Resources without an :expose option cannot expose anything, so they
      # narrow the intersection to the empty set.
      def combine_expose
        return nil if matched_resources.any? { |r| r.expose.nil? }

        matched_resources.map(&:expose).reduce(:&).sort
      end

      # Explicit :max_age values intersect at the tightest (smallest) value;
      # resources that leave it unset inherit the default instead of
      # tightening the constraint.
      def combine_max_age
        configured = matched_resources.select(&:max_age_configured).map(&:max_age)
        configured.empty? ? DEFAULT_MAX_AGE : configured.min
      end

      def combine_vary
        matched_resources.flat_map { |r| r.vary_headers || [] }.uniq.sort
      end
    end
  end
end
