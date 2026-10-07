require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/authn_context_policy'

class AuthnContextPolicyTest < Minitest::Test
  describe OneLogin::RubySaml::AuthnContextPolicy do
    let(:levels) do
      {
        "local:low" => 1,
        "local:medium" => 2,
        "local:high" => 3,
        "local:smartcard" => 4,
        "local:branch" => :branch
      }
    end

    def policy(requested, actual, comparison = "exact", comparator = nil)
      OneLogin::RubySaml::AuthnContextPolicy.new(
        Array(requested),
        [],
        { :class_ref => [actual] },
        comparison,
        comparator
      )
    end

    describe "exact" do
      it "matches when the returned context is one of the requested candidates" do
        assert policy(["local:low", "local:medium"], "local:medium").match?
      end

      it "does not use the comparator to decide equality" do
        assert policy(["local:low"], "local:low", "exact", levels).match?
        refute policy(["local:low"], "local:high", "exact", levels).match?
      end

      it "rejects a different level" do
        refute policy(["local:medium"], "local:high").match?
      end

      it "does not match when the response contains only a DeclRef for a ClassRef request" do
        matching_policy = OneLogin::RubySaml::AuthnContextPolicy.new(
          ["local:medium"],
          [],
          { :decl_ref => ["local:medium"] }
        )

        refute matching_policy.match?
        assert_includes matching_policy.errors, "Response AuthnContext must contain exactly one AuthnContextClassRef"
      end

      it "ignores a DeclRef when the response also contains the requested ClassRef" do
        matching_policy = OneLogin::RubySaml::AuthnContextPolicy.new(
          ["local:medium"],
          [],
          {
            :class_ref => ["local:medium"],
            :decl_ref => ["local:declaration"]
          }
        )

        assert matching_policy.match?
      end
    end

    describe "minimum" do
      it "accepts an equal level" do
        assert policy(["local:medium"], "local:medium", "minimum", levels).match?
      end

      it "accepts a stronger level" do
        assert policy(["local:medium"], "local:high", "minimum", levels).match?
      end

      it "rejects a weaker level" do
        matching_policy = policy(["local:medium"], "local:low", "minimum", levels)

        refute matching_policy.match?
      end

      it "accepts when any requested candidate is at or below the returned level" do
        assert policy(["local:smartcard", "local:low"], "local:medium", "minimum", levels).match?
      end
    end

    describe "maximum" do
      it "accepts an equal level" do
        assert policy(["local:medium"], "local:medium", "maximum", levels).match?
      end

      it "accepts a weaker level" do
        assert policy(["local:medium"], "local:low", "maximum", levels).match?
      end

      it "rejects a stronger level" do
        matching_policy = policy(["local:medium"], "local:high", "maximum", levels)

        refute matching_policy.match?
      end

      it "accepts when any requested candidate is at or above the returned level" do
        assert policy(["local:low", "local:smartcard"], "local:medium", "maximum", levels).match?
      end
    end

    describe "better" do
      it "rejects an equal level" do
        matching_policy = policy(["local:medium"], "local:medium", "better", levels)

        refute matching_policy.match?
      end

      it "accepts a stronger level" do
        assert policy(["local:medium"], "local:high", "better", levels).match?
      end

      it "rejects a weaker level" do
        refute policy(["local:medium"], "local:low", "better", levels).match?
      end

      it "accepts when the returned level is stronger than any candidate" do
        assert policy(["local:low", "local:medium"], "local:high", "better", levels).match?
      end
    end

    describe "caller-provided ordering" do
      it "accepts a Proc comparator" do
        comparator = lambda do |requested, actual|
          levels.fetch(actual) <=> levels.fetch(requested)
        end

        assert policy(["local:medium"], "local:high", "minimum", comparator).match?
      end

      it "rejects incomparable contexts when the comparator returns nil" do
        comparator = lambda { |_requested, _actual| nil }
        matching_policy = policy(["local:medium"], "local:branch", "minimum", comparator)

        refute matching_policy.match?
      end

      it "rejects incomparable ordered contexts even if a hash value is not numerically comparable" do
        matching_policy = policy(["local:medium"], "local:branch", "minimum", levels)

        refute matching_policy.match?
        assert_includes matching_policy.errors.join(" "), "could not compare"
      end

      it "rejects an unknown returned context" do
        matching_policy = policy(["local:medium"], "local:unknown", "minimum", levels)

        refute matching_policy.match?
        assert_includes matching_policy.errors.join(" "), "could not compare"
      end

      it "rejects an unknown requested context" do
        matching_policy = policy(["local:unknown"], "local:medium", "minimum", levels)

        refute matching_policy.match?
        assert_includes matching_policy.errors.join(" "), "could not compare"
      end
    end

    describe "invalid policy input" do
      it "rejects a missing returned context" do
        matching_policy = OneLogin::RubySaml::AuthnContextPolicy.new(
          ["local:medium"],
          [],
          { :class_ref => [] }
        )

        refute matching_policy.match?
        assert_includes matching_policy.errors, "Response AuthnContext must contain exactly one AuthnContextClassRef"
      end

      it "rejects multiple returned contexts" do
        matching_policy = OneLogin::RubySaml::AuthnContextPolicy.new(
          ["local:medium"],
          [],
          { :class_ref => ["local:medium", "local:high"] }
        )

        refute matching_policy.match?
        assert_includes matching_policy.errors, "Response AuthnContext must contain exactly one AuthnContextClassRef"
      end

      it "rejects missing requested contexts" do
        matching_policy = OneLogin::RubySaml::AuthnContextPolicy.new(
          [],
          [],
          { :class_ref => ["local:medium"] }
        )

        refute matching_policy.match?
        assert_includes matching_policy.errors, "Requested AuthnContext is missing"
      end

      it "rejects requested ClassRef and DeclRef candidates in the same request" do
        matching_policy = OneLogin::RubySaml::AuthnContextPolicy.new(
          ["local:medium"],
          ["local:decl"],
          { :class_ref => ["local:medium"] }
        )

        refute matching_policy.match?
        assert_includes matching_policy.errors, "Requested AuthnContext cannot contain both ClassRef and DeclRef"
      end

      it "requires a comparator for ordered comparisons" do
        matching_policy = policy(["local:medium"], "local:high", "minimum")

        refute matching_policy.match?
        assert_includes matching_policy.errors, "AuthnContext comparator is required for minimum comparison"
      end

      it "rejects an unsupported comparison" do
        matching_policy = policy(["local:medium"], "local:medium", "different")

        refute matching_policy.match?
        assert_includes matching_policy.errors, "Unsupported AuthnContext comparison: different"
      end
    end
  end
end
