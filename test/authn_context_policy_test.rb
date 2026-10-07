require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/authn_context_policy'

describe OneLogin::RubySaml::AuthnContextPolicy do
  Low = 'local:low'
  Medium = 'local:medium'
  High = 'local:high'
  Hardware = 'local:hardware'

  OrderedLevels = [Low, Medium, High].freeze

  let(:comparator) do
    lambda do |actual, requested|
      actual_rank = OrderedLevels.index(actual)
      requested_rank = OrderedLevels.index(requested)
      next nil if actual_rank.nil? || requested_rank.nil?
      actual_rank <=> requested_rank
    end
  end

  def auth_context(value, type = 'class')
    [type, value]
  end

  def reference(value)
    value.is_a?(Array) ? value : auth_context(value)
  end

  def reference_list(values)
    return [values] if values.is_a?(Array) && values.size == 2 && ['class', 'decl'].include?(values.first)
    return [] if values.nil?
    return values.collect { |value| reference(value) } if values.is_a?(Array)
    [reference(values)]
  end

  def build_policy(requested, actual, comparison = 'exact', compare_with = comparator)
    requested_values = reference_list(requested)
    actual_values = actual.nil? ? nil : reference_list(actual)

    OneLogin::RubySaml::AuthnContextPolicy.new(
      requested_values, actual_values, comparison, compare_with
    )
  end

  def assert_policy_rejects(policy, message)
    assert !policy.match?
    assert_equal message, policy.error
  end

  it "matches exact only when the response uses one requested class reference" do
    assert build_policy(Medium, Medium, 'exact').match?
    assert build_policy([Low, High], High, 'exact').match?

    assert_policy_rejects build_policy(Medium, Low, 'exact'), "Response AuthnContext does not exactly match a requested AuthnContext"
    assert_policy_rejects build_policy(Medium, High, 'exact'), "Response AuthnContext does not exactly match a requested AuthnContext"
  end

  it "does not treat class and declaration references as interchangeable in exact" do
    requested = auth_context(Medium, 'class')
    actual = auth_context(Medium, 'decl')

    assert_policy_rejects build_policy(requested, actual, 'exact'), "Response AuthnContext does not exactly match a requested AuthnContext"
  end

  it "matches minimum at and above the requested boundary, but not below or incomparable contexts" do
    assert build_policy(Medium, Medium, 'minimum').match?
    assert build_policy(Medium, High, 'minimum').match?
    assert build_policy([High, Low], Medium, 'minimum').match?

    assert_policy_rejects build_policy(Medium, Low, 'minimum'), "Response AuthnContext is weaker than the minimum requested AuthnContext"
    assert_policy_rejects build_policy(Medium, Hardware, 'minimum'), "Response AuthnContext is weaker than the minimum requested AuthnContext"
  end

  it "matches maximum at and below the requested boundary, but not above or incomparable contexts" do
    assert build_policy(Medium, Medium, 'maximum').match?
    assert build_policy(Medium, Low, 'maximum').match?
    assert build_policy([High, Low], Medium, 'maximum').match?

    assert_policy_rejects build_policy(Medium, High, 'maximum'), "Response AuthnContext is stronger than the maximum requested AuthnContext"
    assert_policy_rejects build_policy(Medium, Hardware, 'maximum'), "Response AuthnContext is stronger than the maximum requested AuthnContext"
  end

  it "matches better only strictly above every requested context" do
    assert build_policy(Medium, High, 'better').match?
    assert build_policy([Low, Medium], High, 'better').match?

    assert_policy_rejects build_policy(Medium, Medium, 'better'), "Response AuthnContext is not better than all requested AuthnContexts"
    assert_policy_rejects build_policy(Medium, Low, 'better'), "Response AuthnContext is not better than all requested AuthnContexts"
    assert_policy_rejects build_policy([Low, Medium], Medium, 'better'), "Response AuthnContext is not better than all requested AuthnContexts"
    assert_policy_rejects build_policy([Medium, Hardware], High, 'better'), "Response AuthnContext is not better than all requested AuthnContexts"
  end

  it "rejects missing response contexts" do
    assert_policy_rejects build_policy(Medium, nil, 'minimum'), "Response must contain exactly one AuthnContext reference"
    assert_policy_rejects build_policy(Medium, [], 'minimum'), "Response must contain exactly one AuthnContext reference"
  end

  it "rejects multiple response candidates" do
    actual = [auth_context(Medium), auth_context(High)]

    assert_policy_rejects build_policy([Low, Medium, High], actual, 'exact'), "Response must contain exactly one AuthnContext reference"
  end

  it "rejects empty response references and unknown ordered contexts" do
    assert_policy_rejects build_policy(Medium, auth_context(' '), 'exact'), "Response must contain a non-empty AuthnContext reference"
    assert_policy_rejects build_policy(Medium, Hardware, 'minimum'), "Response AuthnContext is weaker than the minimum requested AuthnContext"
    assert_policy_rejects build_policy(Medium, Hardware, 'maximum'), "Response AuthnContext is stronger than the maximum requested AuthnContext"
    assert_policy_rejects build_policy(Medium, Hardware, 'better'), "Response AuthnContext is not better than all requested AuthnContexts"
  end

  it "rejects empty request context lists and unsupported comparisons" do
    assert_policy_rejects build_policy([], Medium, 'exact'), "Requested AuthnContext must contain at least one context"
    assert_policy_rejects build_policy(Medium, Medium, 'stronger'), "Unsupported AuthnContext comparison: stronger"
  end

  it "rejects ordered comparisons when no comparator is provided" do
    policy = OneLogin::RubySaml::AuthnContextPolicy.new(
      [auth_context(Medium)], [auth_context(High)], 'minimum'
    )

    assert_policy_rejects policy, "Response AuthnContext is weaker than the minimum requested AuthnContext"
  end
end
