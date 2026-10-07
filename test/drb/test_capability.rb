# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb/drb'

class TestDRbCapability < Test::Unit::TestCase
  class SecretService
    include DRb::DRbUndumped

    def public_value
      1
    end

    def private_view
      2
    end

    def secret
      'secret'
    end

    def raw_child
      ChildService.new
    end

    def hidden_child
      ChildService.new
    end

    def child
      ChildService.new
    end
  end

  class ChildService
    include DRb::DRbUndumped

    def name
      'child'
    end

    def secret
      'child-secret'
    end
  end

  def setup
    @service = SecretService.new
    @front = DRb::Capability.new(
      @service,
      [:public_value, :private_view, :raw_child, :hidden_child, :child],
      returns: {
        raw_child: :reference,
        child: {allow: [:name], returns: {}}
      }
    )
    @server = DRb::DRbServer.new('druby://127.0.0.1:0', @front)
    @root = DRb::DRbObject.new_with_uri(@server.uri)
  end

  def teardown
    @server&.stop_service
    @server&.thread&.join
    DRb::DRbConn.stop_pool
  end

  def test_allows_only_declared_methods
    assert_equal(1, @root.public_value)
    assert_equal(2, @root.private_view)
    assert_respond_to(@root, :public_value)
    assert_respond_to(@root, :derive)
    assert_not_respond_to(@root, :secret)

    assert_raise(DRb::DRbCapabilityError) do
      @root.secret
    end
  end

  def test_indirect_calls_cannot_bypass_capability
    assert_equal(1, @root.send(:public_value))
    assert_equal(1, @root.public_send(:public_value))

    assert_raise(DRb::DRbCapabilityError) { @root.send(:secret) }
    assert_raise(DRb::DRbCapabilityError) { @root.public_send(:secret) }
    assert_raise(DRb::DRbCapabilityError) { @root.__send__(:secret) }
    assert_raise(DRb::DRbCapabilityError) do
      @root.instance_variable_set(:@allowed_methods, [:secret])
      @root.secret
    end
  end

  def test_returned_object_uses_declared_nested_capability
    child = @root.child

    assert_kind_of(DRb::Capability, child)
    assert_equal('child', child.name)
    assert_respond_to(child, :name)
    assert_not_respond_to(child, :secret)
    assert_raise(DRb::DRbCapabilityError) { child.secret }
  end

  def test_returned_object_can_use_declared_plain_reference
    child = @root.raw_child

    assert_kind_of(DRb::DRbObject, child)
    assert_equal('child-secret', child.secret)
  end

  def test_undeclared_remote_return_is_rejected
    assert_raise(DRb::DRbCapabilityError) do
      @root.hidden_child
    end
  end

  def test_derived_capability_can_only_reduce_permissions
    limited = @root.derive([:child])
    child = limited.child

    assert_equal('child', child.name)
    assert_not_respond_to(limited, :public_value)
    assert_raise(DRb::DRbCapabilityError) { limited.public_value }
    assert_raise(DRb::DRbCapabilityError) { limited.derive([:secret]) }
  end

  def test_revoking_one_grant_leaves_other_grants_valid
    limited = @root.derive([:public_value])
    other = @root.derive([:public_value])

    assert_equal(1, limited.public_value)
    assert_equal(1, other.public_value)
    assert limited.revoke!
    assert_raise(DRb::DRbCapabilityError) { limited.public_value }
    assert_equal(1, other.public_value)
    assert_equal(1, @root.public_value)
  end
end
