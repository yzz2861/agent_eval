# frozen_string_literal: false
require_relative '../lib/helper'
require 'drb'
require 'socket'

module DRbTests

  # In-memory dRuby transport for tests: connection-less socket pairs handed
  # out through a listener queue.  It exercises the exact same DRbMessage /
  # Marshal path as the TCP transport, without needing to bind a socket.
  class DRbMemorySocket
    LISTENERS = {}
    @mutex = Mutex.new
    @seq = 0

    def self.register(listener)
      @mutex.synchronize do
        @seq += 1
        uri = "drbmem://cap-#{@seq}"
        LISTENERS[uri] = listener
        uri
      end
    end

    def self.unregister(uri)
      LISTENERS.delete(uri)
    end

    def self.parse_uri(uri)
      raise DRb::DRbBadScheme, uri unless uri.start_with?('drbmem:')
      [uri, nil]
    end

    def self.open(uri, config)
      listener = LISTENERS[uri]
      raise DRb::DRbConnError, "no listener for #{uri}" unless listener
      listener.connect(config)
    end

    def self.open_server(uri, config)
      listener = new(nil, nil, config)
      if uri && uri != 'drbmem:'
        raise DRb::DRbBadURI, uri unless uri.start_with?('drbmem://')
        @mutex.synchronize do
          LISTENERS[uri] = listener
        end
        listener.uri = uri
      else
        listener.uri = register(listener)
      end
      listener
    end

    def self.uri_option(uri, config)
      [uri, nil]
    end

    attr_accessor :uri

    def initialize(uri, soc, config = {})
      @uri = uri
      @socket = soc
      @config = config
      @msg = DRb::DRbMessage.new(config)
      @mutex = Mutex.new
      @cond = ConditionVariable.new
      @pending = []
      @shutdown = false
    end

    def connect(config)
      server_side, client_side = UNIXSocket.pair(:STREAM)
      @mutex.synchronize do
        raise DRb::DRbConnError, "server stopped" if @shutdown
        @pending << server_side
        @cond.signal
      end
      self.class.new(@uri, client_side, config)
    end

    def stream; @socket; end

    def send_request(ref, msg_id, arg, b)
      @msg.send_request(stream, ref, msg_id, arg, b)
    end

    def recv_request
      @msg.recv_request(stream)
    end

    def send_reply(succ, result)
      @msg.send_reply(stream, succ, result)
    end

    def recv_reply
      @msg.recv_reply(stream)
    end

    def accept
      @mutex.synchronize do
        @cond.wait(@mutex) while @pending.empty? && !@shutdown
        return nil if @shutdown && @pending.empty?
        s = @pending.shift
        self.class.new(@uri, s, @config)
      end
    end

    def shutdown
      @mutex.synchronize do
        @shutdown = true
        @cond.broadcast
      end
    end

    def close
      shutdown rescue nil
      @socket.close if @socket
      if @uri
        @mutex.synchronize { @pending.each(&:close) rescue nil; @pending.clear }
        self.class.unregister(@uri)
      end
    end

    def alive?
      @socket && !@socket.closed?
    end
  end
  DRb::DRbProtocol.add_protocol(DRbMemorySocket)

  module DRbCapabilityTest

    def assert_raises_kind_of(klass)
      yield
      raise Test::Unit::AssertionFailedError,
            "expected #{klass} but nothing was raised"
    rescue Exception => e
      unless e.is_a?(klass)
        raise Test::Unit::AssertionFailedError,
              "expected #{klass}, got #{e.class}: #{e.message}"
      end
      e
    end

    # Object exposed behind capabilities on the server side.
    class Vault
      include DRb::DRbUndumped

      def open; :opened; end
      def close; :closed; end
      def admin_reset; :reset; end
      def make_box(label); Box.new(label); end
      def make_secret_doc; SecretDoc.new; end
      def touch; :touched; end
    end

    class Box
      include DRb::DRbUndumped

      def initialize(label)
        @label = label
      end

      def label; @label; end
      def seal; :sealed; end
      def destroy; :destroyed; end
    end

    class SecretDoc
      include DRb::DRbUndumped

      def read; :secret; end
    end

    # Privileged front object used only by the test harness to distribute
    # capabilities and revoke them server side.
    class CapabilityFront
      def initialize
        @vault = Vault.new
        @grants = {}
      end

      def read_only_grant
        grant = DRb.publish(@vault, [:open, :close, :make_box],
                            make_box: [:label, :seal])
        @grants[:ro] = grant
        grant.proxy
      end

      def admin_grant
        grant = DRb.publish(@vault,
                            [:open, :close, :admin_reset, :make_secret_doc,
                             :make_box, :touch],
                            make_secret_doc: [:read],
                            make_box: {methods: [:label, :seal, :destroy]},
                            touch: :copy)
        @grants[:admin] = grant
        grant.proxy
      end

      def revoke(name)
        @grants[name.to_sym]&.revoke
      end
    end

    def setup
      super
      @cap_server = DRb::DRbServer.new('drbmem:', CapabilityFront.new)
      @client_server = DRb::DRbServer.new('drbmem:', nil)
      @front = DRb::DRbObject.new_with_uri(@cap_server.uri)
    end

    def teardown
      @cap_server.stop_service if @cap_server
      @client_server.stop_service if @client_server
      DRb::DRbConn.stop_pool
      super
    end

    def test_permitted_methods_callable
      ro = @front.read_only_grant
      assert_equal(:opened, ro.open)
      assert_equal(:closed, ro.close)
    end

    def test_denied_method_raises
      ro = @front.read_only_grant
      err = assert_raises_kind_of(DRb::DRbError) { ro.admin_reset }
      assert_match(/does not permit method 'admin_reset'/, err.message)
    end

    def test_denied_meta_method_still_denied
      ro = @front.read_only_grant
      assert_equal(false, ro.respond_to?(:object_id))
      assert_equal(false, ro.respond_to?(:class))
      err = assert_raises_kind_of(DRb::DRbError) do
        ro.send(:__drb_not_a_real_method_x)
      end
      assert_match(/does not permit method/, err.message)
    end

    def test_send_and_public_send_cannot_bypass
      ro = @front.read_only_grant
      [:send, :public_send].each do |entry|
        assert_raises_kind_of(DRb::DRbError) do
          ro.__send__(entry, :admin_reset)
        end
      end
      assert_raise(SecurityError) do
        ro.method_missing(:__send__, :admin_reset)
      end
    end

    def test_indirect_dispatch_over_wire_denied
      ro = @front.read_only_grant
      err = assert_raises_kind_of(DRb::DRbError) { ro.send(:admin_reset) }
      assert_match(/does not permit method/, err.message)
    end

    def test_instance_eval_unavailable
      ro = @front.read_only_grant
      assert_equal(false, ro.respond_to?(:instance_eval))
      err = assert_raises_kind_of(DRb::DRbError) do
        ro.instance_eval { admin_reset }
      end
      assert_match(/does not permit method/, err.message)
    end

    def test_respond_to_reflects_interface
      ro = @front.read_only_grant
      assert_equal(true, ro.respond_to?(:open))
      assert_equal(true, ro.respond_to?(:close))
      assert_equal(false, ro.respond_to?(:admin_reset))
      assert_equal(false, ro.respond_to?(:send))
      assert_equal(false, ro.respond_to?(:__send__))
    end

    def test_client_field_tamper_cannot_widen
      ro = @front.read_only_grant
      ro.instance_variable_set(:@cap_methods, ro.cap_methods + [:admin_reset])
      assert_equal(true, ro.respond_to?(:admin_reset))
      err = assert_raises_kind_of(DRb::DRbError) { ro.admin_reset }
      assert_match(/does not permit method/, err.message)
    end

    def test_unknown_capability_ref_rejected
      ro = @front.read_only_grant
      ref = ro.instance_variable_get(:@ref)
      ref.instance_variable_set(:@id, '0' * 32)
      err = assert_raises_kind_of(DRb::DRbCapabilityRevoked) { ro.open }
      assert_match(/invalid capability reference/, err.message)
    end

    def test_derived_capability_is_attenuated
      ro = @front.read_only_grant
      view = ro.derive([:open])
      assert_equal(:opened, view.open)
      err = assert_raises_kind_of(DRb::DRbError) { view.close }
      assert_match(/does not permit method/, err.message)
    end

    def test_derivation_cannot_widen
      ro = @front.read_only_grant
      assert_raise(DRb::DRbCapabilityDenied) do
        ro.derive([:open, :admin_reset])
      end
    end

    def test_returned_object_wrapped_as_capability
      ro = @front.read_only_grant
      box = ro.make_box('mail')
      assert_equal('mail', box.label)
      assert_equal(:sealed, box.seal)
      err = assert_raises_kind_of(DRb::DRbError) { box.destroy }
      assert_match(/does not permit method/, err.message)
    end

    def test_nested_return_policy_on_admin_view
      admin = @front.admin_grant
      box = admin.make_box('vault-box')
      assert_equal('vault-box', box.label)
      assert_equal(:destroyed, box.destroy)
      assert_equal(false, box.respond_to?(:class))

      doc = admin.make_secret_doc
      assert_equal(:secret, doc.read)
      err = assert_raises_kind_of(DRb::DRbError) { doc.label }
      assert_match(/does not permit method/, err.message)
    end

    def test_copy_policy_returns_value
      admin = @front.admin_grant
      assert_equal(:touched, admin.touch)
    end

    def test_reference_policy_returns_full_drb_object
      registry = @cap_server.capability_registry
      target = Vault.new
      grant = DRb.publish(target, [:make_box], make_box: :reference)
      proxy = grant.proxy
      box = proxy.make_box('ref')
      assert_equal('ref', box.label)
      assert_equal(:destroyed, box.destroy)
    end

    def test_copy_policy_rejects_unmarshallable_result
      unmarshallable = Class.new do
        include DRb::DRbUndumped
      end
      target = Object.new
      target.define_singleton_method(:thing) { unmarshallable.new }
      grant = DRb.publish(target, [:thing], thing: :copy)
      proxy = grant.proxy
      err = assert_raises_kind_of(DRb::DRbError) { proxy.thing }
      assert_match(/DRbCapabilityPolicyError|cannot be marshalled/, err.message)
    end

    def test_revocation_invalidates_old_reference
      ro = @front.read_only_grant
      assert_equal(:opened, ro.open)
      @front.revoke(:ro)
      err = assert_raises_kind_of(DRb::DRbError) { ro.open }
      assert_match(/revoked/, err.message)
    end

    def test_revoking_derived_view_preserves_parent
      ro = @front.read_only_grant
      view = ro.derive([:open])
      @front.revoke(:ro)
      assert_equal(:opened, view.open)
    end

    def test_independent_sibling_grants
      ro = @front.read_only_grant
      admin = @front.admin_grant
      @front.revoke(:ro)
      err = assert_raises_kind_of(DRb::DRbError) { ro.open }
      assert_match(/revoked/, err.message)
      assert_equal(:opened, admin.open)
      assert_raises_kind_of(DRb::DRbError) { ro.admin_reset }
    end

    def test_chained_derivation_on_client_stub
      ro = @front.read_only_grant
      view = ro.derive([:open])
      assert_equal(:opened, view.open)
      assert_raises_kind_of(DRb::DRbError) { view.close }
    end

    def test_deny_list_enforced_at_publish
      assert_raise(DRb::DRbCapabilityDenied) do
        DRb.publish(Vault.new, [:send])
      end
      assert_raise(DRb::DRbCapabilityDenied) do
        DRb.publish(Vault.new, [:__send__])
      end
      assert_raise(DRb::DRbCapabilityDenied) do
        DRb.publish(Vault.new, [:instance_eval])
      end
    end

    def test_capability_stub_marshals_without_resolving
      # Simulate a separate client process: with no current server the wire
      # form must restore to a client stub, not the server-side enforcer.
      ro = @front.read_only_grant
      dumped = Marshal.dump(ro)
      restored = load_as_remote_client(dumped)
      assert_kind_of(DRb::DRbCapabilityObject, restored)
      assert_equal(ro.cap_methods, restored.cap_methods)
      assert_equal(true, restored.respond_to?(:open))
      assert_equal(false, restored.respond_to?(:admin_reset))
    end

    private

    # Marshal.load while temporarily making DRb.here? answer false, which is
    # exactly what a different process sees for the server's URI.
    def load_as_remote_client(data)
      DRb.singleton_class.send(:alias_method, :here_without_stub_test, :here?)
      DRb.define_singleton_method(:here?) { |_uri| false }
      Marshal.load(data)
    ensure
      DRb.singleton_class.send(:alias_method, :here?, :here_without_stub_test)
    end
  end

  class TestDRbCapability < Test::Unit::TestCase
    include DRbCapabilityTest
  end


  # Same-process loopback coverage: the stub dereferences inside the issuing
  # server, so the enforcer still gate-keeps every call.
  class TestDRbCapabilityLoopback < Test::Unit::TestCase
    class LocalVault
      include DRb::DRbUndumped
      def read; :read; end
      def write; :written; end
    end

    def setup
      @server = DRb::DRbServer.new('drbmem:')
      @vault = LocalVault.new
      @grant = DRb.publish(@vault, [:read])
      @proxy = @grant.proxy
    end

    def teardown
      @server.stop_service if @server
      DRb::DRbConn.stop_pool
    end

    def test_loopback_enforces
      assert_equal(:read, @proxy.read)
      assert_raise(DRb::DRbCapabilityDenied) { @proxy.write }
      assert_raise(DRb::DRbCapabilityDenied) { @proxy.send(:write) }
      assert_raise(DRb::DRbCapabilityDenied) { @proxy.public_send(:write) }
      assert_equal(true, @proxy.respond_to?(:read))
      assert_equal(false, @proxy.respond_to?(:write))
    end

    def test_loopback_attenuation
      view = @proxy.derive([])
      entry = ::Kernel.instance_method(:instance_variable_get).
        bind_call(view, :@entry)
      assert_equal([], entry.methods)
      assert_raise(DRb::DRbCapabilityDenied) { view.read }
      assert_equal(:read, @proxy.read)
    end

    def test_loopback_revocation
      @grant.revoke
      assert_raise(DRb::DRbCapabilityRevoked) { @proxy.read }
    end

    def test_loopback_return_wrap
      inner = LocalVault.new
      registry = @server.capability_registry
      grant = DRb.publish(@vault, [:read], read: [:read])
      wrapped = registry.apply_policy(grant.entry, :read, inner)
      assert_equal(true, DRb::DRbCapabilityMarker === wrapped)
      assert_equal(:read, wrapped.read)
      assert_raise(DRb::DRbCapabilityDenied) { wrapped.write }
    end
  end
end
