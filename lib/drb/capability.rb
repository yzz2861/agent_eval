# frozen_string_literal: false
#
# = drb/capability.rb
#
# Optional capability proxies for dRuby.
#
# A capability is a reference to a live server object that may invoke only a
# server-declared subset of that object's methods.  Capabilities can be
# attenuated: a holder may derive a new capability whose interface is a
# subset of the one it holds.  Each capability is independently revocable;
# revoking one capability never affects sibling capabilities, including
# those derived from the same object.
#
# == Security model
#
# The capability table (the mapping from capability id to target object,
# allowed methods and return policies) lives entirely inside the
# DRb::DRbServer that exported the object.  The reference handed to a client
# carries only an unforgeable random id plus a cached copy of the method
# list; mutating client-side fields cannot widen the interface because the
# server consults its own table on every invocation.  The enforcer that
# receives each call is a BasicObject that whitelists methods, so indirect
# entries such as +send+ and +public_send+ cannot be used to bypass the
# restriction, and +respond_to?+ reports only the permitted interface.
#
# This feature is *not* a general defense against connecting untrusted
# peers.  In particular it does not change dRuby's use of Marshal: an
# attacker who may deliver arbitrary marshalled data, or invoke arbitrary
# methods outside a capability, is still outside the threat model.  Run drb
# behind the existing transport protections (localhost/private networks,
# DRb::ACL, TLS) and only hand capabilities to peers you would already allow
# to connect.
#++

require 'securerandom'

module DRb

  # Base class for capability related errors.
  class DRbCapabilityError < DRbError; end

  # Raised when a capability is used to invoke a method it does not permit,
  # or when an attempt is made to widen a capability while deriving one.
  class DRbCapabilityDenied < DRbCapabilityError; end

  # Raised when a capability reference refers to a capability that has been
  # revoked, or a capability id unknown to the server is used.
  class DRbCapabilityRevoked < DRbCapabilityError; end

  # Raised when a return policy cannot be honored, e.g. a +:copy+ policy is
  # declared for a result that cannot be marshalled.
  class DRbCapabilityPolicyError < DRbCapabilityError; end

  # Wire reference carried inside a marshalled DRbCapabilityObject.
  #
  # The id is meaningful only to the server that minted it; the client
  # cannot derive target object ids from it.
  class DRbCapabilityRef # :nodoc: all
    attr_reader :id

    def initialize(id)
      @id = id
    end

    def _dump(lv)
      Marshal.dump(@id)
    end

    def self._load(s)
      new(Marshal.load(s))
    end
  end

  # Client-side stub for a capability.
  #
  # It reuses the normal dRuby transport (DRbObject) for message delivery,
  # but carries the capability id under which the call is authorized and a
  # cached view of the currently permitted methods.
  class DRbCapabilityObject < DRbObject

    # Reconstitute a capability stub from its wire form.  Inside the issuing
    # server this resolves to the live enforcer so loopback calls are
    # authorized exactly like remote calls; elsewhere a client stub is
    # built.
    def self._load(s)
      uri, ref, methods = Marshal.load(s)
      if DRb.here?(uri)
        return DRb.to_obj(ref)
      end
      it = allocate
      it.instance_variable_set(:@uri, uri)
      it.instance_variable_set(:@ref, ref)
      it.instance_variable_set(:@cap_methods, methods)
      it
    end

    def self.new_with(uri, ref, methods) # :nodoc:
      it = allocate
      it.instance_variable_set(:@uri, uri)
      it.instance_variable_set(:@ref, ref)
      it.instance_variable_set(:@cap_methods, methods)
      it
    end

    def _dump(lv)
      Marshal.dump([@uri, @ref, @cap_methods])
    end

    # Build a wire stub from a live server enforcer.
    def self.from_enforcer(uri, enforcer) # :nodoc:
      entry = ::Kernel.instance_method(:instance_variable_get).
        bind_call(enforcer, :@entry)
      new_with(entry.uri || uri,
               DRbCapabilityRef.new(entry.id), entry.methods.dup)
    end

    # Methods currently permitted by the capability, as cached at the time
    # the capability was issued or last derived.  The server-side table is
    # authoritative; this list is exposed only for local introspection.
    attr_reader :cap_methods

    # Reports +true+ only for methods the capability currently permits.
    #
    # This is answered from the cached interface without a round trip, so
    # it never reveals methods the holder cannot call.  The server still
    # re-checks the interface when a method is actually invoked.
    def respond_to?(msg_id, priv=false)
      return true if msg_id == :_dump || msg_id == :derive ||
                     msg_id == :cap_methods
      return false if msg_id == :marshal_dump
      @cap_methods.include?(msg_id)
    end

    # Derive a strictly weaker capability.
    #
    # +methods+ must be a subset of the methods permitted by this
    # capability.  The derivation is performed by the server, which mints
    # a fresh, independently revocable capability.  Revoking the returned
    # capability does not affect this one, and vice versa.
    def derive(methods)
      wanted = methods.map do |m|
        m = m.to_sym unless Symbol === m
        unless @cap_methods.include?(m)
          raise DRbCapabilityDenied,
            "cannot grant method '#{m}' that this capability does not hold"
        end
        m
      end
      method_missing(:__drb_cap_derive, wanted)
    end
  end

  # Marks the server-side capability enforcer so the marshalling layer can
  # replace it with a DRbCapabilityObject wire stub.
  module DRbCapabilityMarker # :nodoc:
    def __drb_make_proxy
      DRbCapabilityObject.from_enforcer(@entry.uri, self)
    end
  end

  # Server-side capability registry.  One instance is owned by each
  # DRbServer; it is the authoritative store of capability state.
  class CapabilityRegistry
    include MonitorMixin

    # One authorized view of a target object.
    Entry = Struct.new(:id, :target, :methods, :policies, :revoked, :uri)

    # Methods that may never appear in a capability interface, even if the
    # target responds to them.  They are meta/escape entries or dRuby
    # plumbing that could bypass the enforcer.
    DENIED_METHODS = [
      :__send__, :send, :public_send,
      :instance_eval, :instance_exec, :define_singleton_method,
      :method, :public_method, :singleton_method,
      :instance_variable_get, :instance_variable_set, :instance_variables,
      :_dump, :marshal_dump, :marshal_load,
      :__drb_make_proxy, :__drbref, :__drburi,
      :__drb_cap_derive
    ].freeze

    def initialize
      super
      @entries = {}
      @enforcers = {}
    end

    attr_writer :server_uri

    # Mint a capability for +target+ permitting +methods+ with the given
    # return +policies+ (a Hash of method name to policy).  Returns the new
    # Entry.
    def publish(target, methods, policies = {})
      synchronize do
        publish_unlocked(target, methods, policies)
      end
    end

    # Create an attenuated capability from an existing live entry.
    def derive(entry, methods)
      synchronize do
        denied = methods - entry.methods
        unless denied.empty?
          raise DRbCapabilityDenied,
            "cannot derive capability adding methods: " \
            "#{denied.map(&:inspect).join(', ')}"
        end
        policies = {}
        entry.policies.each do |m, policy|
          policies[m] = policy if methods.include?(m)
        end
        publish_unlocked(entry.target, methods, policies)
      end
    end

    def revoke(id)
      synchronize do
        entry = @entries[id]
        return false unless entry
        entry.revoked = true
        @entries.delete(id)
      end
      true
    end

    def resolve(id)
      entry = @entries[id]
      if entry.nil? || entry.revoked
        raise DRbCapabilityRevoked,
          "capability '#{id}' has been revoked or does not exist"
      end
      entry
    end

    def to_obj(ref)
      case ref
      when DRbCapabilityRef
        enforcer = @enforcers[ref.id]
        raise DRbCapabilityRevoked, "invalid capability reference" unless enforcer
        resolve(ref.id)
        enforcer
      else
        raise DRbCapabilityRevoked, "invalid capability reference"
      end
    end

    # Apply the declared return policy for +msg_id+ to +result+.
    def apply_policy(entry, msg_id, result)
      policy = entry.policies[msg_id]
      case policy
      when nil, :default
        result
      when :copy
        begin
          Marshal.dump(result)
        rescue TypeError, SystemStackError
          raise DRbCapabilityPolicyError,
            "method '#{msg_id}' declares :copy but the result cannot be marshalled"
        end
        result
      when :reference
        DRbObject.new(result)
      when Hash
        wrap_as_capability(result, policy[:methods], policy[:policies] || {})
      else
        result
      end
    end

    private

    def publish_unlocked(target, methods, policies)
      methods = methods.map do |m|
        m = m.to_sym unless Symbol === m
        unless Symbol === m
          raise ArgumentError, "capability method names must be symbols"
        end
        if DENIED_METHODS.include?(m)
          raise DRbCapabilityDenied,
            "method '#{m}' may not be exposed through a capability"
        end
        unless target.respond_to?(m)
          raise ArgumentError,
            "target does not have public method '#{m}' to expose"
        end
        m
      end.uniq

      policies = normalize_policies(policies)
      policies.each_key do |m|
        unless methods.include?(m)
          raise ArgumentError,
            "return policy declared for unexposed method '#{m}'"
        end
      end

      id = mint_id
      entry = Entry.new(id, target, methods, policies, false, issuer_uri)
      @entries[id] = entry
      @enforcers[id] = CapabilityEnforcer.new(self, entry)
      entry
    end

    def wrap_as_capability(result, methods, policies)
      case result
      when DRbCapabilityMarker
        result
      when nil
        result
      else
        subentry = publish(result, methods || [], policies)
        @enforcers[subentry.id]
      end
    end

    def issuer_uri
      @server_uri || DRb.uri
    end

    def normalize_policies(policies)
      normalized = {}
      policies.each do |m, policy|
        m = m.to_sym unless Symbol === m
        normalized[m] = normalize_policy(policy)
      end
      normalized
    end

    def normalize_policy(policy)
      case policy
      when Symbol, String
        policy.to_sym
      when Hash
        methods = (policy[:methods] || policy['methods'] || []).map do |m|
          Symbol === m ? m : m.to_sym
        end
        sub = policy[:policies] || policy['policies'] || {}
        {methods: methods, policies: normalize_policies(sub)}
      when Array
        {methods: policy.map { |m| Symbol === m ? m : m.to_sym }, policies: {}}
      else
        raise ArgumentError, "invalid capability return policy: #{policy.inspect}"
      end
    end

    def mint_id
      id = nil
      synchronize do
        loop do
          id = SecureRandom.hex(16)
          break unless @entries.key?(id)
        end
      end
      id
    end
  end

  # Server-side enforcer: every call that enters the server through a
  # capability is routed here.  It is a BasicObject with a whitelist, so
  # the only invocable entries are the declared methods (plus the internal
  # pseudo-entries implemented below).
  class CapabilityEnforcer < ::BasicObject
    include ::DRb::DRbUndumped
    include ::DRb::DRbCapabilityMarker

    # Remove escape hatches that exist on BasicObject itself.
    undef_method :instance_eval, :instance_exec

    def initialize(registry, entry)
      @registry = registry
      @entry = entry
    end

    # The whitelist gate.  Unknown or non-whitelisted methods on a
    # BasicObject land here, covering both loopback dispatch and the dRuby
    # server's invocation.  The built-in +__send__+ is blocked by the
    # server's insecure method check and +respond_to?+ is defined below.
    def method_missing(msg_id, *argv, &block)
      unless ::Symbol === msg_id
        ::Kernel.raise ::ArgumentError, "method name is not a symbol"
      end

      case msg_id
      when :__drb_cap_derive
        wanted = argv.first
        subentry = @registry.derive(live_entry, wanted)
        return CapabilityEnforcer.new(@registry, subentry)
      end

      if CapabilityRegistry::DENIED_METHODS.include?(msg_id) ||
         !@entry.methods.include?(msg_id)
        live_entry # raises if revoked
        ::Kernel.raise ::DRb::DRbCapabilityDenied,
          "capability does not permit method '#{msg_id}'"
      end

      entry = live_entry
      result = entry.target.__send__(msg_id, *argv, &block)
      @registry.apply_policy(entry, msg_id, result)
    end

    def respond_to_missing?(msg_id, priv=false)
      @entry.methods.include?(msg_id)
    end

    def respond_to?(msg_id, priv=false)
      asked = msg_id.to_sym unless ::Symbol === msg_id
      @entry.methods.include?(asked)
    end

    private

    def live_entry
      @registry.resolve(@entry.id)
    end
  end

  # Handle returned by the server when a capability is published.  It
  # exposes the capability stub to hand to clients and a way to revoke the
  # capability locally.
  class CapabilityGrant
    def initialize(registry, entry)
      @registry = registry
      @entry = entry
    end

    # The marshalled-capable DRbCapabilityObject to publish to clients.
    def proxy
      enforcer = CapabilityEnforcer.new(@registry, @entry)
      DRbCapabilityMarker.instance_method(:__drb_make_proxy).
        bind_call(enforcer)
    end

    # Revoke this capability.  Existing remote references start failing
    # with DRbCapabilityRevoked; sibling and derived capabilities are left
    # untouched.
    def revoke
      @registry.revoke(@entry.id)
    end

    attr_reader :entry
  end

  # Publish +object+ under a capability from the current server.
  #
  # +methods+ is the list of permitted public method names.  +policies+
  # optionally declares how return values are packaged; recognized policies
  # are:
  #
  # +nil+/+:default+ :: Normal dRuby marshalling (the default).
  # +:copy+ :: Send a marshalled copy; raise if the result is unmarshallable.
  # +:reference+ :: Send a full DRbObject reference (all methods) rather
  #                 than a capability.
  # +Hash+/+Array+ :: Wrap the returned remote object in another capability
  #                   exposing the listed +:methods+ and optional nested
  #                   +:policies+.
  #
  # Returns a DRb::CapabilityGrant.
  def self.publish(object, methods, policies = {})
    registry = DRb.current_server.capability_registry
    entry = registry.publish(object, methods, policies)
    CapabilityGrant.new(registry, entry)
  end
end
