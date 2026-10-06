# frozen_string_literal: true

module MessagePack
  # Lightweight negotiation layer on top of MessagePack::Factory.
  #
  # Two peers extend MessagePack independently, so the same extension type
  # id may mean a different object on each side. Instead of sharing a
  # global registry, each peer describes its types with a logical name, a
  # version and the type ids it is able to use. Negotiation matches those
  # descriptions and builds a session-specific factory whose wire ids are
  # valid for that session only.
  #
  #   local = MessagePack::Negotiation::Registry.new
  #   local.register(:point, version: 1, types: [3, 10], klass: Point)
  #
  #   session = MessagePack::Negotiation.negotiate(local, remote_advertisement)
  #   session.factory # => frozen MessagePack::Factory for this session
  #
  # The global MessagePack::DefaultFactory is never touched, and a session
  # keeps its interpretation even if the source registry is extended later.
  module Negotiation
    # Extension type ids reserved by the MessagePack specification for
    # predefined extension types (e.g. Timestamp uses -1). Application
    # types must live in 0..127.
    RESERVED_TYPE_IDS = (-128..-1).freeze
    MIN_TYPE_ID = 0
    MAX_TYPE_ID = 127

    class Error < StandardError; end

    # Raised when a registration would silently change the meaning of a
    # registry, e.g. a type id or a (name, version) pair registered twice.
    class ConflictError < Error; end

    # Raised when a reserved or out-of-range type id is registered.
    class InvalidTypeIdError < Error; end

    # Raised when required types cannot be negotiated. Carries the
    # unresolved required types and the optional types that would have
    # been disabled, so callers can report both at once.
    class NegotiationError < Error
      attr_reader :unresolved, :disabled

      def initialize(unresolved, disabled)
        @unresolved = unresolved.freeze
        @disabled = disabled.freeze
        names = unresolved.map { |entry| entry[:name] }.join(", ")
        super("cannot negotiate required extension type(s): #{names}")
      end
    end

    # Local description of the extension types a peer supports.
    #
    # Registrations are append-only: a type id or a (name, version) pair
    # can never be redefined, so a later registration can never override
    # an earlier one.
    class Registry
      Entry = Struct.new(:name, :version, :type_ids, :klass, :options, :required)

      def initialize
        @entries = {}        # [name, version] => Entry
        @type_id_owner = {}  # type id => [name, version]
      end

      # Register a logical type.
      #
      # name:     logical type name shared with the peer (Symbol or String)
      # version:  integer version of the logical type
      # type:     single usable extension type id (0..127)
      # types:    list of usable extension type ids, in preference order
      # klass:    local class (or Struct) the type maps to
      # required: when true, a session is refused unless this type is
      #           negotiated; when false the type is simply disabled
      # packer/unpacker: same convention as MessagePack::Factory#register_type
      def register(name, version:, type: nil, types: nil, klass: nil, required: true,
                   packer: :to_msgpack_ext, unpacker: :from_msgpack_ext)
        name = name.to_sym
        version = Integer(version)
        type_ids = normalize_type_ids(type, types)
        key = [name, version]

        if @entries.key?(key)
          raise ConflictError, "#{name.inspect} version #{version} is already registered"
        end

        type_ids.each do |type_id|
          unless usable_type_id?(type_id)
            raise InvalidTypeIdError,
                  "extension type id #{type_id} is reserved by the protocol or out of range (usable: #{MIN_TYPE_ID}..#{MAX_TYPE_ID})"
          end
          if (owner = @type_id_owner[type_id])
            raise ConflictError,
                  "extension type id #{type_id} is already used by #{owner[0].inspect} version #{owner[1]}"
          end
        end

        options = { packer: packer, unpacker: unpacker }.freeze
        entry = Entry.new(name, version, type_ids, klass, options, !!required)
        @entries[key] = entry
        type_ids.each { |type_id| @type_id_owner[type_id] = key }
        entry
      end

      def entry(name, version)
        @entries[[name.to_sym, Integer(version)]]
      end

      def required?(name)
        name = name.to_sym
        @entries.each_value.any? { |entry| entry.name == name && entry.required }
      end

      # What this peer can offer on the wire:
      #   { name => { version => [type ids] } }
      def advertisement
        advertisement = {}
        @entries.each_value do |entry|
          (advertisement[entry.name] ||= {})[entry.version] = entry.type_ids
        end
        advertisement
      end

      private

      def normalize_type_ids(type, types)
        ids = []
        ids << type unless type.nil?
        ids.concat(Array(types)) unless types.nil?
        if ids.empty?
          raise ArgumentError, "at least one type id is required (type: or types:)"
        end
        ids.map { |id| Integer(id) }.uniq.freeze
      end

      def usable_type_id?(type_id)
        type_id >= MIN_TYPE_ID && type_id <= MAX_TYPE_ID && !RESERVED_TYPE_IDS.cover?(type_id)
      end
    end

    # Result of a successful negotiation. The factory is frozen, so the
    # session's interpretation cannot be changed afterwards.
    class Session
      attr_reader :factory, :enabled, :disabled

      def initialize(factory, enabled, disabled)
        @factory = factory
        @enabled = enabled.freeze
        @disabled = disabled.freeze
      end

      def enabled?(name)
        @enabled.any? { |entry| entry[:name] == name.to_sym }
      end

      def packer(*args)
        factory.packer(*args)
      end

      def unpacker(*args)
        factory.unpacker(*args)
      end

      def dump(object, *rest)
        factory.dump(object, *rest)
      end
      alias pack dump

      def load(src, *rest)
        factory.load(src, *rest)
      end
      alias unpack load
    end

    class << self
      # Negotiate a session between the local registry and the peer's
      # advertisement (a Registry or a plain { name => { version => [ids] } }
      # hash). Returns a Session, or raises NegotiationError when a required
      # type has no common version or no common usable type id.
      #
      # On failure nothing is installed: the local registry, the peer
      # advertisement and MessagePack::DefaultFactory are left untouched.
      def negotiate(local, remote)
        remote_advertisement = normalize_advertisement(remote)

        enabled = []
        disabled = []
        unresolved = []
        registrations = [] # [type_id, Entry], applied only on success

        local.advertisement.keys.sort.each do |name|
          local_versions = local.advertisement[name]
          remote_versions = remote_advertisement[name] || {}
          common_versions = (local_versions.keys & remote_versions.keys).sort

          chosen = nil
          common_versions.reverse_each do |version|
            common_ids = usable_type_ids(local_versions[version]) & usable_type_ids(remote_versions[version])
            unless common_ids.empty?
              chosen = [version, common_ids.min]
              break
            end
          end

          if chosen
            version, type_id = chosen
            registrations << [type_id, local.entry(name, version)]
            enabled << { name: name, version: version, type: type_id }
          else
            reason =
              if remote_versions.empty?
                :not_supported_by_peer
              elsif common_versions.empty?
                :no_common_version
              else
                :no_common_type_id
              end
            record = { name: name, reason: reason }
            if local.required?(name)
              unresolved << record
            else
              disabled << record
            end
          end
        end

        # Refuse the session before installing anything: the factory is
        # only built once every required type has been resolved.
        unless unresolved.empty?
          raise NegotiationError.new(unresolved, disabled)
        end

        factory = Factory.new
        registrations.each do |type_id, entry|
          factory.register_type(type_id, entry.klass, **entry.options)
        end
        factory.freeze

        Session.new(factory, enabled, disabled)
      end

      private

      def normalize_advertisement(remote)
        advertisement = remote.is_a?(Registry) ? remote.advertisement : remote
        normalized = {}
        advertisement.each_pair do |name, versions|
          normalized[name.to_sym] = versions.each_with_object({}) do |(version, ids), hash|
            hash[Integer(version)] = Array(ids).map { |id| Integer(id) }
          end
        end
        normalized
      end

      def usable_type_ids(type_ids)
        type_ids.select do |type_id|
          type_id >= MIN_TYPE_ID && type_id <= MAX_TYPE_ID && !RESERVED_TYPE_IDS.cover?(type_id)
        end
      end
    end
  end
end
