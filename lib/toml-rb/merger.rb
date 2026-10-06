# frozen_string_literal: true

module TomlRB
  class Deletion
    attr_reader :identity

    def initialize(identity = nil)
      @identity = identity
    end

    def inspect
      identity ? "#<TomlRB::Deletion #{identity.inspect}>" : "#<TomlRB::Deletion>"
    end
  end

  # Sentinel used to remove a key or table from a lower-priority layer.
  DELETE = Deletion.new.freeze

  class Merger
    UNSET_RULES = Object.new.freeze

    def initialize(*layers, table_arrays: {}, array_tables: UNSET_RULES)
      @layers = layers
      @rules = normalize_rules(array_tables == UNSET_RULES ? table_arrays : array_tables)
    end

    def to_h
      result = {}
      @layers.each do |layer|
        unless layer.is_a?(Hash)
          raise ArgumentError, "each configuration layer must be a Hash"
        end
        merge_hash!(result, deep_copy(layer), [])
      end
      result
    end

    private

    def normalize_rules(rules)
      unless rules.is_a?(Hash)
        raise ArgumentError, "array_tables rules must be a Hash"
      end

      rules.each_with_object({}) do |(path, key), normalized|
        unless key.is_a?(String) || key.is_a?(Symbol)
          raise ArgumentError, "identity field must be a String or Symbol"
        end
        parts = path_parts(path)
        identity_key = key.to_s
        if identity_key.empty?
          raise ArgumentError, "identity field for #{parts.join(".")} cannot be empty"
        end
        if normalized.key?(parts)
          raise ArgumentError, "duplicate array table rule #{parts.join(".")}"
        end
        normalized[parts] = identity_key
      end
    end

    def path_parts(path)
      case path
      when Array
        parts = path.map(&:to_s)
      when String, Symbol
        parts = path.to_s.split("\.")
      else
        raise ArgumentError, "array table paths must be a String, Symbol or Array"
      end

      if parts.empty? || parts.any? { |part| part.empty? }
        raise ArgumentError, "array table path cannot be empty"
      end
      parts
    end

    def merge_hash!(target, source, path)
      source.each do |key, value|
        child_path = path + [key]
        if value.is_a?(Deletion)
          target.delete(key)
          next
        end

        if target.key?(key)
          target[key] = merge_value(target[key], value, child_path)
        elsif value.is_a?(Hash)
          target[key] = {}
          merge_hash!(target[key], value, child_path)
        else
          prepare_value!(value, child_path)
          target[key] = value
        end
      end
    end

    def merge_value(current, incoming, path)
      identity_key = rule_for(path)
      if identity_key
        merge_table_array(current, incoming, path, identity_key)
      elsif current.is_a?(Hash) && incoming.is_a?(Hash)
        merge_hash!(current, incoming, path)
        current
      elsif type_conflict?(current, incoming)
        fail_merge!(conflict_message(path, current, incoming))
      else
        prepare_value!(incoming, path)
        incoming
      end
    end

    def type_conflict?(current, incoming)
      current.is_a?(Hash) != incoming.is_a?(Hash)
    end

    def merge_table_array(current, incoming, path, identity_key)
      unless current.is_a?(Array) && incoming.is_a?(Array)
        fail_merge!(
          "conflicting value types at #{format_path(path)}: " \
          "#{type_name(current)} cannot merge with #{type_name(incoming)}"
        )
      end
      unless current.is_a?(Array) && current.all?(Hash)
        fail_merge!("array table #{format_path(path)} must contain only tables")
      end
      unless incoming.is_a?(Array) && incoming.all? { |member| member.is_a?(Hash) || member.is_a?(Deletion) }
        fail_merge!("array table #{format_path(path)} must contain tables or member deletions")
      end

      validate_table_array!(current, path, identity_key, false)
      validate_table_array!(incoming, path, identity_key, true)
      current.each { |member| prepare_hash!(member, path) }
      incoming.each { |member| prepare_hash!(member, path) if member.is_a?(Hash) }

      merged = current.each_with_object({}) do |member, indexed|
        identity = member_identity(member, path, identity_key)
        duplicate_identity!(path, identity) if indexed.key?(identity)
        indexed[identity] = member
      end

      processed_identities = {}
      incoming.each do |member|
        identity =
          if member.is_a?(Deletion)
            deletion_identity(member, path, identity_key)
          else
            member_identity(member, path, identity_key)
          end
        duplicate_identity!(path, identity) if processed_identities.key?(identity)
        processed_identities[identity] = true

        if member.is_a?(Deletion)
          merged.delete(identity)
          next
        end

        if merged.key?(identity)
          merge_hash!(merged[identity], member, path)
        else
          merged[identity] = member
        end
      end

      merged.values
    end

    def validate_table_array!(members, path, identity_key, allow_deletions)
      seen = {}
      members.each do |member|
        if member.is_a?(Deletion)
          unless allow_deletions
            fail_merge!("array table #{format_path(path)} must contain only tables")
          end
          identity = deletion_identity(member, path, identity_key)
        else
          fail_merge!("array table #{format_path(path)} must contain only tables") unless member.is_a?(Hash)
          identity = member_identity(member, path, identity_key)
        end

        duplicate_identity!(path, identity) if seen.key?(identity)
        seen[identity] = true
      end
    end

    def member_identity(member, path, identity_key)
      identity = read_identity(member, identity_key)
      unless scalar_identity?(identity)
        fail_merge!("array table #{format_path(path)} is missing identity #{identity_key.inspect}")
      end
      identity
    end

    def deletion_identity(deletion, path, identity_key)
      identity = deletion.identity
      identity = read_identity(identity, identity_key) if identity.is_a?(Hash)
      unless scalar_identity?(identity)
        fail_merge!("array table #{format_path(path)} deletion is missing identity #{identity_key.inspect}")
      end
      identity
    end

    def scalar_identity?(identity)
      return false if identity.nil? || identity.is_a?(Deletion) || identity.is_a?(Hash) || identity.is_a?(Array)
      return false if identity.is_a?(Float) && identity.nan?

      true
    end

    def read_identity(member, identity_key)
      return member[identity_key] if member.key?(identity_key)

      symbol_key = identity_key.to_sym
      member[symbol_key] if member.key?(symbol_key)
    end

    def prepare_value!(value, path)
      identity_key = rule_for(path)
      return ensure_no_deletions!(value, path) unless identity_key

      unless value.is_a?(Array)
        fail_merge!(
          "conflicting value types at #{format_path(path)}: " \
          "declared array table cannot merge with #{type_name(value)}"
        )
      end
      unless value.all? { |member| member.is_a?(Hash) || member.is_a?(Deletion) }
        fail_merge!("array table #{format_path(path)} must contain only tables")
      end
      validate_table_array!(value, path, identity_key, true)
      value.each { |member| prepare_hash!(member, path) if member.is_a?(Hash) }
    end

    def ensure_no_deletions!(value, path)
      case value
      when Deletion
        if path.any?(Integer)
          fail_merge!(
            "deletion at array index #{path.last} is only valid for a declared array table"
          )
        end
      when Hash
        value.each { |key, child| ensure_no_deletions!(child, path + [key]) }
      when Array
        value.each_with_index { |child, index| ensure_no_deletions!(child, path + [index]) }
      end
    end

    def prepare_hash!(hash, path)
      prepared = {}
      merge_hash!(prepared, hash, path)
      hash.replace(prepared)
    end

    def duplicate_identity!(path, identity)
      fail_merge!("duplicate identity #{identity.inspect} in array table #{format_path(path)}")
    end

    def conflict_message(path, current, incoming)
      "conflicting value types at #{format_path(path)}: #{type_name(current)} cannot merge with #{type_name(incoming)}"
    end

    def type_name(value)
      value.is_a?(Hash) ? "table" : value.is_a?(Array) ? "array" : "scalar"
    end

    def format_path(path)
      path.map(&:to_s).join(".")
    end

    def fail_merge!(message)
      raise MergeConflict, message
    end

    def rule_for(path)
      @rules[path.map(&:to_s)]
    end

    def deep_copy(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, child), copy|
          copy[duplicate_value(key)] = deep_copy(child)
        end
      when Array
        value.map { |child| deep_copy(child) }
      else
        duplicate_value(value)
      end
    end

    def duplicate_value(value)
      value.dup
    rescue TypeError
      value
    end
  end

  def self.layered_merge(*layers, table_arrays: {}, array_tables: Merger::UNSET_RULES)
    Merger.new(
      *layers,
      table_arrays: table_arrays,
      array_tables: array_tables
    ).to_h
  end

  def self.merge(*layers, table_arrays: {}, array_tables: Merger::UNSET_RULES)
    layered_merge(
      *layers,
      table_arrays: table_arrays,
      array_tables: array_tables
    )
  end

  def self.delete(identity = nil)
    identity.nil? ? DELETE : Deletion.new(identity)
  end

  def self.delete_member(identity)
    Deletion.new(identity)
  end
end
